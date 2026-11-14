-- Branches and releases as first-class project versions (DefectDojo engagement /
-- Dependency-Track project version / SecObserve branch).
--
-- Every scan, SBOM and finding belongs to exactly one version. A finding is now
-- unique per (version, fingerprint): the same CVE on `main` and `feature/x` is two
-- findings with independent lifecycles, and scanning one never closes, triages or
-- deduplicates the other. Each project has one default version (normally the main
-- branch); portfolio metrics, summaries, SLA alerts and gates read it.
CREATE TABLE IF NOT EXISTS project_versions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'branch' CHECK (kind IN ('branch', 'release')),
    is_default  BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, name)
);
CREATE UNIQUE INDEX IF NOT EXISTS project_versions_one_default
    ON project_versions (project_id) WHERE is_default;

-- project_version resolves (creating on first use) the version a scan/SBOM/finding
-- belongs to. An empty name means "the project's default version". The first
-- version a project ever gets becomes its default — so a team that scans `master`
-- first gets `master` as default without configuring anything; with no name at
-- all the default is called `main`. Concurrent first uses are safe: the losing
-- insert hits a unique index and the winner's row is read back.
CREATE OR REPLACE FUNCTION project_version(p_project uuid, p_name text, p_kind text)
RETURNS uuid LANGUAGE plpgsql AS $$
DECLARE
    v_id uuid;
BEGIN
    IF COALESCE(p_name, '') = '' THEN
        SELECT id INTO v_id FROM project_versions WHERE project_id = p_project AND is_default;
        IF FOUND THEN
            RETURN v_id;
        END IF;
        p_name := 'main';
    END IF;

    SELECT id INTO v_id FROM project_versions WHERE project_id = p_project AND name = p_name;
    IF FOUND THEN
        RETURN v_id;
    END IF;

    INSERT INTO project_versions (project_id, name, kind, is_default)
    VALUES (p_project, p_name, COALESCE(NULLIF(p_kind, ''), 'branch'),
            NOT EXISTS (SELECT 1 FROM project_versions WHERE project_id = p_project AND is_default))
    ON CONFLICT DO NOTHING
    RETURNING id INTO v_id;
    IF v_id IS NOT NULL THEN
        RETURN v_id;
    END IF;

    -- Lost a race: either the same name (read it) or the default slot (retry as
    -- a non-default version).
    SELECT id INTO v_id FROM project_versions WHERE project_id = p_project AND name = p_name;
    IF FOUND THEN
        RETURN v_id;
    END IF;
    INSERT INTO project_versions (project_id, name, kind, is_default)
    VALUES (p_project, p_name, COALESCE(NULLIF(p_kind, ''), 'branch'), false)
    ON CONFLICT (project_id, name) DO NOTHING
    RETURNING id INTO v_id;
    IF v_id IS NULL THEN
        SELECT id INTO v_id FROM project_versions WHERE project_id = p_project AND name = p_name;
    END IF;
    RETURN v_id;
END
$$;

ALTER TABLE scans    ADD COLUMN IF NOT EXISTS version_id UUID REFERENCES project_versions(id) ON DELETE CASCADE;
ALTER TABLE sboms    ADD COLUMN IF NOT EXISTS version_id UUID REFERENCES project_versions(id) ON DELETE CASCADE;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS version_id UUID REFERENCES project_versions(id) ON DELETE CASCADE;

-- Backfill. Existing findings were one row per (project, fingerprint) across all
-- branches, so they can't be split after the fact: everything a project already
-- has goes to its default version, named after the branch it scanned most (or
-- `main`). New scans on other branches start their own versions.
INSERT INTO project_versions (project_id, name, kind, is_default)
SELECT p.id,
       COALESCE((SELECT s.branch FROM scans s WHERE s.project_id = p.id AND s.branch <> ''
                 GROUP BY s.branch ORDER BY count(*) DESC, s.branch LIMIT 1), 'main'),
       'branch', true
FROM projects p
WHERE EXISTS (SELECT 1 FROM scans WHERE project_id = p.id)
   OR EXISTS (SELECT 1 FROM sboms WHERE project_id = p.id)
   OR EXISTS (SELECT 1 FROM findings WHERE project_id = p.id)
ON CONFLICT DO NOTHING;

UPDATE scans s SET version_id = v.id FROM project_versions v
WHERE v.project_id = s.project_id AND v.is_default AND s.version_id IS NULL;
UPDATE sboms s SET version_id = v.id FROM project_versions v
WHERE v.project_id = s.project_id AND v.is_default AND s.version_id IS NULL;
UPDATE findings f SET version_id = v.id FROM project_versions v
WHERE v.project_id = f.project_id AND v.is_default AND f.version_id IS NULL;

ALTER TABLE scans    ALTER COLUMN version_id SET NOT NULL;
ALTER TABLE sboms    ALTER COLUMN version_id SET NOT NULL;
ALTER TABLE findings ALTER COLUMN version_id SET NOT NULL;

-- Identity moves from (project, fingerprint) to (version, fingerprint).
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_project_id_fingerprint_key;
CREATE UNIQUE INDEX IF NOT EXISTS findings_version_fingerprint ON findings (version_id, fingerprint);

-- Any row inserted without a version gets one: a scan by its branch name, an
-- SBOM or finding the project's default (findings with a last scan inherit its
-- version). The application always resolves it explicitly; this keeps every
-- other writer (manual SQL, future paths) consistent instead of failing.
CREATE OR REPLACE FUNCTION fill_version_id() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.version_id IS NULL THEN
        -- Nested IFs: PL/pgSQL may evaluate both sides of an AND, and NEW only
        -- has the columns of the table that fired.
        IF TG_TABLE_NAME = 'scans' THEN
            NEW.version_id := project_version(NEW.project_id, NEW.branch, 'branch');
        ELSIF TG_TABLE_NAME = 'findings' THEN
            IF NEW.last_scan_id IS NOT NULL THEN
                SELECT version_id INTO NEW.version_id FROM scans WHERE id = NEW.last_scan_id;
            END IF;
        END IF;
        IF NEW.version_id IS NULL THEN
            NEW.version_id := project_version(NEW.project_id, NULL, NULL);
        END IF;
    END IF;
    RETURN NEW;
END
$$;
DROP TRIGGER IF EXISTS scans_version ON scans;
CREATE TRIGGER scans_version BEFORE INSERT ON scans FOR EACH ROW EXECUTE FUNCTION fill_version_id();
DROP TRIGGER IF EXISTS sboms_version ON sboms;
CREATE TRIGGER sboms_version BEFORE INSERT ON sboms FOR EACH ROW EXECUTE FUNCTION fill_version_id();
-- Named so it runs before findings_sla (triggers fire alphabetically).
DROP TRIGGER IF EXISTS findings_0version ON findings;
CREATE TRIGGER findings_0version BEFORE INSERT ON findings FOR EACH ROW EXECUTE FUNCTION fill_version_id();
-- Metrics read the default version's live backlog.
CREATE INDEX IF NOT EXISTS idx_findings_version_active
    ON findings (version_id, severity)
    WHERE duplicate_of IS NULL AND status IN ('open', 'confirmed');
