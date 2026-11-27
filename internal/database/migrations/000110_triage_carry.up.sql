-- M13 13.1: carry manual triage decisions (false_positive / wont_fix / reopen)
-- across a project's branches and to new versions, opt-in per project.
ALTER TABLE projects
    ADD COLUMN triage_carry_enabled boolean NOT NULL DEFAULT false,
    ADD COLUMN triage_carry_branch_regex text NOT NULL DEFAULT '';

-- When a finding's status was last deliberately decided -- by a person, or by
-- triage carry copying someone else's decision -- so a later carry attempt can
-- tell a targeted, more recent decision on this one instance apart from a
-- stale or superseded source decision. NULL means "never decided directly":
-- carry may always apply there. Automated passes (VEX, vulnerability
-- policies, triage rules, connectors, risk acceptance) never set this column.
ALTER TABLE findings ADD COLUMN status_decided_at timestamptz;

CREATE INDEX idx_findings_project_fingerprint ON findings (project_id, fingerprint);

-- triage_carries holds, per (project, fingerprint), the single most recent
-- eligible decision made anywhere in the project: what to copy to the
-- project's other in-scope versions, and to a newly ingested finding sharing
-- the fingerprint. One row per fingerprint, replaced whenever a newer
-- decision arrives -- see internal/triagecarry.
CREATE TABLE triage_carries (
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    fingerprint text NOT NULL,
    status text NOT NULL CHECK (status IN ('open', 'false_positive', 'wont_fix')),
    reason text NOT NULL DEFAULT '',
    expires_at timestamptz,
    actor text NOT NULL,
    source_finding_id uuid REFERENCES findings(id) ON DELETE SET NULL,
    source_version_id uuid REFERENCES project_versions(id) ON DELETE SET NULL,
    source_branch text NOT NULL DEFAULT '',
    decided_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, fingerprint)
);

-- M13 13.15 (half): mark two findings as duplicates by hand. Automatic dedup
-- (finding.Repository.Deduplicate) must never rewrite a manual decision.
ALTER TABLE findings ADD COLUMN duplicate_manual boolean NOT NULL DEFAULT false;

-- Marking/unmarking a manual duplicate joins the finding's history, like a
-- status or severity change.
ALTER TABLE finding_events DROP CONSTRAINT finding_events_kind_check;
ALTER TABLE finding_events ADD CONSTRAINT finding_events_kind_check
    CHECK (kind IN ('created', 'status', 'severity', 'assignee', 'comment', 'attachment', 'assessment', 'tags', 'duplicate'));

CREATE OR REPLACE FUNCTION findings_record_events() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO finding_events (finding_id, project_id, kind, to_value, actor)
        VALUES (NEW.id, NEW.project_id, 'created', NEW.status, finding_actor());
        RETURN NEW;
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        INSERT INTO finding_events (finding_id, project_id, kind, from_value, to_value, actor, note)
        VALUES (NEW.id, NEW.project_id, 'status', OLD.status, NEW.status, finding_actor(), finding_note());
    END IF;
    IF NEW.severity IS DISTINCT FROM OLD.severity THEN
        INSERT INTO finding_events (finding_id, project_id, kind, from_value, to_value, actor, note)
        VALUES (NEW.id, NEW.project_id, 'severity', OLD.severity, NEW.severity, finding_actor(), finding_note());
    END IF;
    IF NEW.assignee_id IS DISTINCT FROM OLD.assignee_id THEN
        INSERT INTO finding_events (finding_id, project_id, kind, from_value, to_value, actor, note)
        VALUES (NEW.id, NEW.project_id, 'assignee',
                (SELECT email FROM users WHERE id = OLD.assignee_id),
                (SELECT email FROM users WHERE id = NEW.assignee_id),
                finding_actor(), finding_note());
    END IF;
    IF NEW.tags IS DISTINCT FROM OLD.tags THEN
        INSERT INTO finding_events (finding_id, project_id, kind, from_value, to_value, actor, note)
        VALUES (NEW.id, NEW.project_id, 'tags', array_to_string(OLD.tags, ', '), array_to_string(NEW.tags, ', '),
                finding_actor(), finding_note());
    END IF;
    -- Only a hand-made mark/unmark joins the history; automatic dedup
    -- re-electing a group's primary (duplicate_manual false on both sides)
    -- would otherwise log on every ingest.
    IF NEW.duplicate_of IS DISTINCT FROM OLD.duplicate_of AND (NEW.duplicate_manual OR OLD.duplicate_manual) THEN
        INSERT INTO finding_events (finding_id, project_id, kind, from_value, to_value, actor, note)
        VALUES (NEW.id, NEW.project_id, 'duplicate', OLD.duplicate_of::text, NEW.duplicate_of::text,
                finding_actor(), finding_note());
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS findings_events ON findings;
CREATE TRIGGER findings_events
    AFTER INSERT OR UPDATE OF status, severity, assignee_id, tags, duplicate_of ON findings
    FOR EACH ROW EXECUTE FUNCTION findings_record_events();
