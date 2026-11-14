-- Analyst workflow on findings: an owner (assignee), a discussion (comments),
-- evidence (attachments) and a complete audit history of every change.

ALTER TABLE findings ADD COLUMN IF NOT EXISTS assignee_id UUID REFERENCES users(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_findings_assignee ON findings (assignee_id) WHERE assignee_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS finding_comments (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id  UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    author_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    author      TEXT NOT NULL DEFAULT '',   -- email at the time, kept if the user goes
    body        TEXT NOT NULL CHECK (length(body) BETWEEN 1 AND 20000),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_finding_comments ON finding_comments (finding_id, created_at);

-- Evidence lives in Postgres like everything else (one binary + one database);
-- the API caps a file at 10 MiB.
CREATE TABLE IF NOT EXISTS finding_attachments (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id    UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    filename      TEXT NOT NULL,
    content_type  TEXT NOT NULL DEFAULT 'application/octet-stream',
    size          INT NOT NULL,
    sha256        TEXT NOT NULL,
    data          BYTEA NOT NULL,
    uploaded_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    uploader      TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_finding_attachments ON finding_attachments (finding_id, created_at);

-- The history: one row per change to a finding's status, severity or assignee,
-- plus comments and attachments. Field changes are recorded by a trigger, so
-- every writer — manual triage, bulk edits, auto-triage, VEX, auto-close,
-- reopen-on-reappearance, the exception sweep, SLA-driven nothing — is captured
-- without having to remember to. The actor and an optional note come from
-- transaction-local settings (xila.actor / xila.note) that user-facing writes
-- set; anything else is recorded as "system".
CREATE TABLE IF NOT EXISTS finding_events (
    id          BIGSERIAL PRIMARY KEY,
    finding_id  UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('created', 'status', 'severity', 'assignee', 'comment', 'attachment')),
    from_value  TEXT,
    to_value    TEXT,
    actor       TEXT NOT NULL DEFAULT 'system',
    note        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_finding_events ON finding_events (finding_id, id);

CREATE OR REPLACE FUNCTION finding_actor() RETURNS text LANGUAGE sql STABLE AS $$
    SELECT COALESCE(NULLIF(current_setting('xila.actor', true), ''), 'system')
$$;
CREATE OR REPLACE FUNCTION finding_note() RETURNS text LANGUAGE sql STABLE AS $$
    SELECT COALESCE(current_setting('xila.note', true), '')
$$;

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
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS findings_events ON findings;
CREATE TRIGGER findings_events
    AFTER INSERT OR UPDATE OF status, severity, assignee_id ON findings
    FOR EACH ROW EXECUTE FUNCTION findings_record_events();
