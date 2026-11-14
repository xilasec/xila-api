-- Issue trackers: one per project (Jira, GitHub Issues, GitLab Issues). Findings
-- at or above min_severity get an issue (on demand, or automatically when
-- auto_create is set), and the issue's open/closed state is synced both ways.
--
-- The API token is stored encrypted (AES-256-GCM, key INTEGRATION_SECRET_KEY,
-- nonce prepended, the project id as additional data so a ciphertext can't be
-- moved to another project's row). It is never returned by the API.
CREATE TABLE IF NOT EXISTS issue_trackers (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id        UUID NOT NULL UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
    kind              TEXT NOT NULL CHECK (kind IN ('jira', 'github', 'gitlab')),
    base_url          TEXT NOT NULL,
    target            TEXT NOT NULL,
    token_enc         BYTEA NOT NULL,
    -- Jira only: Cloud authenticates with email + API token (basic auth); with
    -- no email the token is sent as a Bearer PAT (Server / Data Center).
    jira_email        TEXT NOT NULL DEFAULT '',
    issue_type        TEXT NOT NULL DEFAULT 'Bug',
    done_transition   TEXT NOT NULL DEFAULT 'Done',
    reopen_transition TEXT NOT NULL DEFAULT 'To Do',
    min_severity      TEXT NOT NULL DEFAULT 'high'
                      CHECK (min_severity IN ('info', 'low', 'medium', 'high', 'critical')),
    auto_create       BOOLEAN NOT NULL DEFAULT false,
    labels            TEXT[] NOT NULL DEFAULT '{}',
    enabled           BOOLEAN NOT NULL DEFAULT true,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One external issue per finding. state is the last state both sides agreed on
-- (as of last_synced_at): sync compares it with each side to tell which one
-- changed, so the two directions never fight.
CREATE TABLE IF NOT EXISTS finding_issues (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id     UUID NOT NULL UNIQUE REFERENCES findings(id) ON DELETE CASCADE,
    tracker_id     UUID NOT NULL REFERENCES issue_trackers(id) ON DELETE CASCADE,
    external_id    TEXT NOT NULL,
    url            TEXT NOT NULL DEFAULT '',
    state          TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'closed')),
    last_synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_finding_issues_tracker ON finding_issues (tracker_id);
