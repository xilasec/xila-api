-- Pull connectors: fetch findings from a running Dependency-Track or DefectDojo
-- instance into a Xila project version, on demand and on CONNECTOR_PULL_INTERVAL.
--
-- remote_project is the Dependency-Track project UUID, or the DefectDojo product
-- id (`42`) or engagement id (`engagement:42`). version is the project version
-- (branch) the findings land in; empty = the project's default version.
--
-- Each pull is one synthetic scan by scanner `dependency-track` / `defectdojo`
-- and auto-closes what that scanner no longer reports in that version. Two
-- connectors of the same kind on the same version would close each other's
-- findings, so that pair is unique; a project may otherwise have any number.
--
-- The API token is stored encrypted (AES-256-GCM, key INTEGRATION_SECRET_KEY,
-- nonce prepended, the project id as additional data). It is never returned.
CREATE TABLE IF NOT EXISTS connectors (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind            TEXT NOT NULL CHECK (kind IN ('dependency-track', 'defectdojo')),
    name            TEXT NOT NULL DEFAULT '',
    base_url        TEXT NOT NULL,
    remote_project  TEXT NOT NULL,
    token_enc       BYTEA NOT NULL,
    version         TEXT NOT NULL DEFAULT '',
    enabled         BOOLEAN NOT NULL DEFAULT true,
    -- last_pulled_at is the last attempt (success or failure); last_success_at
    -- the last pull that was applied. last_count is what that pull imported.
    last_pulled_at  TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_error      TEXT NOT NULL DEFAULT '',
    last_count      INTEGER NOT NULL DEFAULT 0,
    last_scan_id    UUID REFERENCES scans(id) ON DELETE SET NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (project_id, kind, version)
);
