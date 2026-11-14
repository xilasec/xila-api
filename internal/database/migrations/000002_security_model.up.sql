-- Teams own projects; projects own scans and findings.
CREATE TABLE IF NOT EXISTS teams (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug        TEXT NOT NULL UNIQUE,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS projects (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    team_id               UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    slug                  TEXT NOT NULL,
    name                  TEXT NOT NULL,
    description           TEXT NOT NULL DEFAULT '',
    repo_url              TEXT NOT NULL DEFAULT '',
    business_criticality  TEXT NOT NULL DEFAULT 'medium'
        CHECK (business_criticality IN ('low', 'medium', 'high', 'critical')),
    tags                  TEXT[] NOT NULL DEFAULT '{}',
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (team_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_projects_team ON projects (team_id);

CREATE TABLE IF NOT EXISTS scans (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id   UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scanner      TEXT NOT NULL,
    category     TEXT NOT NULL
        CHECK (category IN ('sast', 'dast', 'sca', 'secret', 'container', 'iac', 'license')),
    status       TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'processing', 'completed', 'failed')),
    commit_sha   TEXT NOT NULL DEFAULT '',
    branch       TEXT NOT NULL DEFAULT '',
    summary      JSONB NOT NULL DEFAULT '{}',
    error        TEXT NOT NULL DEFAULT '',
    started_at   TIMESTAMPTZ,
    finished_at  TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scans_project ON scans (project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS findings (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id       UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    fingerprint      TEXT NOT NULL,
    scanner          TEXT NOT NULL,
    category         TEXT NOT NULL
        CHECK (category IN ('sast', 'dast', 'sca', 'secret', 'container', 'iac', 'license')),
    rule_id          TEXT NOT NULL DEFAULT '',
    title            TEXT NOT NULL,
    description      TEXT NOT NULL DEFAULT '',
    severity         TEXT NOT NULL
        CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    cwe              INTEGER,
    cve              TEXT[] NOT NULL DEFAULT '{}',
    file_path        TEXT NOT NULL DEFAULT '',
    line             INTEGER,
    package_name     TEXT NOT NULL DEFAULT '',
    package_version  TEXT NOT NULL DEFAULT '',
    fixed_version    TEXT NOT NULL DEFAULT '',
    url              TEXT NOT NULL DEFAULT '',
    metadata         JSONB NOT NULL DEFAULT '{}',
    status           TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'confirmed', 'false_positive', 'risk_accepted', 'remediated', 'wont_fix')),
    first_seen_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    first_scan_id    UUID REFERENCES scans(id) ON DELETE SET NULL,
    last_scan_id     UUID REFERENCES scans(id) ON DELETE SET NULL,
    resolved_at      TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A finding is unique per project by its fingerprint; this drives dedup.
    UNIQUE (project_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_findings_project_status ON findings (project_id, status);
CREATE INDEX IF NOT EXISTS idx_findings_project_severity ON findings (project_id, severity);
