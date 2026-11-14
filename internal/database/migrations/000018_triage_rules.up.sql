-- Auto-triage rules: persistent conditions -> action, applied automatically on
-- every ingest and across the backlog to cut noise (suppress / accept / downgrade).
CREATE TABLE IF NOT EXISTS triage_rules (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL,
    enabled      BOOLEAN NOT NULL DEFAULT true,
    sort_order   INT NOT NULL DEFAULT 0,
    -- Scope: NULL applies to every project; otherwise just this one.
    project_id   UUID REFERENCES projects(id) ON DELETE CASCADE,
    -- Match conditions (all set ones are AND-ed; empty/absent means "any").
    scanner      TEXT NOT NULL DEFAULT '',
    category     TEXT NOT NULL DEFAULT '',
    severities   TEXT[] NOT NULL DEFAULT '{}',
    cwe          INT,
    rule_id      TEXT NOT NULL DEFAULT '',
    cve_in       TEXT[] NOT NULL DEFAULT '{}',
    path_regex   TEXT NOT NULL DEFAULT '',
    package_regex TEXT NOT NULL DEFAULT '',
    -- Action.
    action       TEXT NOT NULL CHECK (action IN ('false_positive', 'risk_accepted', 'wont_fix', 'set_severity')),
    new_severity TEXT NOT NULL DEFAULT '',
    reason       TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_triage_rules_project ON triage_rules (project_id);
