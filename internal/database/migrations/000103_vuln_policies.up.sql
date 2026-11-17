-- Vulnerability policies (Dependency-Track 5 parity): admin-managed rules
-- with a CEL condition over a component + vulnerability pair, matched at
-- ingest and on re-evaluation, that set an analysis state and/or a rating
-- override atomically. See internal/vulnpolicy.
CREATE TABLE IF NOT EXISTS vuln_policies (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    enabled     BOOLEAN NOT NULL DEFAULT true,
    -- CEL condition over component/vulnerability/project facts (internal/vulnpolicy
    -- expression.go); validated against the schema when saved.
    condition   TEXT NOT NULL DEFAULT '',
    -- Higher priority wins when several policies match the same pair.
    priority    INT NOT NULL DEFAULT 0,
    -- Analysis to set (optional): state + justification/details recorded on
    -- the finding. '' state = no analysis action (rating-only policy).
    analysis_state         TEXT NOT NULL DEFAULT ''
        CHECK (analysis_state IN ('', 'not_affected', 'false_positive', 'exploitable', 'in_triage')),
    analysis_justification TEXT NOT NULL DEFAULT '',
    analysis_details       TEXT NOT NULL DEFAULT '',
    -- Rating override (optional): '' severity = no rating action.
    rating_severity    TEXT NOT NULL DEFAULT '',
    rating_cvss_vector TEXT NOT NULL DEFAULT '',
    rating_cvss_score  DOUBLE PRECISION,
    -- Validity window: NULL = unbounded on that side.
    valid_from  TIMESTAMPTZ,
    valid_until TIMESTAMPTZ,
    -- Scope: global applies everywhere; projects to the linked
    -- vuln_policy_projects rows; tag to projects carrying `tag`.
    scope TEXT NOT NULL DEFAULT 'global' CHECK (scope IN ('global', 'projects', 'tag')),
    tag   TEXT NOT NULL DEFAULT '',
    -- Operation mode: apply mutates findings; log only records what would
    -- have matched (never applied, never tracked for revert).
    mode TEXT NOT NULL DEFAULT 'apply' CHECK (mode IN ('apply', 'log')),
    created_by TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Project scope (scope = 'projects').
CREATE TABLE IF NOT EXISTS vuln_policy_projects (
    policy_id  UUID NOT NULL REFERENCES vuln_policies(id) ON DELETE CASCADE,
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    PRIMARY KEY (policy_id, project_id)
);
CREATE INDEX IF NOT EXISTS idx_vuln_policy_projects_project ON vuln_policy_projects (project_id);

-- Tracks what a policy is currently holding on a finding, so a later
-- evaluation can tell "still this policy's doing" from "a person changed it
-- since" (never overturned) and revert exactly what it set when the policy
-- no longer matches, is disabled, or falls outside its validity window.
-- One row per finding: only the highest-priority matching policy ever holds
-- it. '' in applied_status/applied_severity means that half isn't tracked.
-- Deliberately no FK on policy_id: deleting a policy must not cascade away
-- this row, or the deleted policy's finding never gets the revert its
-- removal should trigger (policy_name is denormalized for the same reason).
CREATE TABLE IF NOT EXISTS vuln_policy_matches (
    finding_id       UUID PRIMARY KEY REFERENCES findings(id) ON DELETE CASCADE,
    policy_id        UUID NOT NULL,
    policy_name      TEXT NOT NULL DEFAULT '',
    applied_status   TEXT NOT NULL DEFAULT '',
    prior_status     TEXT NOT NULL DEFAULT '',
    applied_severity TEXT NOT NULL DEFAULT '',
    prior_severity   TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_vuln_policy_matches_policy ON vuln_policy_matches (policy_id);
