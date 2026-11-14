-- Risk acceptance / exceptions with expiry. The active exception lives on the
-- finding; every acceptance is also recorded in finding_exceptions for audit.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS exception_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS exception_by TEXT NOT NULL DEFAULT '';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS exception_expires_at TIMESTAMPTZ;

-- Drives the expiry sweep: only findings with an expiry are of interest.
CREATE INDEX IF NOT EXISTS idx_findings_exception_expiry
    ON findings (exception_expires_at) WHERE exception_expires_at IS NOT NULL;

CREATE TABLE IF NOT EXISTS finding_exceptions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id  UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    status      TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    actor       TEXT NOT NULL DEFAULT '',
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_finding_exceptions_finding
    ON finding_exceptions (finding_id, created_at DESC);
