-- Daily metric snapshots: one row per (UTC day, scope) so trend charts read a
-- small table instead of recomputing history from findings on every request.
--
-- scope_kind/scope_id name the rollup: a project, team or org id, or NULL for
-- the whole portfolio. There is no FK (the id is polymorphic); a deleted
-- project's history stays until the day is recomputed.
--
-- Every column is additive across scopes so the API can aggregate any set of
-- project rows (RBAC-scoped portfolio views) without losing precision:
--   * sla_met / sla_missed are fixes that day with an SLA, on time vs late;
--     compliance = met / (met + missed).
--   * remediation_days_sum is the sum of (resolved_at - first_seen_at) in days
--     over the day's `closed` findings; MTTR = remediation_days_sum / closed.
--   * risk_score is the project summary's score (severity weight × count ×
--     business-criticality multiplier), summed over projects for wider scopes.
-- reconstructed marks rows computed after the fact by the first-run backfill
-- (from lifecycle timestamps) rather than taken on or right after the day.
CREATE TABLE IF NOT EXISTS metric_snapshots (
    day                  DATE NOT NULL,
    scope_kind           TEXT NOT NULL CHECK (scope_kind IN ('portfolio', 'org', 'team', 'project')),
    scope_id             UUID,
    open_critical        INT NOT NULL DEFAULT 0,
    open_high            INT NOT NULL DEFAULT 0,
    open_medium          INT NOT NULL DEFAULT 0,
    open_low             INT NOT NULL DEFAULT 0,
    open_info            INT NOT NULL DEFAULT 0,
    open_total           INT NOT NULL DEFAULT 0,
    new_count            INT NOT NULL DEFAULT 0,
    closed_count         INT NOT NULL DEFAULT 0,
    risk_score           DOUBLE PRECISION NOT NULL DEFAULT 0,
    sla_breached         INT NOT NULL DEFAULT 0,
    sla_met              INT NOT NULL DEFAULT 0,
    sla_missed           INT NOT NULL DEFAULT 0,
    remediation_days_sum DOUBLE PRECISION NOT NULL DEFAULT 0,
    reconstructed        BOOLEAN NOT NULL DEFAULT false,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((scope_kind = 'portfolio') = (scope_id IS NULL)),
    UNIQUE NULLS NOT DISTINCT (day, scope_kind, scope_id)
);

-- Trend reads are "one scope, newest N days" or "these projects, newest N days".
CREATE INDEX IF NOT EXISTS idx_metric_snapshots_scope ON metric_snapshots (scope_kind, scope_id, day);
