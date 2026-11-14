-- Gate: compare against a named baseline branch/version (instead of the
-- single-scan "new_only" heuristic) and fail on the project's own weighted risk
-- score. Both are optional: NULL keeps the existing behavior.
ALTER TABLE gate_policies ADD COLUMN IF NOT EXISTS baseline_branch TEXT;
ALTER TABLE gate_policies ADD COLUMN IF NOT EXISTS max_risk_score DOUBLE PRECISION;
