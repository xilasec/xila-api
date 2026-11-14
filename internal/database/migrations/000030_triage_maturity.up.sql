-- Auto-triage maturity: exploit/business-aware conditions, per-rule hit metrics,
-- and an optional four-eyes approval workflow for rule changes.
ALTER TABLE triage_rules
    -- Conditions. min_epss: finding.epss >= it (unknown EPSS never matches).
    -- kev: only KEV-listed findings. project_criticality: the finding's project
    -- business criticality is one of these (empty = any).
    ADD COLUMN IF NOT EXISTS min_epss DOUBLE PRECISION
        CHECK (min_epss IS NULL OR (min_epss >= 0 AND min_epss <= 1)),
    ADD COLUMN IF NOT EXISTS kev BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS project_criticality TEXT[] NOT NULL DEFAULT '{}'
        CHECK (project_criticality <@ ARRAY['low', 'medium', 'high', 'critical']::TEXT[]),
    -- Hit metrics: findings this rule actually changed (ingest + backfill).
    ADD COLUMN IF NOT EXISTS hit_count BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS last_hit_at TIMESTAMPTZ,
    -- Approval workflow. Only 'approved' rules ever apply. Existing rules predate
    -- the workflow and keep applying, so they migrate as approved.
    ADD COLUMN IF NOT EXISTS approval_status TEXT NOT NULL DEFAULT 'approved'
        CHECK (approval_status IN ('pending', 'approved', 'rejected')),
    ADD COLUMN IF NOT EXISTS created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS updated_by UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS approved_by UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS approved_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS rejected_by UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS rejected_at TIMESTAMPTZ;
