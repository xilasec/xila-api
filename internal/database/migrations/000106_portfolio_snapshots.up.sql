-- Data lifecycle past 100M findings (M11 11.9): the portfolio's remaining
-- finding scans move into the daily snapshots, so PORTFOLIO_FROM_SNAPSHOTS can
-- serve /portfolio from these rows. Every column stays summable across
-- projects: counts, and a category -> count map summed per key.
ALTER TABLE metric_snapshots
    ADD COLUMN open_kev         INT   NOT NULL DEFAULT 0,
    ADD COLUMN open_exploitable INT   NOT NULL DEFAULT 0,
    ADD COLUMN open_by_category JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(open_by_category) = 'object'),
    ADD COLUMN expiring_soon    INT   NOT NULL DEFAULT 0;

-- Each project's latest compliance scores and SLA parts (summable), taken by
-- the snapshot job with the counts above, so PORTFOLIO_FROM_SNAPSHOTS serves
-- the whole portfolio without a live scan. Replaced on every run.
CREATE TABLE portfolio_parts (
    project_id  UUID PRIMARY KEY REFERENCES projects(id) ON DELETE CASCADE,
    compliance  JSONB NOT NULL DEFAULT '[]',
    sla         JSONB NOT NULL DEFAULT '{}',
    computed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
