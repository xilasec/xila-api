-- Security gates: a pass/fail policy evaluated against a project's deduped,
-- triaged backlog so CI can break the build. project_id NULL is the global default.
CREATE TABLE IF NOT EXISTS gate_policies (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    UUID UNIQUE REFERENCES projects(id) ON DELETE CASCADE,
    max_critical  INT,               -- fail if open criticals exceed this
    max_high      INT,               -- fail if open highs exceed this
    block_kev     BOOLEAN NOT NULL DEFAULT false, -- fail on any open CISA-KEV finding
    max_epss      DOUBLE PRECISION,  -- fail if any open finding's EPSS ≥ this
    block_license BOOLEAN NOT NULL DEFAULT false, -- fail on any open license violation
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- At most one global default (project_id NULL); per-project is covered by UNIQUE.
CREATE UNIQUE INDEX IF NOT EXISTS gate_policies_global ON gate_policies ((project_id IS NULL)) WHERE project_id IS NULL;
