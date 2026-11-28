-- Declared scan expectations per project (M13 13.17, expected-scans half):
-- "this scanner (or category) should report within this window, on this
-- branch", so ingesthealth can flag one that never ran, not just one that
-- stopped (which needs 3+ scans of history to establish a cadence).
CREATE TABLE project_scan_expectations (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    scanner       TEXT,
    category      TEXT,
    branch        TEXT NOT NULL DEFAULT '', -- '' = the project's default version
    max_age_hours INT NOT NULL CHECK (max_age_hours > 0),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((scanner IS NOT NULL) <> (category IS NOT NULL))
);
CREATE UNIQUE INDEX project_scan_expectations_unique
    ON project_scan_expectations (project_id, COALESCE(scanner, ''), COALESCE(category, ''), branch);

-- A gate may fail when a declared expectation has no matching completed scan
-- within its window.
ALTER TABLE gate_policies ADD COLUMN require_expected_scans BOOLEAN NOT NULL DEFAULT false;
