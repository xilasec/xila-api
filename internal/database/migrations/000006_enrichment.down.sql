DROP INDEX IF EXISTS idx_findings_project_priority;
ALTER TABLE findings
    DROP COLUMN IF EXISTS cvss,
    DROP COLUMN IF EXISTS epss,
    DROP COLUMN IF EXISTS kev,
    DROP COLUMN IF EXISTS priority;
