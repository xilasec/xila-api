DROP TABLE IF EXISTS ingest_settings;
DROP INDEX IF EXISTS idx_scan_jobs_pending_org;
DROP INDEX IF EXISTS idx_scan_jobs_org_processing;
DROP INDEX IF EXISTS idx_scan_jobs_one_processing_per_project;
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS org_id;
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS project_id;
