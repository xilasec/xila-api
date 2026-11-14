DROP INDEX IF EXISTS findings_archived_idx;
DROP INDEX IF EXISTS scans_archived_idx;
DROP INDEX IF EXISTS engagements_archived_idx;
DROP INDEX IF EXISTS projects_archived_idx;
ALTER TABLE findings DROP COLUMN archived_by, DROP COLUMN archived_at;
ALTER TABLE scans DROP COLUMN archived_by, DROP COLUMN archived_at;
ALTER TABLE engagements DROP COLUMN archived_by, DROP COLUMN archived_at;
ALTER TABLE projects DROP COLUMN archived_by, DROP COLUMN archived_at;
