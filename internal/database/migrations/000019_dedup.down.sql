DROP INDEX IF EXISTS idx_findings_duplicate_of;
DROP INDEX IF EXISTS idx_findings_correlation;
ALTER TABLE findings DROP COLUMN IF EXISTS duplicate_of;
ALTER TABLE findings DROP COLUMN IF EXISTS correlation_key;
