DROP TABLE IF EXISTS finding_exceptions;
DROP INDEX IF EXISTS idx_findings_exception_expiry;
ALTER TABLE findings DROP COLUMN IF EXISTS exception_expires_at;
ALTER TABLE findings DROP COLUMN IF EXISTS exception_by;
ALTER TABLE findings DROP COLUMN IF EXISTS exception_reason;
