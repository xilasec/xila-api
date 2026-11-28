DROP INDEX IF EXISTS idx_findings_malicious;
ALTER TABLE gate_policies DROP COLUMN IF EXISTS allow_malicious;
ALTER TABLE findings DROP COLUMN IF EXISTS malicious;
