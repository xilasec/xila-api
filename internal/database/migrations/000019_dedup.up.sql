-- Cross-tool dedup: the same CVE+package reported by multiple scanners is one
-- issue. correlation_key groups them; duplicate_of points non-primary reports at
-- the elected primary (recomputed on every ingest). Duplicates are hidden from
-- lists/counts/risk so metrics reflect issues, not report copies.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS correlation_key TEXT;
ALTER TABLE findings ADD COLUMN IF NOT EXISTS duplicate_of UUID REFERENCES findings(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_findings_correlation ON findings (project_id, correlation_key);
CREATE INDEX IF NOT EXISTS idx_findings_duplicate_of ON findings (duplicate_of);
