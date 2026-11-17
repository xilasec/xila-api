-- Every scan-scoped pass (exposure evidence, reprioritize, feed tags, the
-- skip-unchanged carry-forward, archive, retention) finds a scan's findings by
-- last_scan_id. Without this index each was a full table scan: invisible at 1M
-- findings, 17 s per pass at 10M (the M11 11.10 load test).
CREATE INDEX IF NOT EXISTS idx_findings_last_scan ON findings (last_scan_id);
