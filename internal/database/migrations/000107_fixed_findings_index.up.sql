-- FINDING_ARCHIVE_AFTER (M11 11.9) looks for live remediated findings by
-- resolved_at; this keeps that a short index range scan at any table size.
CREATE INDEX IF NOT EXISTS idx_findings_fixed_live ON findings (resolved_at)
    WHERE status = 'remediated' AND archived_at IS NULL;
