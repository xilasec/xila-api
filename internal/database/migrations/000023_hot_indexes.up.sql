-- Indexes for the hot paths at ingestion scale. The dominant read shape across
-- the product (lists, gates, triage, portfolio, risk) is "the active backlog":
-- open/confirmed findings that aren't cross-tool duplicates. A partial index on
-- exactly that predicate keeps triaged/remediated/duplicate rows — the bulk of a
-- mature table — out of the index entirely.

-- Backlog listing + gates + risk, already ordered by priority.
CREATE INDEX IF NOT EXISTS idx_findings_active
    ON findings (project_id, priority DESC)
    WHERE duplicate_of IS NULL AND status IN ('open', 'confirmed');

-- CloseMissing: every ingest scans the project's live findings for this scanner.
CREATE INDEX IF NOT EXISTS idx_findings_close_missing
    ON findings (project_id, scanner)
    WHERE status IN ('open', 'confirmed');

-- ListNewHighSeverity (the new-critical alert) + new-only gating, which key off
-- "first seen in this scan".
CREATE INDEX IF NOT EXISTS idx_findings_first_scan
    ON findings (first_scan_id)
    WHERE duplicate_of IS NULL;

-- Deduplicate elects a primary per correlation group among active findings; the
-- existing (project_id, correlation_key) index also carries the triaged rows.
CREATE INDEX IF NOT EXISTS idx_findings_active_correlation
    ON findings (project_id, correlation_key)
    WHERE correlation_key IS NOT NULL AND status IN ('open', 'confirmed');

-- Enrichment walks every CVE-bearing finding on each refresh.
CREATE INDEX IF NOT EXISTS idx_findings_with_cve
    ON findings (project_id)
    WHERE cardinality(cve) > 0;
