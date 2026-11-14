-- Exploit-aware prioritization signals on findings.
--   cvss     — base score 0–10 (captured from the scanner, e.g. Trivy)
--   epss     — EPSS exploit probability 0–1 (FIRST.org)
--   kev      — present in CISA's Known Exploited Vulnerabilities catalog
--   priority — severity weight × exploitability, the value the backlog sorts by
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS cvss     REAL,
    ADD COLUMN IF NOT EXISTS epss     REAL,
    ADD COLUMN IF NOT EXISTS kev      BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS priority REAL NOT NULL DEFAULT 0;

-- Backfill a base priority (exploitability multiplier = 1) from severity.
UPDATE findings SET priority = CASE severity
        WHEN 'critical' THEN 15 WHEN 'high' THEN 7 WHEN 'medium' THEN 3 WHEN 'low' THEN 1 ELSE 0 END
WHERE priority = 0;

CREATE INDEX IF NOT EXISTS idx_findings_project_priority ON findings (project_id, priority DESC);
