-- The findings lists' default order is newest-seen first (ORDER BY last_seen_at
-- DESC). Without an index in that order Postgres scans every finding and sorts
-- to return one page: measured on 1M findings (docs/SCALE.md), the project list
-- took 217 ms and the portfolio-wide list 292 ms of database time; with these,
-- 0.8 ms and 0.4 ms. One index per shape: per project, and across projects
-- (/findings, scoped by authz to many projects).
CREATE INDEX IF NOT EXISTS idx_findings_project_last_seen ON findings (project_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_findings_last_seen ON findings (last_seen_at DESC);
