-- M11 11.6 fair queueing: denormalize project_id/org_id onto scan_jobs so the
-- claim query can enforce "at most one processing job per project" and prefer
-- the org with the fewest jobs currently processing, without joining through
-- scans -> projects -> teams on every claim.
ALTER TABLE scan_jobs ADD COLUMN project_id UUID REFERENCES projects(id) ON DELETE CASCADE;
ALTER TABLE scan_jobs ADD COLUMN org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

UPDATE scan_jobs sj
SET project_id = s.project_id, org_id = t.org_id
FROM scans s
JOIN projects p ON p.id = s.project_id
JOIN teams t ON t.id = p.team_id
WHERE sj.scan_id = s.id;

-- Every scan_jobs row references a scan, and every scan has a project (NOT
-- NULL), so the backfill above covers every existing row; EnqueueJob sets
-- both columns explicitly for new ones going forward.
ALTER TABLE scan_jobs ALTER COLUMN project_id SET NOT NULL;
ALTER TABLE scan_jobs ALTER COLUMN org_id SET NOT NULL;

-- Invariant: at most one job per project may be "processing" at a time, so a
-- burst against one project never runs more than one worker on it — the rest
-- wait and workers move on to other projects instead of blocking on the
-- dedup lock. Two workers racing the same project's only slot hit this index
-- and the loser retries (see Repository.ClaimJob).
-- Old workers had no such limit, so a rolling upgrade can find two jobs of one
-- project processing: keep the oldest and hand the others back to the queue
-- (a worker still running one deletes it on completion as before).
UPDATE scan_jobs SET status = 'pending', locked_at = NULL
WHERE status = 'processing' AND id NOT IN (
    SELECT DISTINCT ON (project_id) id FROM scan_jobs
    WHERE status = 'processing' ORDER BY project_id, locked_at, id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_scan_jobs_one_processing_per_project
    ON scan_jobs (project_id) WHERE status = 'processing';

-- The claim query's org-fairness tier (how many jobs an org currently has
-- processing) only ever scans processing rows — bounded by the number of
-- active workers cluster-wide, never by queue depth.
CREATE INDEX IF NOT EXISTS idx_scan_jobs_org_processing ON scan_jobs (org_id) WHERE status = 'processing';

-- The fair claim walks the orgs with pending work (a loose index scan, one
-- probe per org) and each org's oldest pending jobs.
CREATE INDEX IF NOT EXISTS idx_scan_jobs_pending_org ON scan_jobs (org_id, created_at) WHERE status = 'pending';

-- M11 11.7 live tuning: instance-wide operator overrides for the queue-depth
-- backpressure threshold and the worker count per node. NULL means "use the
-- env default" (INGEST_MAX_QUEUE_DEPTH / INGEST_WORKERS). A singleton row like
-- sla_settings.
CREATE TABLE IF NOT EXISTS ingest_settings (
    id              BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    max_queue_depth INT CHECK (max_queue_depth >= 0),
    workers         INT CHECK (workers >= 0),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO ingest_settings DEFAULT VALUES ON CONFLICT DO NOTHING;
