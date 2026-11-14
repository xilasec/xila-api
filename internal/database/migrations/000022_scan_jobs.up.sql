-- Durable ingest queue: an upload persists its raw payload here and returns
-- immediately (202); a worker pool claims jobs with SELECT … FOR UPDATE SKIP
-- LOCKED and runs the parse→dedup pipeline off the request path.
CREATE TABLE IF NOT EXISTS scan_jobs (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id       UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    payload       BYTEA NOT NULL,
    format        TEXT NOT NULL DEFAULT '',
    close_missing BOOLEAN NOT NULL DEFAULT true,
    status        TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'processing', 'failed')),
    attempts      INT NOT NULL DEFAULT 0,
    last_error    TEXT NOT NULL DEFAULT '',
    locked_at     TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Claimable = pending, or processing that's gone stale (crashed worker).
CREATE INDEX IF NOT EXISTS idx_scan_jobs_claim ON scan_jobs (created_at) WHERE status IN ('pending', 'processing');
