-- Skip-unchanged scans (M11 11.4): a scan records the content hash of what it
-- parsed (every field the upsert would write, keyed by dedup fingerprint, plus
-- close_missing) so the next upload for the same target can tell whether
-- anything actually changed. unchanged_of points at the earlier scan it
-- repeated, when it did.
ALTER TABLE scans
    ADD COLUMN content_hash TEXT,
    ADD COLUMN unchanged_of UUID REFERENCES scans(id) ON DELETE SET NULL;

-- Finds "the latest completed scan of this target" (project, scanner, version,
-- asset) — the one a new upload's content hash is compared against.
CREATE INDEX IF NOT EXISTS idx_scans_target_completed
    ON scans (project_id, scanner, version_id, asset_id, created_at DESC)
    WHERE status = 'completed';

-- The async path needs to carry the caller's force=true (always process) into
-- the worker, since the skip decision happens there, after parsing.
ALTER TABLE scan_jobs ADD COLUMN force BOOLEAN NOT NULL DEFAULT false;

-- When did anything a re-ingest acts on last change for a finding? A repeat of
-- an earlier scan only skips the pipeline if none of that scan's findings
-- changed after it finished (a reset title, a manual close, an archive all
-- need the full pipeline to restore the scanner's view). clock_timestamp, not
-- now(): a long transaction must not stamp a time from before it started.
ALTER TABLE findings ADD COLUMN state_changed_at TIMESTAMPTZ;

CREATE OR REPLACE FUNCTION findings_state_changed() RETURNS trigger AS $$
BEGIN
    IF NEW.status IS DISTINCT FROM OLD.status
       OR NEW.severity IS DISTINCT FROM OLD.severity
       OR NEW.title IS DISTINCT FROM OLD.title
       OR NEW.description IS DISTINCT FROM OLD.description
       OR NEW.severity_manual IS DISTINCT FROM OLD.severity_manual
       OR NEW.title_manual IS DISTINCT FROM OLD.title_manual
       OR NEW.archived_at IS DISTINCT FROM OLD.archived_at THEN
        NEW.state_changed_at := clock_timestamp();
    END IF;
    RETURN NEW;
END $$ LANGUAGE plpgsql;

CREATE TRIGGER findings_state BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION findings_state_changed();
