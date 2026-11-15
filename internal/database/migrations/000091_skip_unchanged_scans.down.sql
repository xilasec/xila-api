DROP TRIGGER IF EXISTS findings_state ON findings;
DROP FUNCTION IF EXISTS findings_state_changed();
ALTER TABLE findings DROP COLUMN IF EXISTS state_changed_at;

ALTER TABLE scan_jobs DROP COLUMN force;

DROP INDEX IF EXISTS idx_scans_target_completed;

ALTER TABLE scans
    DROP COLUMN unchanged_of,
    DROP COLUMN content_hash;
