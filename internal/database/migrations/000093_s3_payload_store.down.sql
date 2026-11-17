ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_payload_xor;
-- A downgrade with s3-stored jobs would otherwise violate payload NOT NULL;
-- their objects are gone from this schema's view either way, so empty them.
UPDATE scan_jobs SET payload = '\x'::bytea WHERE payload IS NULL;
ALTER TABLE scan_jobs DROP COLUMN IF EXISTS payload_ref;
ALTER TABLE scan_jobs ALTER COLUMN payload SET NOT NULL;
