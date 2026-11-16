-- M11 11.8: raw ingest payloads can live in S3-compatible object storage
-- instead of scan_jobs.payload (INGEST_PAYLOAD_STORE=s3), which keeps a
-- million 1 MB reports from being a terabyte of Postgres bytea traffic.
-- payload_ref holds the object store key ("scan-jobs/<scan id>", relative to
-- the configured bucket/prefix); exactly one of payload/payload_ref is set.
ALTER TABLE scan_jobs ALTER COLUMN payload DROP NOT NULL;
ALTER TABLE scan_jobs ADD COLUMN payload_ref TEXT;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_payload_xor
    CHECK ((payload IS NOT NULL) <> (payload_ref IS NOT NULL));
