DROP TABLE IF EXISTS sbom_documents;
ALTER TABLE sboms
    DROP COLUMN IF EXISTS original_stored,
    DROP COLUMN IF EXISTS original_media_type,
    DROP COLUMN IF EXISTS original_size,
    DROP COLUMN IF EXISTS original_sha256;
