-- The SBOM exactly as uploaded (supply-chain evidence, e.g. under the CRA:
-- the document a vendor shipped, not one regenerated from parsed rows).
-- Every snapshot records the upload's digest, size and media type; the bytes
-- themselves are kept in sbom_documents unless SBOM_KEEP_ORIGINAL=false.
ALTER TABLE sboms
    ADD COLUMN original_sha256     TEXT    NOT NULL DEFAULT '',
    ADD COLUMN original_size       BIGINT  NOT NULL DEFAULT 0,
    ADD COLUMN original_media_type TEXT    NOT NULL DEFAULT '',
    ADD COLUMN original_stored     BOOLEAN NOT NULL DEFAULT false;

-- A separate table keeps the documents out of every snapshot listing.
CREATE TABLE sbom_documents (
    sbom_id UUID PRIMARY KEY REFERENCES sboms(id) ON DELETE CASCADE,
    content BYTEA NOT NULL
);
