-- Component integrity (internal/pkgmeta): whether a component's SBOM hashes
-- match the digests its registry publishes for that version. NULL = unknown
-- (no hash on either side), never "verified".
ALTER TABLE sbom_components ADD COLUMN integrity text CHECK (integrity IN ('verified', 'mismatch'));
CREATE INDEX sbom_components_integrity_mismatch ON sbom_components (project_id) WHERE integrity = 'mismatch';
