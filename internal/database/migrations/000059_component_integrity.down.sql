DROP INDEX IF EXISTS sbom_components_integrity_mismatch;
ALTER TABLE sbom_components DROP COLUMN IF EXISTS integrity;
