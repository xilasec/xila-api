DROP INDEX IF EXISTS idx_components_file_path;
ALTER TABLE sbom_components DROP COLUMN IF EXISTS file_path;
