DROP TABLE IF EXISTS pkgmeta_registries;
DROP INDEX IF EXISTS idx_sbom_components_internal;
ALTER TABLE sbom_components DROP COLUMN IF EXISTS internal;
DROP TABLE IF EXISTS component_patterns;
