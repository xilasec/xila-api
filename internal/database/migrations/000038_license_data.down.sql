DROP TABLE IF EXISTS license_groups;
DROP INDEX IF EXISTS idx_components_license_ids;
DROP INDEX IF EXISTS idx_components_license_unresolved;
ALTER TABLE sbom_components
    DROP COLUMN IF EXISTS license_resolved,
    DROP COLUMN IF EXISTS license_categories,
    DROP COLUMN IF EXISTS license_ids,
    DROP COLUMN IF EXISTS license_expression;
