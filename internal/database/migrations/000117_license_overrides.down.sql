ALTER TABLE sbom_components
    DROP COLUMN IF EXISTS license_override_id,
    DROP COLUMN IF EXISTS license_declared_resolved,
    DROP COLUMN IF EXISTS license_declared_categories,
    DROP COLUMN IF EXISTS license_declared_ids,
    DROP COLUMN IF EXISTS license_declared_expression;
DROP TABLE IF EXISTS license_overrides;
