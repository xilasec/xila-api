DROP TABLE IF EXISTS asset_relations;
ALTER TABLE assets
    DROP CONSTRAINT IF EXISTS assets_exposure_source,
    DROP COLUMN IF EXISTS exposure_updated_at,
    DROP COLUMN IF EXISTS exposure_reason,
    DROP COLUMN IF EXISTS exposure_source,
    DROP COLUMN IF EXISTS exposure;
