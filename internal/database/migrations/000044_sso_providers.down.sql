-- Mappings scoped to one provider would widen to their whole kind once the
-- scope columns are gone; drop them rather than grant more than was mapped.
DELETE FROM sso_group_mappings WHERE provider_id IS NOT NULL OR env_provider;
DROP INDEX IF EXISTS idx_sso_group_mappings_provider;
ALTER TABLE sso_group_mappings
    DROP CONSTRAINT IF EXISTS sso_group_mappings_unique,
    DROP CONSTRAINT IF EXISTS sso_group_mappings_scope,
    DROP CONSTRAINT IF EXISTS sso_group_mappings_provider_fk,
    DROP COLUMN IF EXISTS env_provider,
    DROP COLUMN IF EXISTS provider_id;
ALTER TABLE sso_group_mappings ADD CONSTRAINT sso_group_mappings_unique UNIQUE NULLS NOT DISTINCT
    (provider, group_name, target_kind, org_id, team_id, project_id);

DROP INDEX IF EXISTS idx_user_identities_provider;
ALTER TABLE user_identities DROP COLUMN IF EXISTS provider_id;

DROP TABLE IF EXISTS sso_providers;
