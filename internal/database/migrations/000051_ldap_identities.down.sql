DELETE FROM user_identities WHERE provider = 'ldap';
DELETE FROM sso_group_mappings WHERE provider = 'ldap';
ALTER TABLE user_identities DROP CONSTRAINT user_identities_provider_check;
ALTER TABLE user_identities ADD CONSTRAINT user_identities_provider_check
    CHECK (provider IN ('oidc', 'saml'));
ALTER TABLE sso_group_mappings DROP CONSTRAINT sso_group_mappings_provider_check;
ALTER TABLE sso_group_mappings ADD CONSTRAINT sso_group_mappings_provider_check
    CHECK (provider IN ('oidc', 'saml', 'any'));
