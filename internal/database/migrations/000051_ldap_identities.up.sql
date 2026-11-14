-- LDAP / Active Directory sign-in is a third identity kind: a directory
-- identity links to a user and syncs groups exactly like OIDC and SAML.
ALTER TABLE user_identities DROP CONSTRAINT user_identities_provider_check;
ALTER TABLE user_identities ADD CONSTRAINT user_identities_provider_check
    CHECK (provider IN ('oidc', 'saml', 'ldap'));
ALTER TABLE sso_group_mappings DROP CONSTRAINT sso_group_mappings_provider_check;
ALTER TABLE sso_group_mappings ADD CONSTRAINT sso_group_mappings_provider_check
    CHECK (provider IN ('oidc', 'saml', 'ldap', 'any'));
