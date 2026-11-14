DROP TABLE IF EXISTS saml_sessions;

ALTER TABLE sso_providers DROP CONSTRAINT IF EXISTS sso_providers_slug_check;
ALTER TABLE sso_providers ADD CONSTRAINT sso_providers_slug_check
    CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$'
           AND slug NOT IN ('login', 'callback', 'metadata', 'acs', 'oidc', 'saml'));
