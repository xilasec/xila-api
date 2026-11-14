-- SSO providers managed at runtime from the admin UI, next to the (at most one
-- per kind) providers configured by environment (OIDC_*, SAML_*), which stay
-- read-only and are not stored here.

-- 1. Admin-managed providers. The slug names the provider in its routes
--    (/api/v1/auth/{kind}/{slug}/…) and is immutable: the IdP registration holds
--    those URLs. Slugs that are path segments of the environment providers'
--    routes, or their own slugs, are reserved so the routes cannot collide.
--    Secrets are sealed with INTEGRATION_SECRET_KEY (AES-256-GCM, bound to the
--    row id) and never returned by the API.
CREATE TABLE IF NOT EXISTS sso_providers (
    id                     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug                   TEXT NOT NULL UNIQUE
        CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$'
               AND slug NOT IN ('login', 'callback', 'metadata', 'acs', 'oidc', 'saml')),
    kind                   TEXT NOT NULL CHECK (kind IN ('oidc', 'saml')),
    name                   TEXT NOT NULL CHECK (name <> ''),
    enabled                BOOLEAN NOT NULL DEFAULT true,
    sort_order             INTEGER NOT NULL DEFAULT 0,

    -- OIDC
    issuer                 TEXT NOT NULL DEFAULT '',
    client_id              TEXT NOT NULL DEFAULT '',
    client_secret_enc      BYTEA,
    scopes                 TEXT[] NOT NULL DEFAULT '{}',
    groups_claim           TEXT NOT NULL DEFAULT '',
    trust_unverified_email BOOLEAN NOT NULL DEFAULT false,

    -- SAML (Xila is the SP; entity_id empty = <PUBLIC_URL>/api/v1/auth/saml/{slug}/metadata)
    idp_metadata_url       TEXT NOT NULL DEFAULT '',
    idp_metadata           TEXT NOT NULL DEFAULT '',
    entity_id              TEXT NOT NULL DEFAULT '',
    email_attribute        TEXT NOT NULL DEFAULT '',
    groups_attributes      TEXT[] NOT NULL DEFAULT '{}',
    allow_idp_initiated    BOOLEAN NOT NULL DEFAULT false,
    sign_requests          BOOLEAN NOT NULL DEFAULT true,
    -- Optional own SP key pair; empty = the shared generated one (saml_sp_keys).
    sp_cert_pem            TEXT NOT NULL DEFAULT '',
    sp_key_enc             BYTEA,

    -- Login policy. auto_create_users NULL = the instance default
    -- (SSO_AUTO_CREATE_USERS).
    auto_create_users      BOOLEAN,
    link_by_email          BOOLEAN NOT NULL DEFAULT true,

    created_by             UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- Target of the (provider_id, provider) FK on group mappings: a mapping
    -- scoped to a provider always carries that provider's kind.
    CONSTRAINT sso_providers_id_kind UNIQUE (id, kind),
    CONSTRAINT sso_providers_oidc CHECK (kind <> 'oidc' OR (issuer <> '' AND client_id <> '' AND client_secret_enc IS NOT NULL)),
    CONSTRAINT sso_providers_saml CHECK (kind <> 'saml' OR idp_metadata_url <> '' OR idp_metadata <> ''),
    CONSTRAINT sso_providers_sp_pair CHECK ((sp_cert_pem = '') = (sp_key_enc IS NULL))
);

-- 2. Which configured provider an identity last signed in through — display
--    only. Identities stay keyed by (kind, issuer, subject): deleting or
--    renaming a provider keeps every account and link, and another provider
--    with the same issuer keeps signing the same people in.
ALTER TABLE user_identities ADD COLUMN IF NOT EXISTS provider_id UUID
    REFERENCES sso_providers(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_user_identities_provider ON user_identities (provider_id);

-- 3. Group mappings can target one provider. `provider` keeps its meaning — the
--    kind scope: 'any', or every provider of one kind (existing 'oidc'/'saml'
--    rows keep applying to every provider of that kind, environment and
--    database alike). A mapping for one provider sets provider_id (a database
--    provider; deleting it deletes its mappings) or env_provider (the one
--    configured by environment for `provider`'s kind).
ALTER TABLE sso_group_mappings
    ADD COLUMN IF NOT EXISTS provider_id UUID,
    ADD COLUMN IF NOT EXISTS env_provider BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sso_group_mappings
    ADD CONSTRAINT sso_group_mappings_provider_fk FOREIGN KEY (provider_id, provider)
        REFERENCES sso_providers (id, kind) ON DELETE CASCADE,
    ADD CONSTRAINT sso_group_mappings_scope CHECK (
        NOT (env_provider AND provider_id IS NOT NULL)
        AND (provider <> 'any' OR (provider_id IS NULL AND NOT env_provider))
    ),
    DROP CONSTRAINT IF EXISTS sso_group_mappings_unique,
    ADD CONSTRAINT sso_group_mappings_unique UNIQUE NULLS NOT DISTINCT
        (provider, provider_id, env_provider, group_name, target_kind, org_id, team_id, project_id);
CREATE INDEX IF NOT EXISTS idx_sso_group_mappings_provider ON sso_group_mappings (provider_id);
