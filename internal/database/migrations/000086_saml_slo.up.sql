-- SAML Single Logout (SLO). Xila has no session state narrower than a user's
-- token_version (000046) — ending "a session" always means bumping it, which
-- signs out every device at once. What this table adds is the SAML side of
-- that: the NameID (and, when the IdP sends one, SessionIndex) a login was
-- made under, so a sign-out can address *that* session at the IdP
-- (SP-initiated) and an IdP's own LogoutRequest can find the user to sign out
-- here (IdP-initiated).
--
-- A row is written on every SAML login and pruned once expired — by then the
-- JWT it exists for has expired too (name_id_format mirrors
-- user_identities.subject_format). provider_id/env_provider follow the same
-- shape as sso_group_mappings: a database provider's own id, or NULL +
-- env_provider for the one (at most one) configured by environment.
CREATE TABLE IF NOT EXISTS saml_sessions (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id    UUID REFERENCES sso_providers(id) ON DELETE CASCADE,
    env_provider   BOOLEAN NOT NULL DEFAULT false,
    name_id        TEXT NOT NULL,
    name_id_format TEXT NOT NULL DEFAULT '',
    session_index  TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at     TIMESTAMPTZ NOT NULL,
    CONSTRAINT saml_sessions_provider CHECK (NOT (env_provider AND provider_id IS NOT NULL))
);
CREATE INDEX IF NOT EXISTS idx_saml_sessions_user ON saml_sessions (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_saml_sessions_identity ON saml_sessions (provider_id, env_provider, name_id, session_index);
CREATE INDEX IF NOT EXISTS idx_saml_sessions_expiry ON saml_sessions (expires_at);

-- "slo" joins the reserved path segments of the environment providers' routes
-- (login, callback, metadata, acs): a database provider may not take it as its
-- slug, or its own Single Logout endpoint would be indistinguishable in shape
-- from this migration's new route.
ALTER TABLE sso_providers DROP CONSTRAINT IF EXISTS sso_providers_slug_check;
ALTER TABLE sso_providers ADD CONSTRAINT sso_providers_slug_check
    CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?$'
           AND slug NOT IN ('login', 'callback', 'metadata', 'acs', 'slo', 'oidc', 'saml'));
