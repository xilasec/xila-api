-- Service accounts + workload identity federation (8.1).

-- 1. A service account is a users row of kind 'service', so every existing
--    RBAC path (org / team / project membership, authz, list scopes, the
--    token_version session check, disabled_at) applies unchanged. It can never
--    hold a password, the admin flag or ownership.
ALTER TABLE users ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'user'
    CHECK (kind IN ('user', 'service'));
ALTER TABLE users ADD CONSTRAINT users_service_unprivileged
    CHECK (kind = 'user' OR (NOT is_admin AND NOT is_owner AND password_hash IS NULL));

CREATE TABLE IF NOT EXISTS service_accounts (
    user_id     UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    -- DNS-label style: the account's email is <name>@service-accounts.invalid.
    name        TEXT NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$'),
    description TEXT NOT NULL DEFAULT '',
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 2. Trusted OIDC issuers whose identity tokens may be exchanged for a Xila
--    session (POST /auth/token, RFC 8693). Keys come from the issuer's JWKS
--    via discovery.
CREATE TABLE IF NOT EXISTS federation_issuers (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL,
    issuer_url  TEXT NOT NULL UNIQUE,
    audience    TEXT NOT NULL CHECK (audience <> ''),
    enabled     BOOLEAN NOT NULL DEFAULT true,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 3. Bindings: claim conditions (exact or glob) on a verified token from an
--    issuer → a service account, optionally confined to one project.
CREATE TABLE IF NOT EXISTS federation_bindings (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    issuer_id          UUID NOT NULL REFERENCES federation_issuers(id) ON DELETE CASCADE,
    service_account_id UUID NOT NULL REFERENCES service_accounts(user_id) ON DELETE CASCADE,
    project_id         UUID REFERENCES projects(id) ON DELETE CASCADE,
    name               TEXT NOT NULL,
    conditions         JSONB NOT NULL CHECK (jsonb_typeof(conditions) = 'object' AND conditions <> '{}'::jsonb),
    enabled            BOOLEAN NOT NULL DEFAULT true,
    created_by         UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_federation_bindings_issuer ON federation_bindings (issuer_id);
CREATE INDEX IF NOT EXISTS idx_federation_bindings_account ON federation_bindings (service_account_id);
