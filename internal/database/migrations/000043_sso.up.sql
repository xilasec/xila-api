-- Enterprise SSO: OIDC + SAML share one identity-linking layer and one
-- IdP-group → role mapping layer.

-- 1. External identities. A user may hold several (an OIDC subject and a SAML
--    NameID, say); each (provider, issuer, subject) belongs to exactly one user.
--    The subject is the IdP's stable id for the person (OIDC `sub`, SAML NameID),
--    so an email change at the IdP does not break the link.
CREATE TABLE IF NOT EXISTS user_identities (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id        UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider       TEXT NOT NULL CHECK (provider IN ('oidc', 'saml')),
    -- OIDC issuer URL / SAML IdP entity id.
    issuer         TEXT NOT NULL,
    subject        TEXT NOT NULL,
    -- SAML NameID Format (empty for OIDC).
    subject_format TEXT NOT NULL DEFAULT '',
    email_at_link  TEXT NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, issuer, subject)
);
CREATE INDEX IF NOT EXISTS idx_user_identities_user ON user_identities (user_id);

-- Carry over the single-provider OIDC links (000017). The issuer they were made
-- against is configuration, not data, so it is stored as '' and claimed by the
-- configured OIDC issuer on that subject's next login (user.LinkIdentity), which
-- rewrites it — idempotent, and a no-op once every legacy row has logged in.
INSERT INTO user_identities (user_id, provider, issuer, subject, email_at_link)
SELECT id, 'oidc', '', oidc_subject, email FROM users WHERE oidc_subject IS NOT NULL
ON CONFLICT DO NOTHING;
ALTER TABLE users DROP COLUMN IF EXISTS oidc_subject;

-- 2. Where a grant came from. 'manual' rows are made by people (the API/UI);
--    'sso' rows are owned by the group sync, which inserts, updates and deletes
--    only its own rows on each SSO login and never touches a manual one.
ALTER TABLE users ADD COLUMN IF NOT EXISTS admin_source TEXT NOT NULL DEFAULT 'manual'
    CHECK (admin_source IN ('manual', 'sso'));
ALTER TABLE org_members ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'manual'
    CHECK (source IN ('manual', 'sso'));
ALTER TABLE team_members ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'manual'
    CHECK (source IN ('manual', 'sso'));
ALTER TABLE project_members ADD COLUMN IF NOT EXISTS source TEXT NOT NULL DEFAULT 'manual'
    CHECK (source IN ('manual', 'sso'));

-- 3. IdP group → role mappings (admin-managed). Exactly the target column for
--    target_kind is set; FKs cascade so deleting an org/team/project drops its
--    mappings.
CREATE TABLE IF NOT EXISTS sso_group_mappings (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    provider    TEXT NOT NULL CHECK (provider IN ('oidc', 'saml', 'any')),
    group_name  TEXT NOT NULL CHECK (group_name <> ''),
    target_kind TEXT NOT NULL CHECK (target_kind IN ('instance_admin', 'org', 'team', 'project')),
    org_id      UUID REFERENCES organizations(id) ON DELETE CASCADE,
    team_id     UUID REFERENCES teams(id) ON DELETE CASCADE,
    project_id  UUID REFERENCES projects(id) ON DELETE CASCADE,
    role        TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT sso_group_mappings_target CHECK (
        (target_kind = 'instance_admin' AND org_id IS NULL AND team_id IS NULL AND project_id IS NULL AND role = '')
     OR (target_kind = 'org' AND org_id IS NOT NULL AND team_id IS NULL AND project_id IS NULL AND role IN ('admin', 'member'))
     OR (target_kind = 'team' AND team_id IS NOT NULL AND org_id IS NULL AND project_id IS NULL AND role IN ('owner', 'editor', 'viewer'))
     OR (target_kind = 'project' AND project_id IS NOT NULL AND org_id IS NULL AND team_id IS NULL AND role IN ('owner', 'editor', 'viewer'))
    ),
    CONSTRAINT sso_group_mappings_unique UNIQUE NULLS NOT DISTINCT (provider, group_name, target_kind, org_id, team_id, project_id)
);
CREATE INDEX IF NOT EXISTS idx_sso_group_mappings_group ON sso_group_mappings (group_name);

-- 4. The SAML SP signing/decryption key pair, generated once when none is
--    configured (SAML_SP_CERT/SAML_SP_KEY) so every replica signs with the same
--    key. The private key is sealed with INTEGRATION_SECRET_KEY (AES-256-GCM).
CREATE TABLE IF NOT EXISTS saml_sp_keys (
    id         SMALLINT PRIMARY KEY CHECK (id = 1),
    cert_pem   TEXT NOT NULL,
    key_enc    BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- 5. Assertion ids already consumed, kept until the assertion would have
--    expired anyway: a captured SAMLResponse cannot be replayed on any replica.
CREATE TABLE IF NOT EXISTS saml_seen_assertions (
    assertion_id TEXT PRIMARY KEY,
    expires_at   TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_saml_seen_assertions_expiry ON saml_seen_assertions (expires_at);
