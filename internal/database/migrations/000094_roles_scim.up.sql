-- M12 12.8: custom roles, user groups, and SCIM 2.0 provisioning.
--
-- 1. User groups: admin-managed named groups of users, scoped to an
--    organization. A group is grantable on an org, team or project exactly
--    like a user — every member of the group gets the grant's role. Group
--    membership is expanded inline wherever a user grant is (see
--    membership.ProjectGrantsSQL and the team/org role queries), so
--    authorization, the permission audit and SCIM agree on one definition.
CREATE TABLE IF NOT EXISTS user_groups (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name        TEXT NOT NULL CHECK (name <> ''),
    -- Set when the group was provisioned by a SCIM client, so a later PUT/PATCH
    -- for the same externalId updates this row instead of creating a duplicate.
    scim_external_id TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);
CREATE UNIQUE INDEX IF NOT EXISTS user_groups_scim_external_id ON user_groups (scim_external_id) WHERE scim_external_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS user_group_members (
    group_id   UUID NOT NULL REFERENCES user_groups(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_user_group_members_user ON user_group_members (user_id);

-- 2. Custom roles: admin-defined named roles = a base role (viewer, uploader,
--    editor, owner) minus a set of denied capabilities. Assignable wherever a
--    base role is granted on a team or project (not on an org: org roles are
--    only admin/member, not a point on the viewer<uploader<editor<owner
--    ladder). The ladder rank for authorization/ranking purposes is always
--    `base_role` — a custom role never ranks higher or lower than its base,
--    it only narrows specific actions within it (see internal/authz).
CREATE TABLE IF NOT EXISTS custom_roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name        TEXT NOT NULL CHECK (name <> ''),
    base_role   TEXT NOT NULL CHECK (base_role IN ('viewer', 'uploader', 'editor', 'owner')),
    -- Capabilities this role denies on top of base_role. Valid values mirror
    -- internal/domain's Capability list; extending that list also means
    -- extending this CHECK.
    denied_capabilities TEXT[] NOT NULL DEFAULT '{}'
        CHECK (denied_capabilities <@ ARRAY['triage', 'comment', 'manage_members', 'project_settings', 'upload', 'export', 'risk_acceptance_approve']::text[]),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

-- 3. Grants extend to groups (group_id, exclusive with user_id) and, on
--    team/project grants only, a custom role narrowing the base role.
ALTER TABLE org_members ADD COLUMN IF NOT EXISTS group_id UUID REFERENCES user_groups(id) ON DELETE CASCADE;
ALTER TABLE org_members DROP CONSTRAINT IF EXISTS org_members_pkey;
ALTER TABLE org_members ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE org_members ADD CONSTRAINT org_members_user_xor_group CHECK ((user_id IS NULL) <> (group_id IS NULL));
CREATE UNIQUE INDEX IF NOT EXISTS org_members_user_unique ON org_members (org_id, user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS org_members_group_unique ON org_members (org_id, group_id) WHERE group_id IS NOT NULL;

ALTER TABLE team_members ADD COLUMN IF NOT EXISTS group_id UUID REFERENCES user_groups(id) ON DELETE CASCADE;
ALTER TABLE team_members ADD COLUMN IF NOT EXISTS custom_role_id UUID REFERENCES custom_roles(id) ON DELETE SET NULL;
ALTER TABLE team_members DROP CONSTRAINT IF EXISTS team_members_pkey;
ALTER TABLE team_members ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE team_members ADD CONSTRAINT team_members_user_xor_group CHECK ((user_id IS NULL) <> (group_id IS NULL));
CREATE UNIQUE INDEX IF NOT EXISTS team_members_user_unique ON team_members (team_id, user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS team_members_group_unique ON team_members (team_id, group_id) WHERE group_id IS NOT NULL;

ALTER TABLE project_members ADD COLUMN IF NOT EXISTS group_id UUID REFERENCES user_groups(id) ON DELETE CASCADE;
ALTER TABLE project_members ADD COLUMN IF NOT EXISTS custom_role_id UUID REFERENCES custom_roles(id) ON DELETE SET NULL;
ALTER TABLE project_members DROP CONSTRAINT IF EXISTS project_members_pkey;
ALTER TABLE project_members ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE project_members ADD CONSTRAINT project_members_user_xor_group CHECK ((user_id IS NULL) <> (group_id IS NULL));
CREATE UNIQUE INDEX IF NOT EXISTS project_members_user_unique ON project_members (project_id, user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS project_members_group_unique ON project_members (project_id, group_id) WHERE group_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_org_members_group ON org_members (group_id) WHERE group_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_team_members_group ON team_members (group_id) WHERE group_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_project_members_group ON project_members (group_id) WHERE group_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_team_members_custom_role ON team_members (custom_role_id) WHERE custom_role_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_project_members_custom_role ON project_members (custom_role_id) WHERE custom_role_id IS NOT NULL;

-- A group or custom role can only be granted inside its own organization:
-- a team owner must not be able to hand a team to another tenant's group
-- (or find out its name). Enforced here so every write path is covered.
CREATE OR REPLACE FUNCTION grant_same_org() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    target_org UUID;
    custom_role UUID;
BEGIN
    IF TG_TABLE_NAME = 'org_members' THEN
        target_org := NEW.org_id;
    ELSIF TG_TABLE_NAME = 'team_members' THEN
        SELECT org_id INTO target_org FROM teams WHERE id = NEW.team_id;
        custom_role := NEW.custom_role_id;
    ELSE
        SELECT t.org_id INTO target_org FROM projects p JOIN teams t ON t.id = p.team_id WHERE p.id = NEW.project_id;
        custom_role := NEW.custom_role_id;
    END IF;
    IF NEW.group_id IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM user_groups WHERE id = NEW.group_id AND org_id = target_org) THEN
        RAISE EXCEPTION 'group % is not in this organization', NEW.group_id USING ERRCODE = 'check_violation';
    END IF;
    IF custom_role IS NOT NULL AND NOT EXISTS (
        SELECT 1 FROM custom_roles WHERE id = custom_role AND org_id = target_org) THEN
        RAISE EXCEPTION 'custom role % is not in this organization', custom_role USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER org_members_same_org BEFORE INSERT OR UPDATE ON org_members
    FOR EACH ROW EXECUTE FUNCTION grant_same_org();
CREATE TRIGGER team_members_same_org BEFORE INSERT OR UPDATE ON team_members
    FOR EACH ROW EXECUTE FUNCTION grant_same_org();
CREATE TRIGGER project_members_same_org BEFORE INSERT OR UPDATE ON project_members
    FOR EACH ROW EXECUTE FUNCTION grant_same_org();

-- 4. SCIM 2.0 provisioning. Users map to Xila users (userName = email);
--    groups map to user_groups. externalId lets a directory's later PUT/PATCH
--    find the same resource again without us guessing identity from a name.
ALTER TABLE users ADD COLUMN IF NOT EXISTS scim_external_id TEXT;
CREATE UNIQUE INDEX IF NOT EXISTS users_scim_external_id ON users (scim_external_id) WHERE scim_external_id IS NOT NULL;

-- Bearer tokens for SCIM clients: a separate table and a separate bearer
-- scheme from internal/apitoken's CI tokens, so a SCIM token cannot reach the
-- rest of the API and the rest of the API's tokens cannot reach SCIM (both
-- checked by hash against their own table only). Only the hash is stored.
-- A token is scoped to one organization: SCIM Groups map to that org's
-- user_groups (SCIM has no tenant concept of its own), and provisioned Users
-- are added to that org as members so they can be put in a team/project.
CREATE TABLE IF NOT EXISTS scim_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL,
    org_id       UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    created_by   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_scim_tokens_created_by ON scim_tokens (created_by);

-- SCIM changes are audited with their token as the actor.
ALTER TABLE audit_log DROP CONSTRAINT audit_log_actor_kind_check;
ALTER TABLE audit_log ADD CONSTRAINT audit_log_actor_kind_check
    CHECK (actor_kind IN ('user', 'service_account', 'api_token', 'system', 'anonymous', 'scim'));
