-- audit_log is append-only: SCIM entries stay, so the widened actor_kind
-- check stays too.
DROP TABLE IF EXISTS scim_tokens;
DROP TRIGGER IF EXISTS org_members_same_org ON org_members;
DROP TRIGGER IF EXISTS team_members_same_org ON team_members;
DROP TRIGGER IF EXISTS project_members_same_org ON project_members;
DROP FUNCTION IF EXISTS grant_same_org();
DROP INDEX IF EXISTS users_scim_external_id;
ALTER TABLE users DROP COLUMN IF EXISTS scim_external_id;

DROP INDEX IF EXISTS idx_project_members_custom_role;
DROP INDEX IF EXISTS idx_team_members_custom_role;
DROP INDEX IF EXISTS idx_project_members_group;
DROP INDEX IF EXISTS idx_team_members_group;
DROP INDEX IF EXISTS idx_org_members_group;

DROP INDEX IF EXISTS project_members_group_unique;
DROP INDEX IF EXISTS project_members_user_unique;
DELETE FROM project_members WHERE user_id IS NULL;
ALTER TABLE project_members DROP CONSTRAINT IF EXISTS project_members_user_xor_group;
ALTER TABLE project_members ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE project_members ADD PRIMARY KEY (project_id, user_id);
ALTER TABLE project_members DROP COLUMN IF EXISTS custom_role_id;
ALTER TABLE project_members DROP COLUMN IF EXISTS group_id;

DROP INDEX IF EXISTS team_members_group_unique;
DROP INDEX IF EXISTS team_members_user_unique;
DELETE FROM team_members WHERE user_id IS NULL;
ALTER TABLE team_members DROP CONSTRAINT IF EXISTS team_members_user_xor_group;
ALTER TABLE team_members ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE team_members ADD PRIMARY KEY (team_id, user_id);
ALTER TABLE team_members DROP COLUMN IF EXISTS custom_role_id;
ALTER TABLE team_members DROP COLUMN IF EXISTS group_id;

DROP INDEX IF EXISTS org_members_group_unique;
DROP INDEX IF EXISTS org_members_user_unique;
DELETE FROM org_members WHERE user_id IS NULL;
ALTER TABLE org_members DROP CONSTRAINT IF EXISTS org_members_user_xor_group;
ALTER TABLE org_members ALTER COLUMN user_id SET NOT NULL;
ALTER TABLE org_members ADD PRIMARY KEY (org_id, user_id);
ALTER TABLE org_members DROP COLUMN IF EXISTS group_id;

DROP TABLE IF EXISTS custom_roles;
DROP TABLE IF EXISTS user_group_members;
DROP TABLE IF EXISTS user_groups;
