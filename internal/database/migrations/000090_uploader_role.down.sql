ALTER TABLE sso_group_mappings DROP CONSTRAINT sso_group_mappings_target,
    ADD CONSTRAINT sso_group_mappings_target CHECK (
        (target_kind = 'instance_admin' AND org_id IS NULL AND team_id IS NULL AND project_id IS NULL AND role = '')
     OR (target_kind = 'org' AND org_id IS NOT NULL AND team_id IS NULL AND project_id IS NULL AND role IN ('admin', 'member'))
     OR (target_kind = 'team' AND team_id IS NOT NULL AND org_id IS NULL AND project_id IS NULL AND role IN ('owner', 'editor', 'viewer'))
     OR (target_kind = 'project' AND project_id IS NOT NULL AND org_id IS NULL AND team_id IS NULL AND role IN ('owner', 'editor', 'viewer'))
    );

ALTER TABLE project_members DROP CONSTRAINT project_members_role_check,
    ADD CONSTRAINT project_members_role_check CHECK (role IN ('owner', 'editor', 'viewer'));

ALTER TABLE team_members DROP CONSTRAINT team_members_role_check,
    ADD CONSTRAINT team_members_role_check CHECK (role IN ('owner', 'editor', 'viewer'));
