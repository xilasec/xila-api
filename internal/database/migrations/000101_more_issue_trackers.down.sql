DELETE FROM issue_trackers WHERE kind IN ('azure-devops', 'linear', 'servicenow');
ALTER TABLE issue_trackers DROP COLUMN IF EXISTS auth_user;
ALTER TABLE issue_trackers DROP CONSTRAINT IF EXISTS issue_trackers_kind_check;
ALTER TABLE issue_trackers ADD CONSTRAINT issue_trackers_kind_check
    CHECK (kind IN ('jira', 'github', 'gitlab'));
