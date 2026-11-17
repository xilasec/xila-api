-- Three more issue trackers: Azure DevOps Boards, Linear and ServiceNow
-- (alongside Jira, GitHub Issues and GitLab Issues).
--
-- auth_user is the ServiceNow Basic auth username (not a secret, stored in
-- the clear like jira_email): an empty value means the stored token is sent
-- as a Bearer OAuth access token instead. Every other kind leaves it empty.
-- issue_type, done_transition and reopen_transition are reused per kind:
-- Azure DevOps' work item type and System.State close/reopen values; Linear's
-- workflow state *types* (completed/canceled vs. unstarted, not names);
-- ServiceNow's state field close/reopen values. jira_email stays Jira-only.
ALTER TABLE issue_trackers DROP CONSTRAINT IF EXISTS issue_trackers_kind_check;
ALTER TABLE issue_trackers ADD CONSTRAINT issue_trackers_kind_check
    CHECK (kind IN ('jira', 'github', 'gitlab', 'azure-devops', 'linear', 'servicenow'));
ALTER TABLE issue_trackers ADD COLUMN auth_user TEXT NOT NULL DEFAULT '';
