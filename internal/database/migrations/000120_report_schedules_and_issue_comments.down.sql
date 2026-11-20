ALTER TABLE issue_trackers DROP COLUMN webhook_secret_enc;
ALTER TABLE issue_trackers DROP COLUMN comment_on_finding_comment;
ALTER TABLE issue_trackers DROP COLUMN jira_fields;
ALTER TABLE issue_trackers DROP COLUMN body_template;
ALTER TABLE issue_trackers DROP COLUMN title_template;

DROP TABLE report_schedule_runs;
DROP TABLE report_schedules;
