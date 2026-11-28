DROP INDEX IF EXISTS idx_finding_issues_external;
DROP TABLE IF EXISTS finding_issue_comments;
ALTER TABLE issue_trackers
    DROP COLUMN IF EXISTS webhook_secret_enc,
    DROP COLUMN IF EXISTS sync_comments,
    DROP COLUMN IF EXISTS body_template,
    DROP COLUMN IF EXISTS title_template;
