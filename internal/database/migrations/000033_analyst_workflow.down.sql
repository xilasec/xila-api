DROP TRIGGER IF EXISTS findings_events ON findings;
DROP FUNCTION IF EXISTS findings_record_events();
DROP FUNCTION IF EXISTS finding_note();
DROP FUNCTION IF EXISTS finding_actor();
DROP TABLE IF EXISTS finding_events;
DROP TABLE IF EXISTS finding_attachments;
DROP TABLE IF EXISTS finding_comments;
DROP INDEX IF EXISTS idx_findings_assignee;
ALTER TABLE findings DROP COLUMN IF EXISTS assignee_id;
