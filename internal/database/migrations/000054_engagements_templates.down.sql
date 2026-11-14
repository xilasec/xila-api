DROP TABLE IF EXISTS finding_templates;
ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_engagement_fk;
DROP INDEX IF EXISTS scans_engagement;
ALTER TABLE scans DROP COLUMN IF EXISTS engagement_id;
DROP TABLE IF EXISTS engagements;
