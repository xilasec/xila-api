ALTER TABLE projects DROP COLUMN IF EXISTS skip_global_rules;
DROP TABLE IF EXISTS triage_settings;
DROP TABLE IF EXISTS triage_rule_actions;
ALTER TABLE triage_rules
    DROP COLUMN IF EXISTS assign_user_id,
    DROP COLUMN IF EXISTS assign_owner_from,
    DROP COLUMN IF EXISTS only_if_unassigned,
    DROP COLUMN IF EXISTS add_tags,
    DROP COLUMN IF EXISTS comment,
    DROP COLUMN IF EXISTS notify,
    DROP COLUMN IF EXISTS schedule,
    DROP COLUMN IF EXISTS schedule_last_run_at,
    DROP COLUMN IF EXISTS age_days_gt;
