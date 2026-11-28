DELETE FROM triage_rules WHERE action = 'none';
DO $$
DECLARE def text;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO def FROM pg_constraint
     WHERE conrelid = 'triage_rules'::regclass AND conname = 'triage_rules_action_check';
    IF position('''none''' IN def) > 0 THEN
        ALTER TABLE triage_rules DROP CONSTRAINT triage_rules_action_check;
        EXECUTE 'ALTER TABLE triage_rules ADD CONSTRAINT triage_rules_action_check '
             || replace(def, '''none''::text, ', '');
    END IF;
END
$$;
DELETE FROM vuln_policies WHERE owner_project_id IS NOT NULL;
ALTER TABLE vuln_policies DROP COLUMN IF EXISTS owner_project_id;
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
