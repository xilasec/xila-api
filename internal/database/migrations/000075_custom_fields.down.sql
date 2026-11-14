DELETE FROM triage_rules WHERE action = 'set_custom_field';
DO $$
DECLARE def text;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO def FROM pg_constraint
     WHERE conrelid = 'triage_rules'::regclass AND conname = 'triage_rules_action_check';
    ALTER TABLE triage_rules DROP CONSTRAINT triage_rules_action_check;
    EXECUTE 'ALTER TABLE triage_rules ADD CONSTRAINT triage_rules_action_check '
         || replace(def, '''set_custom_field''::text, ', '');
END
$$;
ALTER TABLE triage_rules DROP COLUMN custom_value, DROP COLUMN custom_field;

DROP TRIGGER IF EXISTS findings_events_custom ON findings;
DROP FUNCTION IF EXISTS findings_record_custom_events();
DROP FUNCTION IF EXISTS custom_field_display(text, jsonb);
DELETE FROM finding_events WHERE kind = 'custom_field';
DO $$
DECLARE def text;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO def FROM pg_constraint
     WHERE conrelid = 'finding_events'::regclass AND conname = 'finding_events_kind_check';
    ALTER TABLE finding_events DROP CONSTRAINT finding_events_kind_check;
    EXECUTE 'ALTER TABLE finding_events ADD CONSTRAINT finding_events_kind_check '
         || replace(def, '''custom_field''::text, ', '');
END
$$;
ALTER TABLE finding_events DROP COLUMN field;

DROP INDEX IF EXISTS findings_custom;
ALTER TABLE findings DROP COLUMN custom;
ALTER TABLE assets   DROP COLUMN custom;
ALTER TABLE projects DROP COLUMN custom;
DROP TABLE IF EXISTS custom_field_definitions;
