DROP TABLE IF EXISTS project_assessment_approvers;
ALTER TABLE projects DROP COLUMN IF EXISTS assessment_approval;

ALTER TABLE vex_statements DROP COLUMN IF EXISTS response;

ALTER TABLE triage_carries
    DROP COLUMN IF EXISTS vex_justification,
    DROP COLUMN IF EXISTS vex_response;

ALTER TABLE finding_assessments
    DROP CONSTRAINT IF EXISTS finding_assessments_vex_justification_check,
    DROP CONSTRAINT IF EXISTS finding_assessments_vex_response_check,
    DROP COLUMN IF EXISTS vex_justification,
    DROP COLUMN IF EXISTS vex_response;

ALTER TABLE triage_rules
    DROP CONSTRAINT IF EXISTS triage_rules_vex_justification_check,
    DROP CONSTRAINT IF EXISTS triage_rules_vex_response_check,
    DROP COLUMN IF EXISTS vex_justification,
    DROP COLUMN IF EXISTS vex_response;

DELETE FROM finding_events WHERE kind = 'vex';
ALTER TABLE finding_events DROP CONSTRAINT IF EXISTS finding_events_kind_check;
ALTER TABLE finding_events ADD CONSTRAINT finding_events_kind_check
    CHECK (kind IN ('created', 'status', 'severity', 'assignee', 'comment', 'attachment', 'assessment', 'tags', 'custom_field', 'duplicate'));

CREATE OR REPLACE FUNCTION findings_record_events() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO finding_events (finding_id, project_id, kind, to_value, actor)
        VALUES (NEW.id, NEW.project_id, 'created', NEW.status, finding_actor());
        RETURN NEW;
    END IF;
    IF NEW.status IS DISTINCT FROM OLD.status THEN
        INSERT INTO finding_events (finding_id, project_id, kind, from_value, to_value, actor, note)
        VALUES (NEW.id, NEW.project_id, 'status', OLD.status, NEW.status, finding_actor(), finding_note());
    END IF;
    IF NEW.severity IS DISTINCT FROM OLD.severity THEN
        INSERT INTO finding_events (finding_id, project_id, kind, from_value, to_value, actor, note)
        VALUES (NEW.id, NEW.project_id, 'severity', OLD.severity, NEW.severity, finding_actor(), finding_note());
    END IF;
    IF NEW.assignee_id IS DISTINCT FROM OLD.assignee_id THEN
        INSERT INTO finding_events (finding_id, project_id, kind, from_value, to_value, actor, note)
        VALUES (NEW.id, NEW.project_id, 'assignee',
                (SELECT email FROM users WHERE id = OLD.assignee_id),
                (SELECT email FROM users WHERE id = NEW.assignee_id),
                finding_actor(), finding_note());
    END IF;
    IF NEW.tags IS DISTINCT FROM OLD.tags THEN
        INSERT INTO finding_events (finding_id, project_id, kind, from_value, to_value, actor, note)
        VALUES (NEW.id, NEW.project_id, 'tags', array_to_string(OLD.tags, ', '), array_to_string(NEW.tags, ', '),
                finding_actor(), finding_note());
    END IF;
    IF NEW.duplicate_of IS DISTINCT FROM OLD.duplicate_of AND (NEW.duplicate_manual OR OLD.duplicate_manual) THEN
        INSERT INTO finding_events (finding_id, project_id, kind, from_value, to_value, actor, note)
        VALUES (NEW.id, NEW.project_id, 'duplicate', OLD.duplicate_of::text, NEW.duplicate_of::text,
                finding_actor(), finding_note());
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS findings_events ON findings;
CREATE TRIGGER findings_events
    AFTER INSERT OR UPDATE OF status, severity, assignee_id, tags, duplicate_of ON findings
    FOR EACH ROW EXECUTE FUNCTION findings_record_events();

ALTER TABLE findings
    DROP CONSTRAINT IF EXISTS findings_vex_justification_check,
    DROP CONSTRAINT IF EXISTS findings_vex_response_check,
    DROP COLUMN IF EXISTS vex_justification,
    DROP COLUMN IF EXISTS vex_response;
