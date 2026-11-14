DROP TRIGGER IF EXISTS findings_events ON findings;
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
    RETURN NEW;
END
$$;
CREATE TRIGGER findings_events
    AFTER INSERT OR UPDATE OF status, severity, assignee_id ON findings
    FOR EACH ROW EXECUTE FUNCTION findings_record_events();
DELETE FROM finding_events WHERE kind = 'tags';
ALTER TABLE finding_events DROP CONSTRAINT finding_events_kind_check;
ALTER TABLE finding_events ADD CONSTRAINT finding_events_kind_check
    CHECK (kind IN ('created', 'status', 'severity', 'assignee', 'comment', 'attachment', 'assessment'));
DROP INDEX IF EXISTS findings_search;
ALTER TABLE findings DROP COLUMN IF EXISTS search;
DROP FUNCTION IF EXISTS findings_text_array(text[]);
DROP INDEX IF EXISTS findings_tags;
ALTER TABLE findings DROP COLUMN IF EXISTS tags;
