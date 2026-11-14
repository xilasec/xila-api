-- Finding tags (user-managed labels: "pci", "q3-sprint", "needs-vendor") and
-- full-text search over a finding's text.

ALTER TABLE findings ADD COLUMN tags text[] NOT NULL DEFAULT '{}';
CREATE INDEX findings_tags ON findings USING gin (tags);

-- array_to_string is only STABLE (element output functions could in theory
-- vary); for text[] it is immutable, which a generated column requires.
CREATE FUNCTION findings_text_array(a text[]) RETURNS text
    LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$ SELECT array_to_string(a, ' ') $$;

-- 'simple' (no stemming, no stop words): findings are identifiers — CVE ids,
-- package names, paths, rule ids — that an English stemmer would mangle.
-- Identity fields weigh more than the description.
ALTER TABLE findings ADD COLUMN search tsvector GENERATED ALWAYS AS (
    setweight(to_tsvector('simple'::regconfig,
        coalesce(title, '') || ' ' || coalesce(rule_id, '') || ' ' || findings_text_array(cve) || ' ' ||
        coalesce(package_name, '') || ' ' || coalesce(purl, '') || ' ' || findings_text_array(tags)), 'A') ||
    setweight(to_tsvector('simple'::regconfig, coalesce(file_path, '')), 'B') ||
    setweight(to_tsvector('simple'::regconfig, left(coalesce(description, ''), 20000)), 'C')
) STORED;
CREATE INDEX findings_search ON findings USING gin (search);

-- Tag changes join the finding's history.
ALTER TABLE finding_events DROP CONSTRAINT finding_events_kind_check;
ALTER TABLE finding_events ADD CONSTRAINT finding_events_kind_check
    CHECK (kind IN ('created', 'status', 'severity', 'assignee', 'comment', 'attachment', 'assessment', 'tags'));

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
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS findings_events ON findings;
CREATE TRIGGER findings_events
    AFTER INSERT OR UPDATE OF status, severity, assignee_id, tags ON findings
    FOR EACH ROW EXECUTE FUNCTION findings_record_events();
