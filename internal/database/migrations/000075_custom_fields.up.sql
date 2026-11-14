-- Typed custom fields: admin-defined fields on projects, assets and findings.
--
-- Values live in a jsonb `custom` column on each entity (key → JSON scalar),
-- not in a value table: every reader that already loads the row (lists, the
-- export cursor, CEL documents, the triage engine) gets them for free, filters
-- are a containment / ->> test on the same row, and a finding's history
-- trigger can diff OLD and NEW in place. The Go layer validates every write
-- against the definitions (type, enum membership, a user who can see the entity).

CREATE TABLE custom_field_definitions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    entity     TEXT NOT NULL CHECK (entity IN ('project', 'asset', 'finding')),
    key        TEXT NOT NULL CHECK (key ~ '^[a-z][a-z0-9_]{0,39}$'),
    label      TEXT NOT NULL CHECK (length(label) BETWEEN 1 AND 100),
    type       TEXT NOT NULL CHECK (type IN ('text', 'number', 'date', 'enum', 'user')),
    options    TEXT[] NOT NULL DEFAULT '{}',
    required   BOOLEAN NOT NULL DEFAULT false,
    -- NULL = every organization; else the field applies only to that org's entities.
    org_id     UUID REFERENCES organizations(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (entity, key),
    CHECK ((type = 'enum') = (cardinality(options) > 0))
);

ALTER TABLE projects ADD COLUMN custom JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(custom) = 'object');
ALTER TABLE assets   ADD COLUMN custom JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(custom) = 'object');
ALTER TABLE findings ADD COLUMN custom JSONB NOT NULL DEFAULT '{}' CHECK (jsonb_typeof(custom) = 'object');
-- ?cf.<key>=value is a containment test, which this index serves.
CREATE INDEX findings_custom ON findings USING gin (custom jsonb_path_ops);

-- History: one finding_events row per changed custom field. `field` names it.
-- The kind CHECK is extended in place (whatever kinds it already lists stay).
ALTER TABLE finding_events ADD COLUMN field TEXT;
DO $$
DECLARE def text;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO def FROM pg_constraint
     WHERE conrelid = 'finding_events'::regclass AND conname = 'finding_events_kind_check';
    IF position('''custom_field''' IN def) = 0 THEN
        ALTER TABLE finding_events DROP CONSTRAINT finding_events_kind_check;
        EXECUTE 'ALTER TABLE finding_events ADD CONSTRAINT finding_events_kind_check '
             || replace(def, 'ARRAY[', 'ARRAY[''custom_field''::text, ');
    END IF;
END
$$;

-- A value as history shows it: the scalar's text, a user field's email.
CREATE FUNCTION custom_field_display(field text, v jsonb) RETURNS text LANGUAGE sql STABLE AS $$
    SELECT CASE
        WHEN v IS NULL OR jsonb_typeof(v) = 'null' THEN NULL
        WHEN (SELECT type FROM custom_field_definitions WHERE entity = 'finding' AND key = field) = 'user'
            THEN COALESCE((SELECT email FROM users WHERE id::text = v #>> '{}'), v #>> '{}')
        ELSE v #>> '{}'
    END
$$;

CREATE FUNCTION findings_record_custom_events() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO finding_events (finding_id, project_id, kind, field, from_value, to_value, actor, note)
    SELECT NEW.id, NEW.project_id, 'custom_field', k,
           custom_field_display(k, OLD.custom -> k), custom_field_display(k, NEW.custom -> k),
           finding_actor(), finding_note()
      FROM (SELECT jsonb_object_keys(OLD.custom) UNION SELECT jsonb_object_keys(NEW.custom)) AS keys(k)
     WHERE (OLD.custom -> k) IS DISTINCT FROM (NEW.custom -> k)
     ORDER BY k;
    RETURN NEW;
END
$$;

CREATE TRIGGER findings_events_custom
    AFTER UPDATE OF custom ON findings
    FOR EACH ROW WHEN (OLD.custom IS DISTINCT FROM NEW.custom)
    EXECUTE FUNCTION findings_record_custom_events();

-- Triage rules may set a finding custom field. The action CHECK is extended in
-- place, like the event kinds above.
ALTER TABLE triage_rules
    ADD COLUMN custom_field TEXT NOT NULL DEFAULT '',
    ADD COLUMN custom_value JSONB;
DO $$
DECLARE def text;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO def FROM pg_constraint
     WHERE conrelid = 'triage_rules'::regclass AND conname = 'triage_rules_action_check';
    IF position('''set_custom_field''' IN def) = 0 THEN
        ALTER TABLE triage_rules DROP CONSTRAINT triage_rules_action_check;
        EXECUTE 'ALTER TABLE triage_rules ADD CONSTRAINT triage_rules_action_check '
             || replace(def, 'ARRAY[', 'ARRAY[''set_custom_field''::text, ');
    END IF;
END
$$;
