-- M13 13.2: a structured VEX analysis (CycloneDX ImpactAnalysisJustification /
-- ImpactAnalysisResponse) on findings, triage rules, pending assessments and
-- stored VEX statements, in finding history, so a manual verdict carries the
-- same machine-readable analysis a VEX document would.
--
-- M13 13.9: a per-project override of ASSESSMENT_REQUIRES_APPROVAL and
-- designated approvers (users and/or groups) who alone may decide an
-- assessment when set.

ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS vex_justification TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS vex_response TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE findings ADD CONSTRAINT findings_vex_justification_check CHECK (
    vex_justification = '' OR vex_justification IN (
        'code_not_present', 'code_not_reachable', 'requires_configuration', 'requires_dependency',
        'requires_environment', 'protected_by_compiler', 'protected_at_runtime', 'protected_at_perimeter',
        'protected_by_mitigating_control')
);
ALTER TABLE findings ADD CONSTRAINT findings_vex_response_check CHECK (
    vex_response <@ ARRAY['can_not_fix', 'will_not_fix', 'update', 'rollback', 'workaround_available']::text[]
);

-- The event kind CHECK is extended in place, like every prior addition to it.
DO $$
DECLARE def text;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO def FROM pg_constraint
     WHERE conrelid = 'finding_events'::regclass AND conname = 'finding_events_kind_check';
    IF position('''vex''' IN def) = 0 THEN
        ALTER TABLE finding_events DROP CONSTRAINT finding_events_kind_check;
        EXECUTE 'ALTER TABLE finding_events ADD CONSTRAINT finding_events_kind_check '
             || replace(def, 'ARRAY[', 'ARRAY[''vex''::text, ');
    END IF;
END
$$;

-- The trigger function is replaced in full (CREATE OR REPLACE), carrying
-- forward every case the latest prior definition (000048) had, plus the new
-- vex_justification / vex_response change.
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
    IF NEW.vex_justification IS DISTINCT FROM OLD.vex_justification
       OR NEW.vex_response IS DISTINCT FROM OLD.vex_response THEN
        INSERT INTO finding_events (finding_id, project_id, kind, from_value, to_value, actor, note)
        VALUES (NEW.id, NEW.project_id, 'vex',
                NULLIF(OLD.vex_justification || CASE WHEN array_length(OLD.vex_response, 1) > 0
                       THEN ' [' || array_to_string(OLD.vex_response, ', ') || ']' ELSE '' END, ''),
                NULLIF(NEW.vex_justification || CASE WHEN array_length(NEW.vex_response, 1) > 0
                       THEN ' [' || array_to_string(NEW.vex_response, ', ') || ']' ELSE '' END, ''),
                finding_actor(), finding_note());
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS findings_events ON findings;
CREATE TRIGGER findings_events
    AFTER INSERT OR UPDATE OF status, severity, assignee_id, tags, vex_justification, vex_response ON findings
    FOR EACH ROW EXECUTE FUNCTION findings_record_events();

-- Triage rules may set the same analysis alongside a false_positive / wont_fix
-- action.
ALTER TABLE triage_rules
    ADD COLUMN IF NOT EXISTS vex_justification TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS vex_response TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE triage_rules ADD CONSTRAINT triage_rules_vex_justification_check CHECK (
    vex_justification = '' OR vex_justification IN (
        'code_not_present', 'code_not_reachable', 'requires_configuration', 'requires_dependency',
        'requires_environment', 'protected_by_compiler', 'protected_at_runtime', 'protected_at_perimeter',
        'protected_by_mitigating_control')
);
ALTER TABLE triage_rules ADD CONSTRAINT triage_rules_vex_response_check CHECK (
    vex_response <@ ARRAY['can_not_fix', 'will_not_fix', 'update', 'rollback', 'workaround_available']::text[]
);

-- A pending assessment carries the same analysis, applied verbatim on approval.
ALTER TABLE finding_assessments
    ADD COLUMN IF NOT EXISTS vex_justification TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS vex_response TEXT[] NOT NULL DEFAULT '{}';
ALTER TABLE finding_assessments ADD CONSTRAINT finding_assessments_vex_justification_check CHECK (
    vex_justification = '' OR vex_justification IN (
        'code_not_present', 'code_not_reachable', 'requires_configuration', 'requires_dependency',
        'requires_environment', 'protected_by_compiler', 'protected_at_runtime', 'protected_at_perimeter',
        'protected_by_mitigating_control')
);
ALTER TABLE finding_assessments ADD CONSTRAINT finding_assessments_vex_response_check CHECK (
    vex_response <@ ARRAY['can_not_fix', 'will_not_fix', 'update', 'rollback', 'workaround_available']::text[]
);

-- An imported CycloneDX document's response codes, kept so an applied verdict
-- can restate them on the findings it covers.
ALTER TABLE vex_statements ADD COLUMN IF NOT EXISTS response TEXT[] NOT NULL DEFAULT '{}';

-- M13 13.9: a project's override of ASSESSMENT_REQUIRES_APPROVAL (inherit
-- follows the instance setting), and who decides when it applies.
ALTER TABLE projects ADD COLUMN IF NOT EXISTS assessment_approval TEXT NOT NULL DEFAULT 'inherit'
    CHECK (assessment_approval IN ('inherit', 'required', 'off'));

-- Designated approvers: a user or a group (never both), granted directly on
-- the project. Empty for a project means "any owner may decide", the
-- original behavior.
CREATE TABLE IF NOT EXISTS project_assessment_approvers (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    user_id    UUID REFERENCES users(id) ON DELETE CASCADE,
    group_id   UUID REFERENCES user_groups(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (num_nonnulls(user_id, group_id) = 1)
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_assessment_approvers_user
    ON project_assessment_approvers (project_id, user_id) WHERE user_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_assessment_approvers_group
    ON project_assessment_approvers (project_id, group_id) WHERE group_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_assessment_approvers_project ON project_assessment_approvers (project_id);
