-- M13 13.5: triage rules that assign, tag, comment and notify, plus more
-- triggers (a rule-level schedule, re-evaluation after a person's decision).
-- M13 13.10: project owners manage their own triage rules and vulnerability
-- policies, and may opt out of global ones when an instance admin allows it.
ALTER TABLE triage_rules
    -- Side actions, alongside the rule's one primary action: assign (a user
    -- id, or owner_from = 'project_owner'), add tags, post a comment, and/or
    -- enqueue a notification. All independent of each other and of the
    -- primary action; '' / NULL / empty / false means "not configured".
    ADD COLUMN IF NOT EXISTS assign_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN IF NOT EXISTS assign_owner_from TEXT NOT NULL DEFAULT ''
        CHECK (assign_owner_from IN ('', 'project_owner')),
    ADD COLUMN IF NOT EXISTS only_if_unassigned BOOLEAN NOT NULL DEFAULT true,
    ADD COLUMN IF NOT EXISTS add_tags TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS comment TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS notify BOOLEAN NOT NULL DEFAULT false,
    -- Schedule trigger: '' = none (ingest + finding-event only); 'daily' runs
    -- once per leader tick where >= 24h passed since schedule_last_run_at.
    ADD COLUMN IF NOT EXISTS schedule TEXT NOT NULL DEFAULT ''
        CHECK (schedule IN ('', 'daily')),
    ADD COLUMN IF NOT EXISTS schedule_last_run_at TIMESTAMPTZ,
    -- Condition: finding.first_seen_at is more than this many days ago.
    ADD COLUMN IF NOT EXISTS age_days_gt INT CHECK (age_days_gt IS NULL OR age_days_gt >= 0);

-- Tracks a side action already fired for a (rule, finding), so re-running an
-- idempotent rule on every ingest/schedule/event never reposts a comment or
-- re-sends a notification for the same finding. assign/add_tags need no log:
-- they're naturally idempotent (assigning/tagging what's already set is a
-- no-op at the SQL layer).
CREATE TABLE IF NOT EXISTS triage_rule_actions (
    rule_id    UUID NOT NULL REFERENCES triage_rules(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    action     TEXT NOT NULL CHECK (action IN ('comment', 'notify')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (rule_id, finding_id, action)
);
CREATE INDEX IF NOT EXISTS idx_triage_rule_actions_rule ON triage_rule_actions (rule_id);

-- Instance-wide triage settings (singleton row, like sla_settings /
-- ingest_settings): whether a project owner may opt their project out of
-- global rules at all (default not allowed).
CREATE TABLE IF NOT EXISTS triage_settings (
    id                          BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),
    allow_skip_global_rules     BOOLEAN NOT NULL DEFAULT false,
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO triage_settings DEFAULT VALUES ON CONFLICT DO NOTHING;

-- A project may opt out of global (project_id IS NULL) triage rules, only
-- when triage_settings.allow_skip_global_rules is on (enforced in
-- internal/project, not here: an instance admin could still turn the
-- instance setting off after a project opted out, and that project's flag
-- is left as-is — it simply stops mattering until re-allowed).
ALTER TABLE projects ADD COLUMN IF NOT EXISTS skip_global_rules BOOLEAN NOT NULL DEFAULT false;

-- A vulnerability policy a project owner made for their project (13.10). Its
-- scope is that project alone; the GitOps bundle (PUT /vuln-policies/bundle)
-- manages admin policies only (owner_project_id IS NULL) and never replaces
-- these.
ALTER TABLE vuln_policies ADD COLUMN IF NOT EXISTS owner_project_id UUID REFERENCES projects(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_vuln_policies_owner_project ON vuln_policies (owner_project_id) WHERE owner_project_id IS NOT NULL;

-- A rule may act through its side actions alone ("assign every critical to
-- the platform team"): action 'none' changes no status, severity or field.
DO $$
DECLARE def text;
BEGIN
    SELECT pg_get_constraintdef(oid) INTO def FROM pg_constraint
     WHERE conrelid = 'triage_rules'::regclass AND conname = 'triage_rules_action_check';
    IF position('''none''' IN def) = 0 THEN
        ALTER TABLE triage_rules DROP CONSTRAINT triage_rules_action_check;
        EXECUTE 'ALTER TABLE triage_rules ADD CONSTRAINT triage_rules_action_check '
             || replace(def, 'ARRAY[', 'ARRAY[''none''::text, ');
    END IF;
END
$$;
