-- Remediation work items: open findings grouped by the one change that fixes
-- them (a package upgrade, a base-image rebuild, an IaC rule on one resource, a
-- code location, a config fix), tracked with an owner, a due date and a status.
--
-- key identifies the change within (project, kind) — e.g. "lodash@4.17.15|pkg:npm/lodash"
-- — so new findings the same change fixes join the live action instead of
-- spawning another. At most one live (open / in_progress) action per key.
CREATE TABLE remediation_actions (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    kind          text NOT NULL
                  CHECK (kind IN ('package_upgrade', 'base_image', 'iac_rule', 'code_location', 'config')),
    key           text NOT NULL,
    title         text NOT NULL,
    -- What to move to, when the change has one (the package version to upgrade to).
    target        text NOT NULL DEFAULT '',
    -- Owner: derived from the findings' assignees unless set by hand
    -- (owner_manual), which then sticks.
    owner_id      uuid REFERENCES users (id) ON DELETE SET NULL,
    owner_manual  boolean NOT NULL DEFAULT false,
    -- The earliest SLA deadline among the action's live findings.
    due_at        timestamptz,
    status        text NOT NULL DEFAULT 'open'
                  CHECK (status IN ('open', 'in_progress', 'done', 'wont_do')),
    -- Audit: created_by / closed_by NULL = the system (auto-create, auto-close,
    -- the issue tracker); close_reason says which.
    created_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),
    closed_at     timestamptz,
    closed_by     uuid REFERENCES users (id) ON DELETE SET NULL,
    close_reason  text NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX remediation_actions_live_key
    ON remediation_actions (project_id, kind, md5(key)) WHERE status IN ('open', 'in_progress');
CREATE INDEX remediation_actions_project ON remediation_actions (project_id, status);

-- The findings an action closes.
CREATE TABLE remediation_action_findings (
    action_id  uuid NOT NULL REFERENCES remediation_actions (id) ON DELETE CASCADE,
    finding_id uuid NOT NULL REFERENCES findings (id) ON DELETE CASCADE,
    added_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (action_id, finding_id)
);
CREATE INDEX remediation_action_findings_finding ON remediation_action_findings (finding_id);

-- One issue-tracker ticket per action, synced both ways like finding_issues:
-- state is the last state both sides agreed on.
CREATE TABLE remediation_action_issues (
    id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id      uuid NOT NULL UNIQUE REFERENCES remediation_actions (id) ON DELETE CASCADE,
    tracker_id     uuid NOT NULL REFERENCES issue_trackers (id) ON DELETE CASCADE,
    external_id    text NOT NULL,
    url            text NOT NULL DEFAULT '',
    state          text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'closed')),
    last_synced_at timestamptz NOT NULL DEFAULT now(),
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX remediation_action_issues_tracker ON remediation_action_issues (tracker_id);
