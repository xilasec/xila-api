-- Scheduled report delivery (M13 13.17 half): a user's own recurring report,
-- rendered as the owner (their RBAC scope at send time) and delivered by
-- email (HTML attachment) or as a link-only notification to channels.
CREATE TABLE report_schedules (
    id                    uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id              uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name                  text NOT NULL CHECK (name <> ''),
    kind                  text NOT NULL CHECK (kind IN ('project', 'portfolio', 'evidence')),
    -- project_id is required for 'project' and 'evidence'; null for 'portfolio'
    -- (the owner's whole visible scope at send time).
    project_id            uuid REFERENCES projects (id) ON DELETE CASCADE,
    -- framework_key is required for 'evidence' only (internal/compliance key).
    framework_key         text NOT NULL DEFAULT '',
    template_id           uuid REFERENCES report_templates (id) ON DELETE SET NULL,
    engagement_id         uuid REFERENCES engagements (id) ON DELETE SET NULL,
    cadence               text NOT NULL CHECK (cadence IN ('daily', 'weekly', 'monthly')),
    hour                  smallint NOT NULL DEFAULT 8 CHECK (hour BETWEEN 0 AND 23),
    weekday               smallint CHECK (weekday BETWEEN 0 AND 6),
    day_of_month          smallint CHECK (day_of_month BETWEEN 1 AND 28),
    recipient_emails      text[] NOT NULL DEFAULT '{}',
    recipient_channel_ids uuid[] NOT NULL DEFAULT '{}',
    enabled               boolean NOT NULL DEFAULT true,
    last_run_at           timestamptz,
    last_run_status       text NOT NULL DEFAULT '' CHECK (last_run_status IN ('', 'success', 'failure')),
    last_run_error        text NOT NULL DEFAULT '',
    created_at            timestamptz NOT NULL DEFAULT now(),
    updated_at            timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT report_schedules_project_required CHECK (
        (kind = 'portfolio' AND project_id IS NULL) OR
        (kind IN ('project', 'evidence') AND project_id IS NOT NULL)
    ),
    CONSTRAINT report_schedules_framework_required CHECK (
        (kind = 'evidence' AND framework_key <> '') OR
        (kind <> 'evidence' AND framework_key = '')
    ),
    CONSTRAINT report_schedules_weekday_required CHECK (
        (cadence = 'weekly') = (weekday IS NOT NULL)
    ),
    CONSTRAINT report_schedules_day_of_month_required CHECK (
        (cadence = 'monthly') = (day_of_month IS NOT NULL)
    )
);
CREATE INDEX report_schedules_owner_idx ON report_schedules (owner_id);
CREATE INDEX report_schedules_due_idx ON report_schedules (enabled) WHERE enabled;

-- One row per run (success or failure), for the schedule's history view.
CREATE TABLE report_schedule_runs (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    schedule_id  uuid NOT NULL REFERENCES report_schedules (id) ON DELETE CASCADE,
    started_at   timestamptz NOT NULL DEFAULT now(),
    finished_at  timestamptz,
    status       text NOT NULL CHECK (status IN ('success', 'failure')),
    error        text NOT NULL DEFAULT '',
    recipients   int NOT NULL DEFAULT 0
);
CREATE INDEX report_schedule_runs_schedule_idx ON report_schedule_runs (schedule_id, started_at DESC);

-- Issue-tracker comments, ticket templates and webhook receivers (M13 13.18).
--
-- title_template/body_template: Go text/template over a fixed finding-field
-- set, rendered instead of the default BuildIssue layout when set. Validated
-- on save (service.go): must parse, execute against sample data and contain
-- no HTML tags.
ALTER TABLE issue_trackers ADD COLUMN title_template text NOT NULL DEFAULT '';
ALTER TABLE issue_trackers ADD COLUMN body_template text NOT NULL DEFAULT '';
-- jira_fields: static custom-field mappings (Jira field id -> value), applied
-- on every issue this tracker creates. Other kinds use the existing labels
-- column for the same purpose (GitHub/GitLab/Azure DevOps labels, Linear
-- labels, ServiceNow categories).
ALTER TABLE issue_trackers ADD COLUMN jira_fields jsonb NOT NULL DEFAULT '{}';
-- comment_on_finding_comment: opt-in per tracker — mirror a Xila finding
-- comment onto the linked issue.
ALTER TABLE issue_trackers ADD COLUMN comment_on_finding_comment boolean NOT NULL DEFAULT false;
-- webhook_secret_enc: sealed (secretbox, AAD = tracker id) shared secret for
-- POST /hooks/issue-trackers/{trackerID}. Null means the webhook is disabled
-- for that tracker (404). Generated server-side only, never accepted as input.
ALTER TABLE issue_trackers ADD COLUMN webhook_secret_enc bytea;
