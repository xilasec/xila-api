-- M13 13.18: ticket templates, comment sync and webhook receivers for the
-- per-project issue tracker.
ALTER TABLE issue_trackers
    -- text/template sources for the issue title and body ('' = built in).
    ADD COLUMN title_template     TEXT    NOT NULL DEFAULT '',
    ADD COLUMN body_template      TEXT    NOT NULL DEFAULT '',
    -- Push Xila comments to the issue and accept the tracker's by webhook.
    ADD COLUMN sync_comments      BOOLEAN NOT NULL DEFAULT false,
    -- Verifies inbound webhooks (secretbox, AAD 'issue-webhook:' || id); ''
    -- means the receiver is off.
    ADD COLUMN webhook_secret_enc BYTEA   NOT NULL DEFAULT ''::bytea;

-- One row per comment that crossed between a finding and its issue, either
-- way: what has been pushed, and which tracker comments were already taken
-- in (a redelivered webhook must not add a comment twice).
CREATE TABLE finding_issue_comments (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    link_id    UUID NOT NULL REFERENCES finding_issues(id) ON DELETE CASCADE,
    comment_id UUID NOT NULL REFERENCES finding_comments(id) ON DELETE CASCADE,
    -- The tracker's id for the comment; '' when it has none (ServiceNow work notes).
    remote_id  TEXT NOT NULL DEFAULT '',
    direction  TEXT NOT NULL CHECK (direction IN ('outbound', 'inbound')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (link_id, comment_id)
);
CREATE UNIQUE INDEX idx_finding_issue_comments_remote ON finding_issue_comments (link_id, remote_id) WHERE remote_id <> '';
-- Webhook lookup: which link an issue event is about.
CREATE INDEX idx_finding_issues_external ON finding_issues (tracker_id, external_id);
