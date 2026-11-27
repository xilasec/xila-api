-- In-app notification inbox and @mentions (13.8): a per-user feed filled by
-- notify.Service.Notify in the same place every outbound channel is routed
-- (internal/inbox), so every current and future event reaches it. Recipients
-- are the finding's assignee for finding.assigned, the resolved users for
-- mention, a project's watchers (project_watches) for its other events, and
-- instance admins for events naming no project.
CREATE TABLE inbox_items (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL DEFAULT '',
    link       TEXT NOT NULL DEFAULT '',
    project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
    finding_id UUID REFERENCES findings(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    read_at    TIMESTAMPTZ
);
CREATE INDEX idx_inbox_items_user_created ON inbox_items (user_id, created_at DESC);
CREATE INDEX idx_inbox_items_user_unread ON inbox_items (user_id) WHERE read_at IS NULL;

-- Muting: a person may opt out of specific event types in their inbox (and,
-- since this is the same preferences row, their personal channels could use
-- it too) without touching on_assigned / on_watched.
ALTER TABLE user_notification_prefs
    ADD COLUMN muted_events TEXT[] NOT NULL DEFAULT '{}';
