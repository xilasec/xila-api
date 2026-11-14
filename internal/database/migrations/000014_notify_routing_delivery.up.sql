-- Per-project channel routing: a channel scoped to a project only receives that
-- project's events; a NULL project_id channel receives everything (global).
ALTER TABLE notification_channels
    ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE CASCADE;

-- Delivery log: every send attempt, for debugging retries/failures.
CREATE TABLE IF NOT EXISTS notification_deliveries (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id   UUID REFERENCES notification_channels(id) ON DELETE SET NULL,
    channel_name TEXT NOT NULL DEFAULT '',
    event_type   TEXT NOT NULL,
    delivered    BOOLEAN NOT NULL DEFAULT false,
    status_code  INTEGER,
    attempts     INTEGER NOT NULL DEFAULT 0,
    error        TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_notification_deliveries_created ON notification_deliveries (created_at DESC);
