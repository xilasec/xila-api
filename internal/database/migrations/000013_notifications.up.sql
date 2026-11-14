-- Outbound notification channels (webhooks / Slack). `events` filters which
-- event types a channel receives ('*' = all).
CREATE TABLE IF NOT EXISTS notification_channels (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    type       TEXT NOT NULL CHECK (type IN ('webhook', 'slack')),
    url        TEXT NOT NULL,
    events     TEXT[] NOT NULL DEFAULT '{*}',
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
