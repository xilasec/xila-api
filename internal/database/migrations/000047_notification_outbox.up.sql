-- Durable notification delivery. Notify() writes one row per subscribed
-- channel (the subscription is decided when the event happens); the leader's
-- dispatcher delivers due rows, retrying with backoff across restarts and
-- failovers. A claimed row carries a lease (locked_until): if its dispatcher
-- dies mid-send, the row becomes due again when the lease runs out.
CREATE TABLE notification_outbox (
    id              bigserial PRIMARY KEY,
    channel_id      uuid NOT NULL REFERENCES notification_channels (id) ON DELETE CASCADE,
    event           jsonb NOT NULL,
    attempts        integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    locked_until    timestamptz,
    last_status     integer,
    last_error      text NOT NULL DEFAULT '',
    delivered_at    timestamptz,
    failed_at       timestamptz, -- gave up after NOTIFY_MAX_ATTEMPTS
    created_at      timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX notification_outbox_due ON notification_outbox (next_attempt_at)
    WHERE delivered_at IS NULL AND failed_at IS NULL;
CREATE INDEX notification_outbox_done ON notification_outbox (created_at)
    WHERE delivered_at IS NOT NULL OR failed_at IS NOT NULL;
