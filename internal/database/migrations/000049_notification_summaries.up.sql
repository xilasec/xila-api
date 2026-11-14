-- Per-channel filters and scheduled summaries.
--
-- min_severity: events that carry a severity below it skip the channel (events
-- without one — summaries, policy, test — always pass).
-- summary / summary_hour / summary_weekday: a scheduled summary of the
-- channel's scope (its project, or the whole portfolio) — daily at the hour,
-- or weekly on the weekday at the hour (UTC; 0 = Sunday). last_summary_at is
-- the slot last sent; claiming it in the same transaction as the enqueue makes
-- a summary go out once even across a leader handover.
ALTER TABLE notification_channels
    ADD COLUMN min_severity    text CHECK (min_severity IN ('critical', 'high', 'medium', 'low', 'info')),
    ADD COLUMN summary         text NOT NULL DEFAULT 'none' CHECK (summary IN ('none', 'daily', 'weekly')),
    ADD COLUMN summary_hour    int  NOT NULL DEFAULT 8 CHECK (summary_hour BETWEEN 0 AND 23),
    ADD COLUMN summary_weekday int  NOT NULL DEFAULT 1 CHECK (summary_weekday BETWEEN 0 AND 6),
    ADD COLUMN last_summary_at timestamptz;

-- The fixed daily "digest" event (DIGEST_ENABLED/DIGEST_INTERVAL) is replaced by
-- per-channel summaries: channels that received it get a daily summary, and
-- the event subscription goes away.
UPDATE notification_channels
   SET summary = 'daily', last_summary_at = now()
 WHERE events @> ARRAY['digest'] OR events @> ARRAY['*'];
UPDATE notification_channels SET events = array_remove(events, 'digest') WHERE events @> ARRAY['digest'];
