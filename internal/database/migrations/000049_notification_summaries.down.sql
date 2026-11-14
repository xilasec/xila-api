UPDATE notification_channels SET events = array_append(events, 'digest')
 WHERE summary <> 'none' AND NOT events @> ARRAY['*'] AND NOT events @> ARRAY['digest'];
ALTER TABLE notification_channels
    DROP COLUMN IF EXISTS last_summary_at,
    DROP COLUMN IF EXISTS summary_weekday,
    DROP COLUMN IF EXISTS summary_hour,
    DROP COLUMN IF EXISTS summary,
    DROP COLUMN IF EXISTS min_severity;
