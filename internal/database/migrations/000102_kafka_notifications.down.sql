ALTER TABLE notification_channels DROP COLUMN config;

DELETE FROM notification_channels WHERE type = 'kafka';
ALTER TABLE notification_channels DROP CONSTRAINT IF EXISTS notification_channels_type_check;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_type_check
    CHECK (type IN ('webhook', 'slack', 'teams', 'mattermost', 'email'));
