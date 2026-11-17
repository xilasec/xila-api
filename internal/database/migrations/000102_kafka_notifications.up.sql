ALTER TABLE notification_channels DROP CONSTRAINT IF EXISTS notification_channels_type_check;
ALTER TABLE notification_channels ADD CONSTRAINT notification_channels_type_check
    CHECK (type IN ('webhook', 'slack', 'teams', 'mattermost', 'email', 'kafka'));

-- Kafka channel settings (12.13): brokers, optional message-key template, TLS
-- and SASL mechanism/username. The topic is the channel's existing `url`
-- column, the same way every other type keeps its target there; the SASL
-- password is sealed into the existing signing_secret column (secretbox, AAD
-- = channel id, write-only), exactly the way a generic webhook's signature
-- secret is.
ALTER TABLE notification_channels ADD COLUMN config JSONB NOT NULL DEFAULT '{}'::jsonb;
