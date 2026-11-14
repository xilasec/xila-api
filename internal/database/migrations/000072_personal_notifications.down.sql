DROP TABLE IF EXISTS project_watches;
DROP TABLE IF EXISTS user_notification_prefs;
DELETE FROM notification_channels WHERE owner_user_id IS NOT NULL;
DROP INDEX IF EXISTS uq_notification_channels_personal;
ALTER TABLE notification_channels DROP COLUMN url_enc, DROP COLUMN owner_user_id;
