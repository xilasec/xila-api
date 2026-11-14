-- Signed webhooks (M8.8). A generic webhook channel may carry a signing
-- secret, sealed with internal/secretbox (AAD = the channel id) and never
-- returned by the API. Every outbox row gets a delivery id: sent as
-- X-Xila-Delivery and kept across retries, so receivers can drop duplicates.
ALTER TABLE notification_channels ADD COLUMN signing_secret BYTEA;
ALTER TABLE notification_outbox ADD COLUMN delivery_id UUID NOT NULL DEFAULT gen_random_uuid();
