ALTER TABLE users DROP COLUMN IF EXISTS oidc_subject;
-- Note: password_hash is left nullable on downgrade (SSO users would violate NOT NULL).
