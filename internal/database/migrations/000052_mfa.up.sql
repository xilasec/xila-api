-- TOTP two-factor authentication for password sign-in (local and directory).
-- The secret is sealed with INTEGRATION_SECRET_KEY; mfa_enabled_at is set once
-- the user proved a code from it. mfa_last_step stops a code being replayed.
ALTER TABLE users
    ADD COLUMN mfa_secret_enc bytea,
    ADD COLUMN mfa_enabled_at timestamptz,
    ADD COLUMN mfa_last_step  bigint;

-- Single-use recovery codes, stored as SHA-256.
CREATE TABLE mfa_recovery_codes (
    user_id   uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash text NOT NULL,
    used_at   timestamptz,
    PRIMARY KEY (user_id, code_hash)
);
