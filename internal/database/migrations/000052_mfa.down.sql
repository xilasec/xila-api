DROP TABLE IF EXISTS mfa_recovery_codes;
ALTER TABLE users
    DROP COLUMN IF EXISTS mfa_last_step,
    DROP COLUMN IF EXISTS mfa_enabled_at,
    DROP COLUMN IF EXISTS mfa_secret_enc;
