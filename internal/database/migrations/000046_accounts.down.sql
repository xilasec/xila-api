DROP TABLE IF EXISTS password_reset_tokens;
ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_owner_not_disabled,
    DROP COLUMN IF EXISTS password_changed_at,
    DROP COLUMN IF EXISTS disabled_at,
    DROP COLUMN IF EXISTS token_version;
