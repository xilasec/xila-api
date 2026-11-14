-- Account lifecycle: password change/reset, deactivation, session revocation.
--
-- token_version is embedded in every JWT ("tv"); bumping it invalidates all of
-- the user's outstanding sessions at once (password change, "sign out
-- everywhere", deactivation). disabled_at blocks every way in — password, SSO,
-- API tokens — without deleting the account's history.
ALTER TABLE users
    ADD COLUMN token_version       integer NOT NULL DEFAULT 0,
    ADD COLUMN disabled_at         timestamptz,
    ADD COLUMN password_changed_at timestamptz,
    -- The owner is the break-glass account: it can never be locked out.
    ADD CONSTRAINT users_owner_not_disabled CHECK (NOT is_owner OR disabled_at IS NULL);

-- Single-use password reset tokens. Only the SHA-256 of the token is stored.
CREATE TABLE password_reset_tokens (
    token_hash text PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX password_reset_tokens_user ON password_reset_tokens (user_id);
