-- Per-browser-session tracking for the idle timeout and absolute session
-- lifetime (SESSION_IDLE_TIMEOUT / SESSION_MAX_AGE). A row exists only while
-- tracking is active (an idle timeout is configured, or the max age is set
-- shorter than JWT_TTL); auth.Service mints a session id (JWT claim "sid")
-- and inserts this row at sign-in; auth.Middleware checks it on every later
-- request and refreshes last_seen_at at most once a minute. "Sign out everywhere" keeps working
-- through the existing users.token_version check — this table only adds the
-- idle/absolute clock, not session revocation.
CREATE TABLE user_sessions (
    id           UUID PRIMARY KEY,
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_user_sessions_user_id ON user_sessions (user_id);
