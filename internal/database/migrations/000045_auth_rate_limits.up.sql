-- Fixed-window counters for password sign-in attempts, shared by every replica
-- (an in-memory limiter is per process, so N replicas allowed N× the attempts).
-- Keys are "ip:<addr>" and "acct:<normalized email>".
CREATE TABLE IF NOT EXISTS auth_rate_limits (
    key          TEXT PRIMARY KEY,
    window_start TIMESTAMPTZ NOT NULL DEFAULT now(),
    count        INT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_auth_rate_limits_window ON auth_rate_limits (window_start);
