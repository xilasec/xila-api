-- API tokens for non-human (CI) access. Only the SHA-256 of the token is stored;
-- the plaintext is shown once at creation. An optional project scope limits a
-- token to a single project.
CREATE TABLE IF NOT EXISTS api_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    created_by   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    project_id   UUID REFERENCES projects(id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    prefix       TEXT NOT NULL,
    token_hash   TEXT NOT NULL UNIQUE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    expires_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens (created_by);
