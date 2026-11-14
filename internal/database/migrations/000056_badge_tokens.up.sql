-- README badges: one unguessable token per project lets anyone holding it
-- fetch the project's badge SVGs without signing in. Only its SHA-256 is
-- stored (like API tokens); rotating replaces it, deleting revokes it.
CREATE TABLE project_badge_tokens (
    project_id uuid PRIMARY KEY REFERENCES projects (id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
