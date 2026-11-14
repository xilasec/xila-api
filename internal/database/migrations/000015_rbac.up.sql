-- RBAC: a global admin flag + per-team membership with roles.
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT false;

CREATE TABLE IF NOT EXISTS team_members (
    team_id    UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('owner', 'editor', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (team_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_team_members_user ON team_members (user_id);

-- Continuity for existing installs: make the oldest user an admin, and give
-- that admin ownership of every existing team so nothing becomes orphaned.
UPDATE users SET is_admin = true
WHERE id = (SELECT id FROM users ORDER BY created_at LIMIT 1)
  AND NOT EXISTS (SELECT 1 FROM users WHERE is_admin);

INSERT INTO team_members (team_id, user_id, role)
SELECT t.id, (SELECT id FROM users WHERE is_admin ORDER BY created_at LIMIT 1), 'owner'
FROM teams t
WHERE EXISTS (SELECT 1 FROM users WHERE is_admin)
ON CONFLICT DO NOTHING;
