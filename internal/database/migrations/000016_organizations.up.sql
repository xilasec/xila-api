-- Organization: the top-level tenant above teams. Teams belong to exactly one
-- org; users join orgs with an org-level role (admin manages the org + all its
-- teams; member's access still comes from team membership).
CREATE TABLE IF NOT EXISTS organizations (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug       TEXT NOT NULL UNIQUE,
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS org_members (
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON org_members (user_id);

ALTER TABLE teams ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id) ON DELETE CASCADE;

-- Backfill: a Default org owns every existing team. Instance admins become org
-- admins; all other existing users become org members, so nothing loses access.
INSERT INTO organizations (slug, name) VALUES ('default', 'Default Organization')
ON CONFLICT (slug) DO NOTHING;

UPDATE teams SET org_id = (SELECT id FROM organizations WHERE slug = 'default')
WHERE org_id IS NULL;

ALTER TABLE teams ALTER COLUMN org_id SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_teams_org ON teams (org_id);

INSERT INTO org_members (org_id, user_id, role)
SELECT (SELECT id FROM organizations WHERE slug = 'default'), u.id,
       CASE WHEN u.is_admin THEN 'admin' ELSE 'member' END
FROM users u
ON CONFLICT DO NOTHING;
