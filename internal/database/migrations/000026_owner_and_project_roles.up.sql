-- Two gaps in the authorization model.
--
-- 1. Every instance admin could demote every other instance admin, including
--    whoever set the instance up. That's not an admin hierarchy, it's a mutual
--    suicide pact: one compromised or careless admin account can lock everyone
--    else out. So exactly one user is the **owner** — always an admin, and no one
--    can take that away. Ownership can only be handed over by the owner.
ALTER TABLE users ADD COLUMN IF NOT EXISTS is_owner boolean NOT NULL DEFAULT false;

-- The founding user (first registered) becomes the owner on existing installs.
UPDATE users SET is_owner = true, is_admin = true
WHERE id = (SELECT id FROM users ORDER BY created_at, id LIMIT 1)
  AND NOT EXISTS (SELECT 1 FROM users WHERE is_owner);

-- At most one owner, enforced by the database rather than by remembering to check.
CREATE UNIQUE INDEX IF NOT EXISTS users_single_owner ON users (is_owner) WHERE is_owner;

-- The owner is an admin by construction. This makes "there is always at least one
-- admin" a schema invariant instead of a handler's good intentions.
ALTER TABLE users ADD CONSTRAINT users_owner_is_admin CHECK (NOT is_owner OR is_admin);

-- 2. Access was only grantable a whole team at a time. "Give Dana read access to
--    this one project" had no expression — you had to add her to the team and hand
--    her every project in it. Project roles close that.
--
-- A user's effective role on a project is the *highest* of: their direct project
-- role, their role on the owning team, and owner if they administer the owning
-- org. Roles only ever add access, never subtract it — a team editor cannot be
-- downgraded to viewer on one project, because a permission model where access is
-- granted in one place and revoked in another is a model nobody can reason about.
CREATE TABLE IF NOT EXISTS project_members (
    project_id uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (project_id, user_id),
    CONSTRAINT project_members_role_check CHECK (role IN ('owner', 'editor', 'viewer'))
);

CREATE INDEX IF NOT EXISTS idx_project_members_user ON project_members (user_id);
