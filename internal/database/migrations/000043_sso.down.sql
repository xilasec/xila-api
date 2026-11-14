DROP TABLE IF EXISTS saml_seen_assertions;
DROP TABLE IF EXISTS saml_sp_keys;
DROP TABLE IF EXISTS sso_group_mappings;

ALTER TABLE project_members DROP COLUMN IF EXISTS source;
ALTER TABLE team_members DROP COLUMN IF EXISTS source;
ALTER TABLE org_members DROP COLUMN IF EXISTS source;
ALTER TABLE users DROP COLUMN IF EXISTS admin_source;

-- Restore the single-provider OIDC link (one subject per user; the first wins).
ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_subject TEXT UNIQUE;
UPDATE users u SET oidc_subject = i.subject
FROM (SELECT DISTINCT ON (user_id) user_id, subject FROM user_identities
      WHERE provider = 'oidc' ORDER BY user_id, created_at) i
WHERE u.id = i.user_id;
DROP TABLE IF EXISTS user_identities;
