-- SSO: users authenticated via OIDC have no local password, and are linked by
-- their stable provider subject.
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
ALTER TABLE users ADD COLUMN IF NOT EXISTS oidc_subject TEXT UNIQUE;
