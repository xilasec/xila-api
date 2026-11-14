DROP TABLE IF EXISTS project_members;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_owner_is_admin;
DROP INDEX IF EXISTS users_single_owner;
ALTER TABLE users DROP COLUMN IF EXISTS is_owner;
