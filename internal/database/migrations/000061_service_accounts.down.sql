DROP TABLE IF EXISTS federation_bindings;
DROP TABLE IF EXISTS federation_issuers;
DELETE FROM users WHERE kind = 'service';
DROP TABLE IF EXISTS service_accounts;
ALTER TABLE users DROP CONSTRAINT IF EXISTS users_service_unprivileged;
ALTER TABLE users DROP COLUMN IF EXISTS kind;
