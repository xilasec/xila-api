ALTER TABLE connectors DROP COLUMN role_arn;
ALTER TABLE connectors DROP CONSTRAINT connectors_kind_check;
ALTER TABLE connectors ADD CONSTRAINT connectors_kind_check
    CHECK (kind IN ('dependency-track', 'defectdojo', 'snyk-api', 'github', 'gitlab', 'wiz', 'tenable'));
