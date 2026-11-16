ALTER TABLE connectors DROP COLUMN auth_url;
ALTER TABLE connectors DROP CONSTRAINT connectors_kind_check;
ALTER TABLE connectors ADD CONSTRAINT connectors_kind_check
    CHECK (kind IN ('dependency-track', 'defectdojo'));
