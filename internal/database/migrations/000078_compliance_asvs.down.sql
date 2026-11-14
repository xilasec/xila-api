DELETE FROM frameworks WHERE key = 'owasp-asvs-5.0';
DROP TABLE IF EXISTS control_attestations;
DELETE FROM control_mappings WHERE match_type IN ('category', 'severity');
ALTER TABLE control_mappings DROP CONSTRAINT IF EXISTS control_mappings_match_type_check;
ALTER TABLE control_mappings ADD CONSTRAINT control_mappings_match_type_check
    CHECK (match_type IN ('cwe', 'rule', 'kev', 'sla', 'sbom', 'vex'));
ALTER TABLE control_mappings DROP COLUMN IF EXISTS category, DROP COLUMN IF EXISTS severity;
