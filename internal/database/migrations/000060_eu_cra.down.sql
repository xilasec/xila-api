DELETE FROM frameworks WHERE key = 'eu-cra';
DELETE FROM control_mappings WHERE match_type IN ('kev', 'sla', 'sbom', 'vex');
ALTER TABLE control_mappings DROP CONSTRAINT IF EXISTS control_mappings_match_type_check;
ALTER TABLE control_mappings ADD CONSTRAINT control_mappings_match_type_check CHECK (match_type IN ('cwe', 'rule'));
ALTER TABLE controls DROP COLUMN IF EXISTS assessment;
