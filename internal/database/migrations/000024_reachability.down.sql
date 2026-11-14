ALTER TABLE triage_rules DROP CONSTRAINT IF EXISTS triage_rules_dep_scope_check;
ALTER TABLE triage_rules DROP COLUMN IF EXISTS dep_transitive, DROP COLUMN IF EXISTS dep_scope;
DROP INDEX IF EXISTS idx_findings_reachable;
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_dep_scope_check;
ALTER TABLE findings DROP COLUMN IF EXISTS dep_scope, DROP COLUMN IF EXISTS dep_depth, DROP COLUMN IF EXISTS dep_direct;
ALTER TABLE sbom_components DROP CONSTRAINT IF EXISTS sbom_components_scope_check;
ALTER TABLE sbom_components DROP COLUMN IF EXISTS scope, DROP COLUMN IF EXISTS depth, DROP COLUMN IF EXISTS direct;
