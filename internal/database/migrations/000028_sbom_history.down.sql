DROP INDEX IF EXISTS idx_findings_purl;
DROP INDEX IF EXISTS idx_findings_pkg;
DROP TABLE IF EXISTS sbom_vulns;
DROP TABLE IF EXISTS sbom_dependencies;
DROP INDEX IF EXISTS idx_components_sbom_ref;
ALTER TABLE sboms DROP COLUMN IF EXISTS root_ref;
ALTER TABLE sbom_components DROP COLUMN IF EXISTS bom_ref;
