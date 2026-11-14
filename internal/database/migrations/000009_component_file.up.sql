-- Where a component was found (e.g. package-lock.json, go.mod). Extracted from
-- CycloneDX evidence/occurrences or syft location properties.
ALTER TABLE sbom_components ADD COLUMN IF NOT EXISTS file_path TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_components_file_path ON sbom_components (file_path);
