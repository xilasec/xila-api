-- Manual concluded-license override (M13 13.12): a curated SPDX expression
-- for one package (optionally one version range) in one project, applied at
-- every ingest instead of the SBOM's declared license. The declared value
-- stays visible on the component row.
CREATE TABLE IF NOT EXISTS license_overrides (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id    UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    purl          TEXT NOT NULL, -- base purl, no version/qualifiers/subpath
    version_range TEXT NOT NULL DEFAULT '', -- empty = every version
    license       TEXT NOT NULL, -- the concluded SPDX expression
    comment       TEXT NOT NULL DEFAULT '',
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_license_overrides_project_purl ON license_overrides (project_id, purl);

-- The SBOM's own declared license, kept once an override replaces
-- license_expression/license_ids/license_categories/license_resolved as the
-- concluded value used by policies, filters and exports.
ALTER TABLE sbom_components
    ADD COLUMN IF NOT EXISTS license_declared_expression TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS license_declared_ids TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS license_declared_categories TEXT[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS license_declared_resolved BOOLEAN,
    ADD COLUMN IF NOT EXISTS license_override_id UUID REFERENCES license_overrides(id) ON DELETE SET NULL;
