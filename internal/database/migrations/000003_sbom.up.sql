-- An SBOM is an immutable snapshot uploaded for a project artifact. Keeping every
-- upload (rather than replacing inventory) is what gives us historical tracking.
CREATE TABLE IF NOT EXISTS sboms (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    artifact        TEXT NOT NULL DEFAULT '',
    version         TEXT NOT NULL DEFAULT '',
    format          TEXT NOT NULL DEFAULT 'CycloneDX',
    spec_version    TEXT NOT NULL DEFAULT '',
    serial_number   TEXT NOT NULL DEFAULT '',
    component_count INTEGER NOT NULL DEFAULT 0,
    source          TEXT NOT NULL DEFAULT 'upload',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sboms_project ON sboms (project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sboms_project_artifact ON sboms (project_id, artifact, created_at DESC);

-- Components belong to a single snapshot. project_id is denormalized so the
-- "which projects contain package X" search never needs a join to filter.
CREATE TABLE IF NOT EXISTS sbom_components (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id     UUID NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    type        TEXT NOT NULL DEFAULT 'library',
    "group"     TEXT NOT NULL DEFAULT '',
    name        TEXT NOT NULL,
    version     TEXT NOT NULL DEFAULT '',
    purl        TEXT NOT NULL DEFAULT '',
    cpe         TEXT NOT NULL DEFAULT '',
    license     TEXT NOT NULL DEFAULT '',
    hashes      JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_components_sbom ON sbom_components (sbom_id);
CREATE INDEX IF NOT EXISTS idx_components_project ON sbom_components (project_id);
CREATE INDEX IF NOT EXISTS idx_components_name ON sbom_components (name);
CREATE INDEX IF NOT EXISTS idx_components_purl ON sbom_components (purl);
