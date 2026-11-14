-- An asset is the concrete thing being secured: a repo, a container image, a
-- cloud resource, a host. It generalizes "project = repo" so findings can be
-- attributed to exactly what they affect (the keystone for container/cloud/CSPM).
CREATE TABLE IF NOT EXISTS assets (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    type        TEXT NOT NULL
        CHECK (type IN ('repository', 'container_image', 'cloud_resource', 'host', 'kubernetes', 'serverless')),
    name        TEXT NOT NULL,
    identifier  TEXT NOT NULL DEFAULT '',
    metadata    JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- An asset is unique per project by its type + external identifier.
    UNIQUE (project_id, type, identifier)
);

CREATE INDEX IF NOT EXISTS idx_assets_project ON assets (project_id);
CREATE INDEX IF NOT EXISTS idx_assets_type ON assets (type);

-- Findings and scans may target a specific asset (nullable: project-level by default).
ALTER TABLE findings ADD COLUMN IF NOT EXISTS asset_id UUID REFERENCES assets(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_findings_asset ON findings (asset_id);

ALTER TABLE scans ADD COLUMN IF NOT EXISTS asset_id UUID REFERENCES assets(id) ON DELETE SET NULL;
