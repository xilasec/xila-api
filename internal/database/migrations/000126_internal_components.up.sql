-- Internal components (M13 13.11): admin-defined patterns that mark SBOM
-- components as internal (first-party), so they are never sent to public
-- registries or public advisory sources. ecosystem '' matches every
-- ecosystem; group_pattern/name_pattern are glob or regex over the
-- component's group (namespace) and name.
CREATE TABLE component_patterns (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ecosystem     TEXT NOT NULL DEFAULT '',
    group_pattern TEXT NOT NULL DEFAULT '',
    name_pattern  TEXT NOT NULL DEFAULT '',
    pattern_type  TEXT NOT NULL DEFAULT 'glob' CHECK (pattern_type IN ('glob', 'regex')),
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (group_pattern <> '' OR name_pattern <> '')
);

-- internal is computed at ingest from component_patterns and recomputed
-- whenever the patterns change (internal/component.Service.Recompute).
ALTER TABLE sbom_components ADD COLUMN IF NOT EXISTS internal BOOLEAN NOT NULL DEFAULT false;
CREATE INDEX IF NOT EXISTS idx_sbom_components_internal ON sbom_components (project_id) WHERE internal;

-- purl_ecosystem extracts a purl's type ("npm", "pypi", …), lower-cased; ''
-- when purl isn't one. Used to recompute sbom_components.internal by
-- (ecosystem, group, name) without reparsing every row's full purl in Go.
CREATE OR REPLACE FUNCTION purl_ecosystem(purl TEXT) RETURNS TEXT AS $$
    SELECT CASE WHEN purl LIKE 'pkg:%' THEN lower(split_part(substring(purl FROM 5), '/', 1)) ELSE '' END;
$$ LANGUAGE sql IMMUTABLE;

-- Private, authenticated package registries (Dependency-Track parity): an
-- admin-managed, ordered list per ecosystem, tried before the env/default
-- public registry. internal marks a registry allowed to see internal
-- component names (see internal/pkgmeta): resolution for an internal
-- component only ever reaches a registry with internal = true, never the
-- env/default public one.
CREATE TABLE pkgmeta_registries (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ecosystem     TEXT NOT NULL,
    url           TEXT NOT NULL,
    auth_type     TEXT NOT NULL DEFAULT 'none' CHECK (auth_type IN ('none', 'basic', 'bearer')),
    username      TEXT NOT NULL DEFAULT '',
    password_enc  BYTEA,
    token_enc     BYTEA,
    internal      BOOLEAN NOT NULL DEFAULT false,
    sort_order    INT NOT NULL DEFAULT 0,
    created_by    UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (auth_type <> 'basic' OR username <> '')
);
CREATE INDEX idx_pkgmeta_registries_ecosystem ON pkgmeta_registries (ecosystem, sort_order);
