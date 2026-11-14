-- Services a CycloneDX BOM declares (`services`, spec 1.2+): the APIs, queues
-- and data stores the software talks to, with their endpoints, authentication,
-- trust boundary / zone and the data classifications flowing through them. Kept
-- per snapshot like sbom_components; nested services are flattened with their
-- parent's bom-ref. Service dependency edges live in sbom_dependencies, keyed
-- by the same bom-refs as components.
CREATE TABLE IF NOT EXISTS sbom_services (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sbom_id        UUID NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
    project_id     UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    position       INT NOT NULL DEFAULT 0,          -- document order (pre-order over nesting)
    bom_ref        TEXT NOT NULL DEFAULT '',
    parent_ref     TEXT NOT NULL DEFAULT '',        -- '' = top-level service
    "group"        TEXT NOT NULL DEFAULT '',
    name           TEXT NOT NULL,
    version        TEXT NOT NULL DEFAULT '',
    description    TEXT NOT NULL DEFAULT '',
    provider       TEXT NOT NULL DEFAULT '',        -- provider organization name
    provider_urls  TEXT[] NOT NULL DEFAULT '{}',
    endpoints      TEXT[] NOT NULL DEFAULT '{}',
    authenticated  BOOLEAN,                         -- NULL: the document doesn't say
    trust_boundary BOOLEAN,                         -- x-trust-boundary; NULL: not stated
    trust_zone     TEXT NOT NULL DEFAULT '',        -- trustZone (1.5+)
    license        TEXT NOT NULL DEFAULT '',
    data           JSONB NOT NULL DEFAULT '[]',     -- data flows: flow, classification, name, description, governance, source, destination
    external_refs  JSONB NOT NULL DEFAULT '[]',
    properties     JSONB NOT NULL DEFAULT '[]',     -- [{name, value}] in document order
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_sbom_services_sbom ON sbom_services (sbom_id, position);
CREATE INDEX IF NOT EXISTS idx_sbom_services_project ON sbom_services (project_id);
