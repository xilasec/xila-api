-- PSIRT publishing (8.16): CSAF 2.0 security advisories about the instance's
-- own products, and admin feed rules applied to incoming advisories before
-- they are matched against inventory.
--
-- An advisory is a draft (editable) until published. Each publish appends a
-- revision and freezes the rendered CSAF document (`document`) — the public
-- distribution and the admin download serve that snapshot, never the live
-- draft fields, so edits after publishing stay private until republished.
-- Withdrawing appends a final revision; the document stays distributed.
CREATE TABLE psirt_advisories (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id           UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    tracking_id          TEXT NOT NULL UNIQUE,
    state                TEXT NOT NULL DEFAULT 'draft' CHECK (state IN ('draft', 'published', 'withdrawn')),
    title                TEXT NOT NULL,
    product_name         TEXT NOT NULL DEFAULT '',
    summary              TEXT NOT NULL DEFAULT '',
    details              TEXT NOT NULL DEFAULT '',
    cve                  TEXT NOT NULL DEFAULT '',
    cwe                  TEXT NOT NULL DEFAULT '',
    cwe_name             TEXT NOT NULL DEFAULT '',
    cvss_vector          TEXT NOT NULL DEFAULT '',
    -- [{version_id?, version?, range?}] — a project version, or an explicit
    -- version / vers range.
    affected             JSONB NOT NULL DEFAULT '[]',
    fixed                JSONB NOT NULL DEFAULT '[]',
    remediation          TEXT NOT NULL DEFAULT '',
    acknowledgments      JSONB NOT NULL DEFAULT '[]',
    source_advisory_id   TEXT REFERENCES private_advisories(id) ON DELETE SET NULL,
    version              INT NOT NULL DEFAULT 0,
    initial_release_at   TIMESTAMPTZ,
    current_release_at   TIMESTAMPTZ,
    document             JSON,   -- the frozen CSAF bytes, served verbatim (JSON keeps them; JSONB would not)
    created_by           UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- A draft was never published; anything published has a frozen document.
    CHECK ((state = 'draft') = (version = 0)),
    CHECK (state = 'draft' OR document IS NOT NULL)
);
CREATE INDEX idx_psirt_advisories_project ON psirt_advisories (project_id);
CREATE INDEX idx_psirt_advisories_released ON psirt_advisories (current_release_at DESC) WHERE document IS NOT NULL;

CREATE TABLE psirt_revisions (
    advisory_id UUID NOT NULL REFERENCES psirt_advisories(id) ON DELETE CASCADE,
    number      INT NOT NULL,
    date        TIMESTAMPTZ NOT NULL,
    summary     TEXT NOT NULL,
    actor_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (advisory_id, number)
);

-- Feed rules: conditions (all set ones must hold) → one action. Evaluated by
-- position, then age. mute drops the advisory for the matching package before
-- inventory matching; set_severity: the first matching rule wins; add_tags:
-- every matching rule's tags are added.
CREATE TABLE feed_rules (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name         TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT '',
    enabled      BOOLEAN NOT NULL DEFAULT true,
    position     INT NOT NULL DEFAULT 0,
    sources      TEXT[] NOT NULL DEFAULT '{}',
    id_glob      TEXT NOT NULL DEFAULT '',
    ecosystems   TEXT[] NOT NULL DEFAULT '{}',
    package_glob TEXT NOT NULL DEFAULT '',
    severities   TEXT[] NOT NULL DEFAULT '{}',
    cvss_min     DOUBLE PRECISION,
    cvss_max     DOUBLE PRECISION,
    expression   TEXT NOT NULL DEFAULT '',
    action       TEXT NOT NULL CHECK (action IN ('mute', 'set_severity', 'add_tags')),
    severity     TEXT CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    tags         TEXT[] NOT NULL DEFAULT '{}',
    created_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (action <> 'set_severity' OR severity IS NOT NULL),
    CHECK (action <> 'add_tags' OR cardinality(tags) > 0)
);
