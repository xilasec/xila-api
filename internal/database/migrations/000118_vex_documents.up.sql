-- Stored, versioned VEX documents (M13 13.14, SecObserve parity): an admin or
-- project editor configures a document's identity, scope and publisher once;
-- "publish" (re-)renders it from current data and appends a revision only
-- when the rendered content actually changed, so a document accumulates a
-- real history instead of a new entry on every publish click.
--
-- Scope is one of:
--   project      one project version (targets has exactly one entry)
--   versions     several versions/branches of one project (targets has 1+)
--   vulnerability  one CVE/GHSA across every project (project_id NULL; admin-only to create)
-- CycloneDX only supports scope=project (its single-BOM-subject model), enforced in Go.
CREATE TABLE vex_documents (
    id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id          TEXT NOT NULL UNIQUE, -- <prefix>-<year>-<NNNN>, e.g. XILA-2026-0001
    format               TEXT NOT NULL CHECK (format IN ('openvex', 'csaf', 'cyclonedx')),
    spec_version         TEXT NOT NULL DEFAULT '',
    scope_kind           TEXT NOT NULL CHECK (scope_kind IN ('project', 'versions', 'vulnerability')),
    project_id           UUID REFERENCES projects(id) ON DELETE CASCADE,
    -- [{version_id?, branch?}], one entry for scope=project, 1+ for scope=versions.
    targets              JSONB NOT NULL DEFAULT '[]',
    vuln_id              TEXT,
    author               TEXT NOT NULL DEFAULT '',
    publisher_name       TEXT NOT NULL DEFAULT '',
    publisher_namespace  TEXT NOT NULL DEFAULT '',
    publisher_contact    TEXT NOT NULL DEFAULT '',
    -- CycloneDX serialNumber is stable across a document's revisions (only its
    -- "version" int increments); generated once here, used when format = cyclonedx.
    serial               TEXT NOT NULL,
    -- content_hash is the baseline-rendering hash (fixed version=1, no
    -- revision history, a fixed reference timestamp) the next publish compares
    -- against. Comparing the full frozen document would always differ, because
    -- its own version number and growing revision history are part of it.
    content_hash         TEXT NOT NULL DEFAULT '',
    version              INT NOT NULL DEFAULT 0,
    published_at         TIMESTAMPTZ,
    created_by           UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (scope_kind IN ('project', 'versions') AND project_id IS NOT NULL AND vuln_id IS NULL) OR
        (scope_kind = 'vulnerability' AND project_id IS NULL AND vuln_id IS NOT NULL)
    ),
    -- A draft was never published; anything published has at least one revision.
    CHECK ((version = 0) = (published_at IS NULL))
);
CREATE INDEX idx_vex_documents_project ON vex_documents (project_id);
CREATE INDEX idx_vex_documents_vuln ON vex_documents (vuln_id) WHERE vuln_id IS NOT NULL;

-- One frozen, distributed rendering per publish that actually changed content.
CREATE TABLE vex_document_revisions (
    document_id   UUID NOT NULL REFERENCES vex_documents(id) ON DELETE CASCADE,
    number        INT NOT NULL,
    published_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    content       JSON NOT NULL, -- the frozen document bytes, served verbatim
    PRIMARY KEY (document_id, number)
);
