-- Per-upload background-processing status (M13 13.3): an SBOM upload returns
-- after parsing and storing, while OSV matching, package-metadata lookup and
-- policy evaluation run afterwards (some inline, some in the background), so
-- a gate run right after upload could see stale state. One row per SBOM
-- tracks which of its enabled post-ingest steps (vulnmatch match, pkgmeta
-- fetch, policy evaluation, reachability rescoring) have finished; a
-- disabled feature's step is simply never added, so it can't block
-- "completed". See internal/sbom/processing.go.
CREATE TABLE IF NOT EXISTS sbom_processing (
    sbom_id      UUID PRIMARY KEY REFERENCES sboms(id) ON DELETE CASCADE,
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    steps        JSONB NOT NULL DEFAULT '{}',
    error        TEXT,
    started_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at TIMESTAMPTZ
);
