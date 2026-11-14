-- Repository metadata for SBOM packages (M5.1 outdated components).
--
-- package_meta caches what each ecosystem's registry says about one package,
-- keyed by its base purl (type/namespace/name — no version, qualifiers or
-- subpath). A row exists once a fetch was attempted; fetched_at is set only by
-- a successful fetch, so a package the registry doesn't know (a private one)
-- has a row with an error and no data — never "up to date".
CREATE TABLE IF NOT EXISTS package_meta (
    base_purl           TEXT PRIMARY KEY,
    ecosystem           TEXT NOT NULL,
    latest_version      TEXT NOT NULL DEFAULT '',  -- newest stable, non-yanked release
    latest_published_at TIMESTAMPTZ,
    -- every release: [{"version", "published_at"?, "yanked"?}]
    versions            JSONB NOT NULL DEFAULT '[]'::jsonb,
    fetched_at          TIMESTAMPTZ,               -- last successful fetch
    next_fetch_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error          TEXT NOT NULL DEFAULT '',
    error_count         INT NOT NULL DEFAULT 0,    -- consecutive failures (backoff)
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_package_meta_next_fetch ON package_meta (next_fetch_at);

-- package_status is the freshness of each component purl seen in an SBOM,
-- computed on write from package_meta (version ordering is per-ecosystem Go
-- code, not SQL). Keyed by the exact component purl so component queries join
-- it directly (ps.purl = c.purl); base_purl + version make it joinable by
-- package version too. A purl without a row is unknown.
CREATE TABLE IF NOT EXISTS package_status (
    purl                TEXT PRIMARY KEY,
    base_purl           TEXT NOT NULL REFERENCES package_meta (base_purl) ON DELETE CASCADE,
    version             TEXT NOT NULL,
    latest_version      TEXT NOT NULL,
    outdated            BOOLEAN NOT NULL,
    versions_behind     INT NOT NULL,
    published_at        TIMESTAMPTZ,
    latest_published_at TIMESTAMPTZ,
    computed_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_package_status_base_version ON package_status (base_purl, version);
CREATE INDEX IF NOT EXISTS idx_package_status_outdated ON package_status (outdated);
