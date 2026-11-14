-- Vulnerability sources (M5.4).
--
-- osv_advisories: a local mirror of OSV.dev ecosystem exports
-- (<Ecosystem>/all.zip), so an air-gapped install can still match its SBOM
-- inventory. One row per advisory; `packages` holds the match keys
-- ("<Ecosystem>|<normalized name>") of every affected package so a component
-- lookup is one GIN probe, and `affected` keeps OSV's full affected[] verbatim
-- for range evaluation. Import is idempotent by (id, modified).
CREATE TABLE osv_advisories (
    id          TEXT PRIMARY KEY,
    modified    TIMESTAMPTZ NOT NULL,
    published   TIMESTAMPTZ,
    withdrawn   TIMESTAMPTZ,
    ecosystems  TEXT[] NOT NULL DEFAULT '{}',
    packages    TEXT[] NOT NULL DEFAULT '{}',
    aliases     TEXT[] NOT NULL DEFAULT '{}',
    summary     TEXT NOT NULL DEFAULT '',
    details     TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT '',
    cvss_vector TEXT NOT NULL DEFAULT '',
    affected    JSONB NOT NULL DEFAULT '[]',
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX osv_advisories_packages_idx ON osv_advisories USING GIN (packages);

-- private_advisories: internal advisories against internal packages, in OSV's
-- shape (affected[] with ranges/versions), evaluated by the same range code as
-- the local OSV mirror. Withdrawn advisories stay for the record but no longer
-- match (their findings auto-close on the next match).
CREATE TABLE private_advisories (
    id          TEXT PRIMARY KEY,
    summary     TEXT NOT NULL,
    details     TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    cvss_vector TEXT NOT NULL DEFAULT '',
    aliases     TEXT[] NOT NULL DEFAULT '{}',
    affected    JSONB NOT NULL DEFAULT '[]',
    packages    TEXT[] NOT NULL DEFAULT '{}',
    published   TIMESTAMPTZ NOT NULL DEFAULT now(),
    withdrawn   TIMESTAMPTZ,
    created_by  UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX private_advisories_packages_idx ON private_advisories USING GIN (packages);

-- nvd_cves caches NVD API 2.0 CVSS data per CVE, so the slow, rate-limited API
-- is asked once per CVE (and again only after the refresh window), and every
-- ingest can stamp new findings from the cache. cvss_score NULL = NVD has the
-- CVE but no v3.x/v4.0 metric yet (or doesn't know it).
CREATE TABLE nvd_cves (
    cve_id        TEXT PRIMARY KEY,
    cvss_score    REAL,
    cvss_vector   TEXT,
    cvss_version  TEXT,
    last_modified TIMESTAMPTZ,
    fetched_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- NVD CVSS on findings (plain read columns: never written by the scanner
-- upsert). cvss_source = 'nvd' marks a `cvss` score filled from NVD because the
-- scanner gave none; NULL means the score (if any) is the scanner's own, which
-- always wins.
ALTER TABLE findings
    ADD COLUMN cvss_vector  TEXT,
    ADD COLUMN cvss_version TEXT,
    ADD COLUMN cvss_source  TEXT CHECK (cvss_source IN ('nvd'));
