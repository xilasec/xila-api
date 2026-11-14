-- More KEV catalogs (M8.4): CISA, ENISA's EU Vulnerability Database
-- exploited list and VulnCheck KEV beside each other.
--
-- kev_catalog_entries holds each catalog's last successful download as the
-- vulnerability ids it asserts (a catalog entry contributes every id it names:
-- CVE, GHSA, EUVD), so a catalog that fails to download keeps asserting what
-- it last listed instead of silently clearing findings' KEV flags.
CREATE TABLE kev_catalog_entries (
    source  TEXT NOT NULL,
    vuln_id TEXT NOT NULL,
    PRIMARY KEY (source, vuln_id)
);

-- kev_catalogs is each catalog's sync state.
CREATE TABLE kev_catalogs (
    source     TEXT PRIMARY KEY,
    entries    INT NOT NULL DEFAULT 0,
    synced_at  TIMESTAMPTZ,
    last_error TEXT NOT NULL DEFAULT '',
    failed_at  TIMESTAMPTZ
);

-- Which catalogs assert a finding is known-exploited (sorted names); `kev`
-- stays the "any catalog" flag every existing filter and count reads. A plain
-- read column: written by enrichment, never by the scanner upsert. Every KEV
-- flag so far came from CISA.
ALTER TABLE findings ADD COLUMN kev_sources TEXT[] NOT NULL DEFAULT '{}';
UPDATE findings SET kev_sources = '{cisa}' WHERE kev;

-- A gate's block_kev can be limited to some catalogs ('{}' = any).
ALTER TABLE gate_policies ADD COLUMN kev_sources TEXT[] NOT NULL DEFAULT '{}';
