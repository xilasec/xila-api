-- JVN iPedia mirror (8.23): Japan Vulnerability Notes advisories read from
-- JVN iPedia's RSS feeds (JVNDB ids, the CVEs they cover, CVSS). JVN names
-- products by CPE without versions, so it cannot say whether an installed
-- version is affected: the matcher uses it to enrich advisories that other
-- sources matched — their CVEs gain the JVNDB id as an alias — never to create
-- or close findings.
CREATE TABLE jvn_advisories (
    id          TEXT PRIMARY KEY,           -- JVNDB-2024-000001
    title       TEXT NOT NULL DEFAULT '',
    url         TEXT NOT NULL DEFAULT '',
    cves        TEXT[] NOT NULL DEFAULT '{}',
    cpes        TEXT[] NOT NULL DEFAULT '{}',
    cvss_score  DOUBLE PRECISION,
    cvss_vector TEXT NOT NULL DEFAULT '',
    severity    TEXT NOT NULL DEFAULT '',
    published   TIMESTAMPTZ,
    modified    TIMESTAMPTZ,
    imported_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_jvn_advisories_cves ON jvn_advisories USING GIN (cves);
