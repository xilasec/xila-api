-- SBOM history you can interrogate: which snapshot was vulnerable to what, how
-- two snapshots differ, and the dependency graph each one describes.

-- The graph. Parsers already read CycloneDX `dependencies` and SPDX relationships
-- to derive depth/scope; now the edges themselves are kept, keyed by the
-- document's own node ids (CycloneDX bom-ref, SPDX SPDXID).
ALTER TABLE sbom_components ADD COLUMN IF NOT EXISTS bom_ref TEXT NOT NULL DEFAULT '';
ALTER TABLE sboms ADD COLUMN IF NOT EXISTS root_ref TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_components_sbom_ref ON sbom_components (sbom_id, bom_ref);

CREATE TABLE IF NOT EXISTS sbom_dependencies (
    sbom_id    UUID NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
    parent_ref TEXT NOT NULL,
    child_ref  TEXT NOT NULL,
    PRIMARY KEY (sbom_id, parent_ref, child_ref)
);

-- Advisory matches per snapshot. vulnmatch re-evaluates every snapshot (not just
-- the current one) against today's advisories, so an old release still answers
-- "was this vulnerable?" after the project has upgraded and its findings closed.
-- Keyed by purl: every component in the snapshot with that purl is affected.
CREATE TABLE IF NOT EXISTS sbom_vulns (
    sbom_id       UUID NOT NULL REFERENCES sboms(id) ON DELETE CASCADE,
    purl          TEXT NOT NULL,
    vuln_id       TEXT NOT NULL,           -- advisory id (GHSA-…, CVE-…, PYSEC-…)
    cves          TEXT[] NOT NULL DEFAULT '{}',
    severity      TEXT NOT NULL DEFAULT 'info',
    summary       TEXT NOT NULL DEFAULT '',
    fixed_version TEXT NOT NULL DEFAULT '',
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(), -- when we first learned it
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(), -- last run that still matched
    PRIMARY KEY (sbom_id, purl, vuln_id)
);
-- "Which snapshots ever shipped CVE-X / GHSA-Y?"
CREATE INDEX IF NOT EXISTS idx_sbom_vulns_vuln ON sbom_vulns (vuln_id);
CREATE INDEX IF NOT EXISTS idx_sbom_vulns_cves ON sbom_vulns USING gin (cves);

-- Component → finding lookups (vulnerable-or-not on every component row) match
-- by purl, or by package name + exact version.
CREATE INDEX IF NOT EXISTS idx_findings_pkg
    ON findings (project_id, lower(package_name), package_version) WHERE package_name <> '';
CREATE INDEX IF NOT EXISTS idx_findings_purl
    ON findings (project_id, purl) WHERE purl <> '';
