-- VEX (Vulnerability Exploitability eXchange): the vendor's or your own team's
-- analysis of whether a vulnerability actually affects a product. It is the one
-- authoritative answer to "is this CVE real for us" — a scanner can only say the
-- package is present, not whether the vulnerable path exists in your build.
--
-- Statements persist and are re-applied on every ingest, so a CVE you already
-- analysed as not-affected never comes back to the triage queue when the next
-- scan reports it again.
CREATE TABLE IF NOT EXISTS vex_statements (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id  uuid NOT NULL REFERENCES projects (id) ON DELETE CASCADE,
    vuln_id     text NOT NULL,             -- CVE-…, GHSA-…: whatever the advisory calls itself
    product     text NOT NULL DEFAULT '',  -- PURL or package name; '' = every product in the project
    status      text NOT NULL,
    justification text NOT NULL DEFAULT '',-- why (component_not_present, vulnerable_code_not_in_execute_path, …)
    detail      text NOT NULL DEFAULT '',
    source      text NOT NULL DEFAULT '',  -- the document it came from (openvex / cyclonedx)
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT vex_statements_status_check
        CHECK (status IN ('not_affected', 'affected', 'fixed', 'under_investigation'))
);

-- One statement per (project, vulnerability, product): re-uploading a VEX
-- document updates the analysis rather than accumulating stale copies of it.
CREATE UNIQUE INDEX IF NOT EXISTS vex_statements_unique
    ON vex_statements (project_id, vuln_id, product);

CREATE INDEX IF NOT EXISTS idx_vex_statements_project ON vex_statements (project_id);
