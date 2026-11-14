ALTER TABLE findings
    DROP COLUMN IF EXISTS cvss_source,
    DROP COLUMN IF EXISTS cvss_version,
    DROP COLUMN IF EXISTS cvss_vector;
DROP TABLE IF EXISTS nvd_cves;
DROP TABLE IF EXISTS private_advisories;
DROP TABLE IF EXISTS osv_advisories;
