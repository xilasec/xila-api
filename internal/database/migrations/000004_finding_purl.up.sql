-- Store the Package URL on findings so SCA findings can be correlated to the
-- exact SBOM component (by purl, or by name+version) that introduced them.
ALTER TABLE findings ADD COLUMN IF NOT EXISTS purl TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_findings_purl ON findings (purl);
