-- KEV ransomware-use flag (knownRansomwareCampaignUse "Known" in the CISA and
-- VulnCheck catalogs). Stored per catalog entry, so a catalog that fails to
-- download keeps asserting it, like the KEV ids themselves; findings carry it
-- as an enrichment-written read column (never written by the scanner upsert).
ALTER TABLE kev_catalog_entries ADD COLUMN ransomware BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE findings ADD COLUMN kev_ransomware BOOLEAN NOT NULL DEFAULT false;
