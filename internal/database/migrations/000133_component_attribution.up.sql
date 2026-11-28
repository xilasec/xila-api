-- Attribution facts a component's SBOM states: its copyright notice and its
-- homepage (CycloneDX copyright / website reference, SPDX copyrightText /
-- homepage, ScanCode.io copyright / homepage_url). '' = the document didn't say.
ALTER TABLE sbom_components
    ADD COLUMN copyright TEXT NOT NULL DEFAULT '',
    ADD COLUMN homepage  TEXT NOT NULL DEFAULT '';
