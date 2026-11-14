-- Revert to the original category set (assumes no cloud/kubernetes rows remain).
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_category_check;
ALTER TABLE findings ADD CONSTRAINT findings_category_check
    CHECK (category IN ('sast', 'dast', 'sca', 'secret', 'container', 'iac', 'license'));

ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_category_check;
ALTER TABLE scans ADD CONSTRAINT scans_category_check
    CHECK (category IN ('sast', 'dast', 'sca', 'secret', 'container', 'iac', 'license'));
