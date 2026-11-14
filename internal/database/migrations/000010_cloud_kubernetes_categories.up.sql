-- Allow CSPM (cloud) and KSPM (kubernetes) finding categories for Prowler,
-- Kubescape, kubeaudit and similar posture scanners.
ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_category_check;
ALTER TABLE findings ADD CONSTRAINT findings_category_check
    CHECK (category IN ('sast', 'dast', 'sca', 'secret', 'container', 'iac', 'license', 'cloud', 'kubernetes'));

ALTER TABLE scans DROP CONSTRAINT IF EXISTS scans_category_check;
ALTER TABLE scans ADD CONSTRAINT scans_category_check
    CHECK (category IN ('sast', 'dast', 'sca', 'secret', 'container', 'iac', 'license', 'cloud', 'kubernetes'));
