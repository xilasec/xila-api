-- Lossy: findings that exist on several versions collapse back to one row per
-- (project, fingerprint) — the default version's copy is kept.
DROP TRIGGER IF EXISTS findings_0version ON findings;
DROP TRIGGER IF EXISTS sboms_version ON sboms;
DROP TRIGGER IF EXISTS scans_version ON scans;
DROP FUNCTION IF EXISTS fill_version_id();
DROP INDEX IF EXISTS idx_findings_version_active;
DROP INDEX IF EXISTS idx_sboms_version;
DROP INDEX IF EXISTS idx_scans_version;
DELETE FROM findings f USING project_versions v
WHERE v.id = f.version_id AND NOT v.is_default
  AND EXISTS (SELECT 1 FROM findings o WHERE o.project_id = f.project_id
              AND o.fingerprint = f.fingerprint AND o.id <> f.id);
DROP INDEX IF EXISTS findings_version_fingerprint;
ALTER TABLE findings ADD CONSTRAINT findings_project_id_fingerprint_key UNIQUE (project_id, fingerprint);
ALTER TABLE findings DROP COLUMN IF EXISTS version_id;
ALTER TABLE sboms    DROP COLUMN IF EXISTS version_id;
ALTER TABLE scans    DROP COLUMN IF EXISTS version_id;
DROP FUNCTION IF EXISTS project_version(uuid, text, text);
DROP TABLE IF EXISTS project_versions;
