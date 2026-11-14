-- Archive instead of delete (internal/archive): projects, engagements, scans and
-- findings carry who archived them and when. An archived record drops out of
-- every list, count, dedup election, gate and sweep (the archive.* SQL
-- fragments), stays restorable within ARCHIVE_RETENTION, and is then purged by
-- the retention job. A project's findings are archived *through* the project
-- (the fragment joins it), never by writing their rows.
ALTER TABLE projects
    ADD COLUMN archived_at timestamptz,
    ADD COLUMN archived_by uuid REFERENCES users (id) ON DELETE SET NULL;
ALTER TABLE engagements
    ADD COLUMN archived_at timestamptz,
    ADD COLUMN archived_by uuid REFERENCES users (id) ON DELETE SET NULL;
ALTER TABLE scans
    ADD COLUMN archived_at timestamptz,
    ADD COLUMN archived_by uuid REFERENCES users (id) ON DELETE SET NULL;
ALTER TABLE findings
    ADD COLUMN archived_at timestamptz,
    ADD COLUMN archived_by uuid REFERENCES users (id) ON DELETE SET NULL;

-- Few rows are archived at any time: partial indexes keep the "is it archived"
-- subqueries and the purge sweep cheap.
CREATE INDEX projects_archived_idx ON projects (archived_at) WHERE archived_at IS NOT NULL;
CREATE INDEX engagements_archived_idx ON engagements (archived_at) WHERE archived_at IS NOT NULL;
CREATE INDEX scans_archived_idx ON scans (archived_at) WHERE archived_at IS NOT NULL;
CREATE INDEX findings_archived_idx ON findings (archived_at) WHERE archived_at IS NOT NULL;
