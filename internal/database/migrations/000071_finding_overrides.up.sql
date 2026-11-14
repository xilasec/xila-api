-- Finding page polish (8.24): a person's edit of a scanner finding's title or
-- severity sticks — the next scan's upsert keeps it and triage-rule severity
-- resets skip it — until they reset it; and a planned remediation date.
ALTER TABLE findings
    ADD COLUMN title_manual           BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN severity_manual        BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN planned_remediation_at DATE;
