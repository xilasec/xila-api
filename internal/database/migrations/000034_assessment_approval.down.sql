DROP TABLE IF EXISTS finding_assessments;

DELETE FROM finding_events WHERE kind = 'assessment';
ALTER TABLE finding_events DROP CONSTRAINT IF EXISTS finding_events_kind_check;
ALTER TABLE finding_events ADD CONSTRAINT finding_events_kind_check
    CHECK (kind IN ('created', 'status', 'severity', 'assignee', 'comment', 'attachment'));
