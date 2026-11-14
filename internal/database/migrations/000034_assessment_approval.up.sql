-- Four-eyes for manual assessments (ASSESSMENT_REQUIRES_APPROVAL): an analyst's
-- status / severity change on a finding is recorded here as `pending` and only
-- takes effect when a different, sufficiently privileged user approves it.

CREATE TABLE IF NOT EXISTS finding_assessments (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_id     UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    project_id     UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    requested_by   UUID REFERENCES users(id) ON DELETE SET NULL,
    requester      TEXT NOT NULL DEFAULT '',   -- email at the time, kept if the user goes
    status         TEXT CHECK (status IN ('open', 'confirmed', 'false_positive', 'risk_accepted', 'remediated', 'wont_fix')),
    severity       TEXT CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    reason         TEXT NOT NULL DEFAULT '',
    expires_at     TIMESTAMPTZ,
    state          TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'approved', 'rejected')),
    decided_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    decider        TEXT NOT NULL DEFAULT '',
    decided_at     TIMESTAMPTZ,
    decision_note  TEXT NOT NULL DEFAULT '',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (status IS NOT NULL OR severity IS NOT NULL)
);
-- At most one open request per finding: a second one must wait for the first.
CREATE UNIQUE INDEX IF NOT EXISTS uq_finding_assessments_pending
    ON finding_assessments (finding_id) WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS idx_finding_assessments_finding ON finding_assessments (finding_id, created_at);
CREATE INDEX IF NOT EXISTS idx_finding_assessments_queue ON finding_assessments (state, created_at);

-- Requests and their approval / rejection appear in the finding's history.
ALTER TABLE finding_events DROP CONSTRAINT IF EXISTS finding_events_kind_check;
ALTER TABLE finding_events ADD CONSTRAINT finding_events_kind_check
    CHECK (kind IN ('created', 'status', 'severity', 'assignee', 'comment', 'attachment', 'assessment'));
