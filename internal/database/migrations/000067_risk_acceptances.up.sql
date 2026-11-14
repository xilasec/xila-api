-- Risk acceptances as first-class objects. One acceptance covers many findings
-- of a project, with a title, a justification, an owner, an expiry and a
-- requested → approved → expired / revoked / rejected lifecycle. A finding is
-- risk_accepted only while an approved acceptance covers it; until approval
-- it stays open and counted.
--
-- This replaces the per-finding exception fields for risk acceptance. The
-- fields stay for false_positive / wont_fix, which still carry their own
-- reason and optional expiry.
CREATE TABLE IF NOT EXISTS risk_acceptances (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id       UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    title            TEXT NOT NULL,
    justification    TEXT NOT NULL DEFAULT '',
    owner_id         UUID REFERENCES users(id) ON DELETE SET NULL,
    expires_at       TIMESTAMPTZ,
    state            TEXT NOT NULL DEFAULT 'requested'
                     CHECK (state IN ('requested', 'approved', 'expired', 'revoked', 'rejected')),
    -- source_key identifies an acceptance the platform keeps for a recurring
    -- source (a triage rule, an import): new matches join the live one.
    -- NULL for acceptances people request.
    source_key       TEXT,
    requested_by     UUID REFERENCES users(id) ON DELETE SET NULL,
    requester        TEXT NOT NULL DEFAULT '',   -- email at the time, or the system actor
    requested_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_by      UUID REFERENCES users(id) ON DELETE SET NULL,
    approver         TEXT NOT NULL DEFAULT '',
    approved_at      TIMESTAMPTZ,
    approval_note    TEXT NOT NULL DEFAULT '',
    -- Who ended it (rejected / revoked; 'system' for expired), when and why.
    closed_by        UUID REFERENCES users(id) ON DELETE SET NULL,
    closer           TEXT NOT NULL DEFAULT '',
    closed_at        TIMESTAMPTZ,
    close_note       TEXT NOT NULL DEFAULT '',
    -- The expiry an "expiring soon" alert was already sent for.
    expiry_warned_at TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_risk_acceptances_project ON risk_acceptances (project_id, state, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_risk_acceptances_queue ON risk_acceptances (state, created_at);
CREATE INDEX IF NOT EXISTS idx_risk_acceptances_expiry
    ON risk_acceptances (expires_at) WHERE state IN ('requested', 'approved') AND expires_at IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_risk_acceptances_source
    ON risk_acceptances (project_id, source_key)
    WHERE source_key IS NOT NULL AND state IN ('requested', 'approved');

-- The membership ledger: every time a finding joined or left an acceptance.
-- A row is live while removed_at IS NULL; leaving (removed by hand, the
-- finding's status changed, the acceptance expired / was revoked / rejected)
-- stamps it instead of deleting it, so the history survives.
CREATE TABLE IF NOT EXISTS risk_acceptance_findings (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    acceptance_id  UUID NOT NULL REFERENCES risk_acceptances(id) ON DELETE CASCADE,
    finding_id     UUID NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    added_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    added_by       TEXT NOT NULL DEFAULT '',
    removed_at     TIMESTAMPTZ,
    removed_by     TEXT NOT NULL DEFAULT '',
    reason         TEXT NOT NULL DEFAULT ''     -- why it left
);
-- A finding is in at most one live acceptance.
CREATE UNIQUE INDEX IF NOT EXISTS uq_risk_acceptance_findings_live
    ON risk_acceptance_findings (finding_id) WHERE removed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_risk_acceptance_findings_acceptance
    ON risk_acceptance_findings (acceptance_id, added_at);
CREATE INDEX IF NOT EXISTS idx_risk_acceptance_findings_finding
    ON risk_acceptance_findings (finding_id, added_at DESC);

-- Conversion 1: every risk_accepted finding becomes a member of an approved
-- acceptance, one per (project, reason, expiry, accepted by). The person who
-- accepted it (exception_by: a user id, or a system actor such as a triage
-- rule or an importing scanner) is recorded as requester, approver and owner.
CREATE TEMP TABLE ra_groups AS
SELECT gen_random_uuid() AS id, g.*,
       u.id AS user_id, COALESCE(u.email, g.exception_by) AS actor
FROM (
    SELECT project_id, exception_reason, exception_expires_at, exception_by,
           min(COALESCE(resolved_at, updated_at)) AS since
    FROM findings
    WHERE status = 'risk_accepted'
    GROUP BY project_id, exception_reason, exception_expires_at, exception_by
) g
LEFT JOIN users u ON u.id::text = g.exception_by;

INSERT INTO risk_acceptances (id, project_id, title, justification, owner_id, expires_at, state,
                              requested_by, requester, requested_at,
                              approved_by, approver, approved_at, approval_note, created_at, updated_at)
SELECT id, project_id,
       CASE WHEN btrim(exception_reason) = '' THEN 'Risk acceptance'
            ELSE left(split_part(btrim(exception_reason), E'\n', 1), 120) END,
       exception_reason, user_id, exception_expires_at, 'approved',
       user_id, actor, since,
       user_id, actor, since, 'converted from per-finding risk acceptance', since, now()
FROM ra_groups;

INSERT INTO risk_acceptance_findings (acceptance_id, finding_id, added_at, added_by)
SELECT g.id, f.id, COALESCE(f.resolved_at, f.updated_at), g.actor
FROM findings f
JOIN ra_groups g ON g.project_id = f.project_id
                AND g.exception_reason = f.exception_reason
                AND g.exception_expires_at IS NOT DISTINCT FROM f.exception_expires_at
                AND g.exception_by = f.exception_by
WHERE f.status = 'risk_accepted';

DROP TABLE ra_groups;

-- The acceptance now holds the reason / expiry; the finding's exception
-- fields describe false_positive / wont_fix only.
UPDATE findings
SET exception_reason = '', exception_by = '', exception_expires_at = NULL
WHERE status = 'risk_accepted'
  AND (exception_reason <> '' OR exception_by <> '' OR exception_expires_at IS NOT NULL);

-- Conversion 2: pending manual assessments asking for risk_accepted become
-- requested acceptances (one per project, reason, expiry and requester). An
-- assessment that also changed severity keeps that part pending; one that was
-- only the acceptance is closed, pointing at its successor.
CREATE TEMP TABLE ra_requests AS
SELECT gen_random_uuid() AS id, g.*
FROM (
    SELECT a.project_id, a.reason, a.expires_at, a.requested_by, a.requester, min(a.created_at) AS since
    FROM finding_assessments a
    WHERE a.state = 'pending' AND a.status = 'risk_accepted'
      AND NOT EXISTS (SELECT 1 FROM risk_acceptance_findings m
                      WHERE m.finding_id = a.finding_id AND m.removed_at IS NULL)
    GROUP BY a.project_id, a.reason, a.expires_at, a.requested_by, a.requester
) g;

INSERT INTO risk_acceptances (id, project_id, title, justification, owner_id, expires_at, state,
                              requested_by, requester, requested_at, created_at, updated_at)
SELECT id, project_id,
       CASE WHEN btrim(reason) = '' THEN 'Risk acceptance'
            ELSE left(split_part(btrim(reason), E'\n', 1), 120) END,
       reason, requested_by, expires_at, 'requested', requested_by, requester, since, since, now()
FROM ra_requests;

INSERT INTO risk_acceptance_findings (acceptance_id, finding_id, added_at, added_by)
SELECT r.id, a.finding_id, a.created_at, a.requester
FROM finding_assessments a
JOIN ra_requests r ON r.project_id = a.project_id
                  AND r.reason = a.reason
                  AND r.expires_at IS NOT DISTINCT FROM a.expires_at
                  AND r.requested_by IS NOT DISTINCT FROM a.requested_by
                  AND r.requester = a.requester
WHERE a.state = 'pending' AND a.status = 'risk_accepted'
  AND NOT EXISTS (SELECT 1 FROM risk_acceptance_findings m
                  WHERE m.finding_id = a.finding_id AND m.removed_at IS NULL);

DROP TABLE ra_requests;

UPDATE finding_assessments SET status = NULL
WHERE state = 'pending' AND status = 'risk_accepted' AND severity IS NOT NULL;
UPDATE finding_assessments
SET state = 'rejected', decider = 'system', decided_at = now(),
    decision_note = 'moved to a risk acceptance request'
WHERE state = 'pending' AND status = 'risk_accepted';

-- Notification subscriptions follow the events: a risk acceptance is announced
-- when approved; channels that heard about lapsed exceptions also hear about
-- lapsed acceptances.
UPDATE notification_channels
SET events = array_replace(events, 'finding.risk_accepted', 'risk_acceptance.approved')
WHERE 'finding.risk_accepted' = ANY (events);
UPDATE notification_channels
SET events = events || '{risk_acceptance.expired}'::text[]
WHERE 'exception.expired' = ANY (events) AND NOT 'risk_acceptance.expired' = ANY (events);
