-- Put the live approved acceptances back on their findings' exception fields.
UPDATE findings f
SET exception_reason = ra.justification,
    exception_by = COALESCE(ra.approved_by::text, ra.approver),
    exception_expires_at = ra.expires_at
FROM risk_acceptance_findings m
JOIN risk_acceptances ra ON ra.id = m.acceptance_id
WHERE m.finding_id = f.id AND m.removed_at IS NULL
  AND ra.state = 'approved' AND f.status = 'risk_accepted';

UPDATE notification_channels
SET events = array_replace(events, 'risk_acceptance.approved', 'finding.risk_accepted')
WHERE 'risk_acceptance.approved' = ANY (events);
UPDATE notification_channels
SET events = array(SELECT e FROM unnest(events) e
                   WHERE e NOT IN ('risk_acceptance.requested', 'risk_acceptance.expiring', 'risk_acceptance.expired'))
WHERE events && '{risk_acceptance.requested,risk_acceptance.expiring,risk_acceptance.expired}'::text[];

DROP TABLE IF EXISTS risk_acceptance_findings;
DROP TABLE IF EXISTS risk_acceptances;
