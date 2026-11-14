-- SLA: how long a finding may stay open, per severity, before it is overdue.
--
-- A policy is set globally, per organization, or per project; the most specific
-- one that exists wins as a whole (no per-field inheritance — a project that
-- writes a policy states all of it). With no stored policy at all, the built-in
-- default in sla_days_for applies. A NULL day count means "no SLA" for that
-- severity.
CREATE TABLE IF NOT EXISTS sla_policies (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id         UUID REFERENCES organizations(id) ON DELETE CASCADE,
    project_id     UUID REFERENCES projects(id) ON DELETE CASCADE,
    critical_days  INT CHECK (critical_days > 0),
    high_days      INT CHECK (high_days > 0),
    medium_days    INT CHECK (medium_days > 0),
    low_days       INT CHECK (low_days > 0),
    info_days      INT CHECK (info_days > 0),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (org_id IS NULL OR project_id IS NULL)
);
CREATE UNIQUE INDEX IF NOT EXISTS sla_policies_project ON sla_policies (project_id) WHERE project_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS sla_policies_org ON sla_policies (org_id) WHERE org_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS sla_policies_global ON sla_policies ((true)) WHERE org_id IS NULL AND project_id IS NULL;

-- sla_policy_for resolves a project's effective policy: project > org > global >
-- built-in default (7/30/90/120 days, no SLA for info — DefectDojo's defaults).
-- scope is 'project' | 'org' | 'global' | 'default'.
CREATE OR REPLACE FUNCTION sla_policy_for(p_project uuid)
RETURNS TABLE (scope text, critical_days int, high_days int, medium_days int, low_days int, info_days int)
LANGUAGE sql STABLE AS $$
    WITH pol AS (
        SELECT CASE WHEN sp.project_id IS NOT NULL THEN 'project'
                    WHEN sp.org_id IS NOT NULL THEN 'org'
                    ELSE 'global' END AS scope,
               sp.critical_days, sp.high_days, sp.medium_days, sp.low_days, sp.info_days
        FROM sla_policies sp
        WHERE sp.project_id = p_project
           OR (sp.project_id IS NULL AND sp.org_id = (
                   SELECT t.org_id FROM projects p JOIN teams t ON t.id = p.team_id WHERE p.id = p_project))
           OR (sp.project_id IS NULL AND sp.org_id IS NULL)
        ORDER BY (sp.project_id IS NOT NULL) DESC, (sp.org_id IS NOT NULL) DESC
        LIMIT 1
    )
    SELECT * FROM pol
    UNION ALL
    SELECT 'default', 7, 30, 90, 120, NULL::int WHERE NOT EXISTS (SELECT 1 FROM pol)
$$;

-- sla_days_for is the day count one finding gets.
CREATE OR REPLACE FUNCTION sla_days_for(p_project uuid, p_severity text)
RETURNS int LANGUAGE sql STABLE AS $$
    SELECT CASE p_severity
               WHEN 'critical' THEN critical_days
               WHEN 'high'     THEN high_days
               WHEN 'medium'   THEN medium_days
               WHEN 'low'      THEN low_days
               WHEN 'info'     THEN info_days
           END
    FROM sla_policy_for(p_project)
$$;

-- Per-finding SLA state.
--   sla_days          the window this finding got (NULL = no SLA)
--   sla_due_at        first_seen_at + sla_days + time spent paused
--   sla_paused_at     set while the finding sits in an exception state
--   sla_paused_total  accumulated paused time from earlier exceptions
--   sla_notified_due  the due date we already sent a breach alert for
--   sla_warned_due    the due date we already sent a due-soon alert for
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS sla_days         INT,
    ADD COLUMN IF NOT EXISTS sla_due_at       TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS sla_paused_at    TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS sla_paused_total INTERVAL NOT NULL DEFAULT '0',
    ADD COLUMN IF NOT EXISTS sla_notified_due TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS sla_warned_due   TIMESTAMPTZ;

-- The SLA clock is maintained by a trigger, not by the Go code paths, because
-- status and severity are written from many places (manual triage, auto-triage,
-- VEX, auto-close, reopen-on-reappearance, the exception sweep). Missing one of
-- them would silently corrupt every due date; a trigger cannot be bypassed.
--
--   * sla_days is re-resolved when the finding is created or its severity changes.
--   * Entering an exception state (risk_accepted / false_positive / wont_fix)
--     pauses the clock; leaving it adds the paused time to the deadline.
--     remediated does NOT pause: a finding that comes back was never fixed.
--   * sla_due_at is always derived from the three facts above.
--
-- All of it is absolute time: a day is 24 hours, and paused time is stored as
-- an exact duration. Adding a 'days' interval to a timestamptz is calendar
-- arithmetic in the session time zone, which would move deadlines by an hour
-- whenever a window spans a DST change.
CREATE OR REPLACE FUNCTION findings_sla_maintain() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    was_paused boolean;
    is_paused  boolean := NEW.status IN ('risk_accepted', 'false_positive', 'wont_fix');
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.sla_days := sla_days_for(NEW.project_id, NEW.severity);
        IF is_paused THEN
            NEW.sla_paused_at := now();
        END IF;
    ELSE
        IF NEW.severity IS DISTINCT FROM OLD.severity OR NEW.project_id IS DISTINCT FROM OLD.project_id THEN
            NEW.sla_days := sla_days_for(NEW.project_id, NEW.severity);
        END IF;
        was_paused := OLD.status IN ('risk_accepted', 'false_positive', 'wont_fix');
        IF is_paused AND NOT was_paused THEN
            NEW.sla_paused_at := now();
        ELSIF was_paused AND NOT is_paused THEN
            NEW.sla_paused_total := OLD.sla_paused_total
                + make_interval(secs => extract(epoch FROM now() - COALESCE(OLD.sla_paused_at, now())));
            NEW.sla_paused_at := NULL;
        END IF;
    END IF;

    NEW.sla_due_at := CASE WHEN NEW.sla_days IS NULL THEN NULL
                           ELSE NEW.first_seen_at + make_interval(hours => 24 * NEW.sla_days) + NEW.sla_paused_total END;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS findings_sla ON findings;
CREATE TRIGGER findings_sla
    BEFORE INSERT OR UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION findings_sla_maintain();

-- Backfill: give every existing finding its window. Findings already in an
-- exception state start their pause from when they got there (best known).
UPDATE findings
SET sla_days      = sla_days_for(project_id, severity),
    sla_paused_at = CASE WHEN status IN ('risk_accepted', 'false_positive', 'wont_fix')
                         THEN COALESCE(resolved_at, updated_at) END;

-- "What is overdue / due next" over the live backlog.
CREATE INDEX IF NOT EXISTS idx_findings_sla_due
    ON findings (sla_due_at)
    WHERE duplicate_of IS NULL AND status IN ('open', 'confirmed') AND sla_due_at IS NOT NULL;

-- Gate: fail when any live finding is past its SLA.
ALTER TABLE gate_policies ADD COLUMN IF NOT EXISTS block_sla_breach BOOLEAN NOT NULL DEFAULT false;
