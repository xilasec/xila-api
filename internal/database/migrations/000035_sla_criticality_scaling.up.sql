-- Optionally scale every SLA window by the project's business criticality: a
-- critical system gets less time to remediate than a low-importance one under
-- the same policy. One instance-wide switch (admin) plus a factor per
-- criticality; off by default, so nothing changes until an admin turns it on.
--
-- The scaled window is round(base × factor), at least 1 day and at most the
-- 3650-day policy maximum. "No SLA" (NULL) stays no SLA. Medium defaults to 1,
-- and projects default to medium criticality, so enabling it leaves typical
-- projects exactly where they were.
CREATE TABLE IF NOT EXISTS sla_settings (
    id                    BOOLEAN PRIMARY KEY DEFAULT true CHECK (id),  -- singleton
    scale_by_criticality  BOOLEAN NOT NULL DEFAULT false,
    critical_factor       NUMERIC(4,2) NOT NULL DEFAULT 0.5  CHECK (critical_factor BETWEEN 0.1 AND 10),
    high_factor           NUMERIC(4,2) NOT NULL DEFAULT 0.75 CHECK (high_factor     BETWEEN 0.1 AND 10),
    medium_factor         NUMERIC(4,2) NOT NULL DEFAULT 1    CHECK (medium_factor   BETWEEN 0.1 AND 10),
    low_factor            NUMERIC(4,2) NOT NULL DEFAULT 1.5  CHECK (low_factor      BETWEEN 0.1 AND 10),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
INSERT INTO sla_settings DEFAULT VALUES ON CONFLICT DO NOTHING;

-- sla_scaled_days is the one place the scaling rule lives: the trigger, policy
-- re-application and the API's preview matrix all call it. A missing settings
-- row means "no scaling", never "no SLA".
CREATE OR REPLACE FUNCTION sla_scaled_days(p_base int, p_criticality text)
RETURNS int LANGUAGE sql STABLE AS $$
    SELECT CASE
        WHEN p_base IS NULL THEN NULL
        WHEN NOT COALESCE(s.scale_by_criticality, false) THEN p_base
        ELSE LEAST(3650, GREATEST(1, round(p_base * CASE p_criticality
                WHEN 'critical' THEN s.critical_factor
                WHEN 'high'     THEN s.high_factor
                WHEN 'low'      THEN s.low_factor
                ELSE s.medium_factor END)))::int
    END
    FROM (VALUES (true)) one(id) LEFT JOIN sla_settings s ON s.id = one.id
$$;

CREATE OR REPLACE FUNCTION sla_days_for(p_project uuid, p_severity text)
RETURNS int LANGUAGE sql STABLE AS $$
    SELECT sla_scaled_days(
               CASE p_severity
                   WHEN 'critical' THEN pol.critical_days
                   WHEN 'high'     THEN pol.high_days
                   WHEN 'medium'   THEN pol.medium_days
                   WHEN 'low'      THEN pol.low_days
                   WHEN 'info'     THEN pol.info_days
               END,
               (SELECT business_criticality FROM projects WHERE id = p_project))
    FROM sla_policy_for(p_project) pol
$$;

-- A project's criticality is edited in one place (PATCH /projects/{id}) but
-- moves every deadline in it while scaling is on; a trigger keeps that from
-- depending on the handler remembering. Writes only windows that change.
CREATE OR REPLACE FUNCTION projects_sla_criticality() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.business_criticality IS DISTINCT FROM OLD.business_criticality
       AND COALESCE((SELECT scale_by_criticality FROM sla_settings), false) THEN
        UPDATE findings f SET sla_days = d.days
        FROM (SELECT id, sla_days_for(project_id, severity) AS days FROM findings WHERE project_id = NEW.id) d
        WHERE f.id = d.id AND f.sla_days IS DISTINCT FROM d.days;
    END IF;
    RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS projects_sla_criticality ON projects;
CREATE TRIGGER projects_sla_criticality
    AFTER UPDATE OF business_criticality ON projects
    FOR EACH ROW EXECUTE FUNCTION projects_sla_criticality();
