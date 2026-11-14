DROP TRIGGER IF EXISTS projects_sla_criticality ON projects;
DROP FUNCTION IF EXISTS projects_sla_criticality();

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

DROP FUNCTION IF EXISTS sla_scaled_days(int, text);
DROP TABLE IF EXISTS sla_settings;
