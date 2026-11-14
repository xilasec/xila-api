ALTER TABLE gate_policies DROP COLUMN IF EXISTS block_sla_breach;
DROP INDEX IF EXISTS idx_findings_sla_due;
DROP TRIGGER IF EXISTS findings_sla ON findings;
DROP FUNCTION IF EXISTS findings_sla_maintain();
ALTER TABLE findings
    DROP COLUMN IF EXISTS sla_days,
    DROP COLUMN IF EXISTS sla_due_at,
    DROP COLUMN IF EXISTS sla_paused_at,
    DROP COLUMN IF EXISTS sla_paused_total,
    DROP COLUMN IF EXISTS sla_notified_due,
    DROP COLUMN IF EXISTS sla_warned_due;
DROP FUNCTION IF EXISTS sla_days_for(uuid, text);
DROP FUNCTION IF EXISTS sla_policy_for(uuid);
DROP TABLE IF EXISTS sla_policies;
