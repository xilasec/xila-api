ALTER TABLE triage_rules
    DROP COLUMN IF EXISTS rejected_at,
    DROP COLUMN IF EXISTS rejected_by,
    DROP COLUMN IF EXISTS approved_at,
    DROP COLUMN IF EXISTS approved_by,
    DROP COLUMN IF EXISTS updated_by,
    DROP COLUMN IF EXISTS created_by,
    DROP COLUMN IF EXISTS approval_status,
    DROP COLUMN IF EXISTS last_hit_at,
    DROP COLUMN IF EXISTS hit_count,
    DROP COLUMN IF EXISTS project_criticality,
    DROP COLUMN IF EXISTS kev,
    DROP COLUMN IF EXISTS min_epss;
