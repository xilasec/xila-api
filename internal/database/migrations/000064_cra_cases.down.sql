DROP TABLE IF EXISTS cra_case_events;
DROP TABLE IF EXISTS cra_cases;
ALTER TABLE projects
    DROP COLUMN IF EXISTS cra_member_states,
    DROP COLUMN IF EXISTS cra_product_version,
    DROP COLUMN IF EXISTS cra_product_name,
    DROP COLUMN IF EXISTS cra_in_scope;
