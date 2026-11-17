ALTER TABLE custom_field_definitions
    DROP CONSTRAINT custom_field_definitions_computed_not_user,
    DROP CONSTRAINT custom_field_definitions_computed_not_required,
    DROP CONSTRAINT custom_field_definitions_computed_expression,
    DROP COLUMN expression,
    DROP COLUMN computed;
