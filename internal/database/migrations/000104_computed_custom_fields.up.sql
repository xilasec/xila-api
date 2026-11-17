-- Computed custom fields: a definition may carry a CEL expression instead of
-- being set by people. The value is still stored in the entity's `custom`
-- column like any other field (filters, exports, history and other CEL
-- expressions see it unchanged); only the API refuses to write to it by hand
-- (400) and the server recomputes it instead (see internal/computed).

ALTER TABLE custom_field_definitions
    ADD COLUMN computed   BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN expression TEXT NOT NULL DEFAULT '',
    ADD CONSTRAINT custom_field_definitions_computed_expression
        CHECK (NOT computed OR expression <> ''),
    ADD CONSTRAINT custom_field_definitions_computed_not_required
        CHECK (NOT (computed AND required)),
    ADD CONSTRAINT custom_field_definitions_computed_not_user
        CHECK (NOT (computed AND type = 'user'));
