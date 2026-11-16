-- Per-project priority weights (M12 12.15): an override of the factors of
-- domain.Priority (domain.Weights, JSON; fields left out keep the default).
-- NULL = the defaults. Validated by the API (domain.Weights.Validate).
ALTER TABLE projects ADD COLUMN priority_weights JSONB;
