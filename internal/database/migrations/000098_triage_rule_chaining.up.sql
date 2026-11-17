-- Triage rule chaining: a rule with continue_matching lets the rules after
-- it (sort_order) evaluate too, against the finding as it left it. Off keeps
-- the original "first match wins".
ALTER TABLE triage_rules ADD COLUMN continue_matching BOOLEAN NOT NULL DEFAULT false;
