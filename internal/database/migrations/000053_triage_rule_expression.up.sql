-- A triage rule may add a CEL expression over the finding's facts; it must hold
-- together with the rule's other conditions.
ALTER TABLE triage_rules ADD COLUMN expression text NOT NULL DEFAULT '';
