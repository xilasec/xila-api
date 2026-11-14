-- Runtime feature switches (internal/feature). The set of features and their
-- defaults live in code; a row exists only once an admin has flipped one, so
-- an absent row means "the default" and a feature removed from code leaves an
-- ignored row behind, never an error.
CREATE TABLE feature_flags (
    key        text PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]*$'),
    enabled    boolean NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by uuid REFERENCES users(id) ON DELETE SET NULL
);
