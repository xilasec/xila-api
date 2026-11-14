-- Reachability, recovered from the SBOM we already store rather than from any
-- analysis of our own: how deep in the dependency tree a component sits, and
-- whether it ships at all. These two facts are what make most of a dependency
-- backlog irrelevant.

-- direct/depth are NULL when the SBOM carried no dependency graph; scope '' means
-- the SBOM did not say. Unknown must never be punished, so both default to
-- "no information" rather than to a guess.
ALTER TABLE sbom_components
    ADD COLUMN IF NOT EXISTS direct boolean,
    ADD COLUMN IF NOT EXISTS depth  integer,
    ADD COLUMN IF NOT EXISTS scope  text NOT NULL DEFAULT '';

ALTER TABLE sbom_components
    ADD CONSTRAINT sbom_components_scope_check
    CHECK (scope IN ('', 'runtime', 'dev', 'optional'));

-- The same facts denormalized onto the finding, matched from the project's
-- current inventory — so listing, filtering, gating and priority need no join.
ALTER TABLE findings
    ADD COLUMN IF NOT EXISTS dep_direct boolean,
    ADD COLUMN IF NOT EXISTS dep_depth  integer,
    ADD COLUMN IF NOT EXISTS dep_scope  text NOT NULL DEFAULT '';

ALTER TABLE findings
    ADD CONSTRAINT findings_dep_scope_check
    CHECK (dep_scope IN ('', 'runtime', 'dev', 'optional'));

-- "Show me only what actually ships, and only what I chose to depend on" is the
-- default working view once reachability is known.
CREATE INDEX IF NOT EXISTS idx_findings_reachable
    ON findings (project_id, priority DESC)
    WHERE duplicate_of IS NULL AND status IN ('open', 'confirmed')
      AND dep_scope <> 'dev' AND dep_direct IS NOT FALSE;

-- Triage rules can now condition on reachability: "transitive dev dependency ->
-- suppress" is the rule that removes most of a dependency backlog.
ALTER TABLE triage_rules
    ADD COLUMN IF NOT EXISTS dep_scope      text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS dep_transitive boolean NOT NULL DEFAULT false;

ALTER TABLE triage_rules
    ADD CONSTRAINT triage_rules_dep_scope_check
    CHECK (dep_scope IN ('', 'runtime', 'dev', 'optional'));
