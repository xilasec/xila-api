-- Stored gate state (M13 13.7): the gate used to be evaluated only on demand
-- (POST /projects/{id}/gate). This caches each project's last evaluated
-- result per version (the default version, plus any branch someone has
-- evaluated), so GET /projects/{id}, the project list and a findings
-- ?fails_gate= filter can read it without re-running the policy. See
-- internal/gate.
CREATE TABLE project_gate_state (
    project_id   UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    version_id   UUID NOT NULL REFERENCES project_versions(id) ON DELETE CASCADE,
    passed       BOOLEAN NOT NULL,
    scope        TEXT NOT NULL DEFAULT '',
    new_only     BOOLEAN NOT NULL DEFAULT false,
    -- Violations: [{"rule": "...", "message": "..."}], same shape as
    -- gate.Violation.
    violations   JSONB NOT NULL DEFAULT '[]',
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (project_id, version_id)
);

CREATE INDEX project_gate_state_project_idx ON project_gate_state (project_id);
