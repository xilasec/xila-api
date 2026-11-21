package gate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// State is a project's last stored gate result for one version (the table's
// row). Evaluate is re-run and the row replaced after every ingest, after
// enrichment/exploit/KEV changes that touch the project, and on a leader
// interval (see Evaluator); it is never computed inline from this table.
type State struct {
	ProjectID   string      `json:"project_id"`
	VersionID   string      `json:"version_id"`
	Passed      bool        `json:"passed"`
	Scope       string      `json:"scope"`
	NewOnly     bool        `json:"new_only"`
	Violations  []Violation `json:"violations"`
	EvaluatedAt time.Time   `json:"evaluated_at"`
}

const stateColumns = `project_id, version_id, passed, scope, new_only, violations, evaluated_at`

func scanState(row pgx.Row) (State, error) {
	var s State
	var raw []byte
	if err := row.Scan(&s.ProjectID, &s.VersionID, &s.Passed, &s.Scope, &s.NewOnly, &raw, &s.EvaluatedAt); err != nil {
		return State{}, err
	}
	s.Violations = []Violation{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &s.Violations); err != nil {
			return State{}, fmt.Errorf("decode violations: %w", err)
		}
	}
	return s, nil
}

// GetState returns a project's stored gate result for one version — ""
// resolves its current default version — and whether one has been stored
// yet (false before the first evaluation).
func (r *Repository) GetState(ctx context.Context, projectID, versionID string) (State, bool, error) {
	var (
		q    string
		args []any
	)
	if versionID == "" {
		q = `SELECT ` + stateColumns + ` FROM project_gate_state
			WHERE project_id = $1
			  AND version_id = (SELECT id FROM project_versions WHERE project_id = $1 AND is_default)`
		args = []any{projectID}
	} else {
		q = `SELECT ` + stateColumns + ` FROM project_gate_state WHERE project_id = $1 AND version_id = $2`
		args = []any{projectID, versionID}
	}
	s, err := scanState(r.db.QueryRow(ctx, q, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, fmt.Errorf("get gate state: %w", err)
	}
	return s, true, nil
}

// UpsertState stores a project version's gate result, replacing any prior one
// for that exact (project, version). s.VersionID must be a concrete id (the
// caller resolves "default" first).
func (r *Repository) UpsertState(ctx context.Context, s State) error {
	violations := s.Violations
	if violations == nil {
		violations = []Violation{}
	}
	raw, err := json.Marshal(violations)
	if err != nil {
		return fmt.Errorf("encode violations: %w", err)
	}
	const q = `
		INSERT INTO project_gate_state (project_id, version_id, passed, scope, new_only, violations, evaluated_at)
		VALUES ($1, $2, $3, $4, $5, $6, now())
		ON CONFLICT (project_id, version_id) DO UPDATE SET
			passed = EXCLUDED.passed, scope = EXCLUDED.scope, new_only = EXCLUDED.new_only,
			violations = EXCLUDED.violations, evaluated_at = now()`
	if _, err := r.db.Exec(ctx, q, s.ProjectID, s.VersionID, s.Passed, s.Scope, s.NewOnly, raw); err != nil {
		return fmt.Errorf("upsert gate state: %w", err)
	}
	return nil
}
