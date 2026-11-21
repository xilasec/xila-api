package sbom

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Processing step names (M13 13.3): every step an SBOM upload's post-ingest
// pipeline may run, tracked by GET /sboms/{id}/status. A step not in a
// record's Steps map means its feature is disabled for this upload, which
// counts as done — see Service.Ingest.
const (
	StepPolicy       = "policy"       // component policy evaluation
	StepReachability = "reachability" // SBOM-derived reachability rescoring
	StepVulnMatch    = "vulnmatch"    // advisory match against this snapshot
	StepPkgMeta      = "pkgmeta"      // registry metadata refresh
)

// Step / overall statuses.
const (
	StepPending   = "pending"
	StepRunning   = "running"
	StepCompleted = "completed"
	StepFailed    = "failed"
)

// ErrNoProcessing is returned for an SBOM with no processing record: one
// uploaded before this feature existed, or through a path that never calls
// CreateProcessing.
var ErrNoProcessing = errors.New("no processing record for this sbom")

// ProcessingStatus is one SBOM upload's background-processing state. Status
// rolls up Steps: completed only once every step in the map is completed
// (steps for a disabled feature are never added, so they can't block it),
// failed if any step failed, running once any step has started, else
// pending. Error is the public message of whichever step last failed.
type ProcessingStatus struct {
	SbomID      string            `json:"sbom_id"`
	Status      string            `json:"status"`
	Steps       map[string]string `json:"steps"`
	Error       string            `json:"error,omitempty"`
	StartedAt   time.Time         `json:"started_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
}

const processingColumns = `sbom_id, status, steps, error, started_at, updated_at, completed_at`

func scanProcessing(row pgx.Row) (ProcessingStatus, error) {
	var p ProcessingStatus
	var steps []byte
	var errMsg *string
	if err := row.Scan(&p.SbomID, &p.Status, &steps, &errMsg, &p.StartedAt, &p.UpdatedAt, &p.CompletedAt); err != nil {
		return ProcessingStatus{}, err
	}
	if errMsg != nil {
		p.Error = *errMsg
	}
	p.Steps = map[string]string{}
	if len(steps) > 0 {
		if err := json.Unmarshal(steps, &p.Steps); err != nil {
			return ProcessingStatus{}, fmt.Errorf("decode processing steps: %w", err)
		}
	}
	return p, nil
}

// CreateProcessing starts an upload's processing record with every given
// step pending. No steps (every post-ingest hook is nil, or disabled by
// config) means nothing to wait for: the record is created already
// completed, so GET /sboms/{id}/status doesn't hang an empty-pipeline upload.
func (r *Repository) CreateProcessing(ctx context.Context, sbomID string, steps []string) (ProcessingStatus, error) {
	stepMap := make(map[string]string, len(steps))
	for _, s := range steps {
		stepMap[s] = StepPending
	}
	raw, err := json.Marshal(stepMap)
	if err != nil {
		return ProcessingStatus{}, fmt.Errorf("encode processing steps: %w", err)
	}
	status := StepPending
	var completedAt *time.Time
	if len(steps) == 0 {
		now := time.Now()
		status, completedAt = StepCompleted, &now
	}
	const q = `
		INSERT INTO sbom_processing (sbom_id, status, steps, completed_at)
		VALUES ($1, $2, $3, $4)
		RETURNING ` + processingColumns
	p, err := scanProcessing(r.db.QueryRow(ctx, q, sbomID, status, raw, completedAt))
	if err != nil {
		return ProcessingStatus{}, fmt.Errorf("create sbom processing: %w", err)
	}
	return p, nil
}

// MarkStep updates one step's status (and, on failure, a public message) and
// recomputes the overall status from every step in a single SQL statement.
// Two background steps (the advisory match, the package-metadata refresh)
// can finish concurrently for the same upload; a Go-side read-modify-write
// would risk one overwriting the other's update with a stale copy of the
// steps map. Doing the read, the jsonb_set and the recomputed status in one
// UPDATE instead means Postgres's row lock serializes concurrent callers —
// each sees the previous caller's already-committed steps when its turn comes.
func (r *Repository) MarkStep(ctx context.Context, sbomID, step, status, errMsg string) (ProcessingStatus, error) {
	var errArg *string
	if errMsg != "" {
		errArg = &errMsg
	}
	const q = `
		WITH new_steps AS (
			SELECT jsonb_set(steps, $2::text[], to_jsonb($3::text)) AS steps
			  FROM sbom_processing WHERE sbom_id = $1
		)
		UPDATE sbom_processing sp
		   SET steps = ns.steps,
		       error = CASE WHEN $3 = 'failed' THEN $4 ELSE sp.error END,
		       status = CASE
		           WHEN EXISTS (SELECT 1 FROM jsonb_each_text(ns.steps) t(k, v) WHERE t.v = 'failed') THEN 'failed'
		           WHEN NOT EXISTS (SELECT 1 FROM jsonb_each_text(ns.steps) t(k, v) WHERE t.v <> 'completed') THEN 'completed'
		           WHEN EXISTS (SELECT 1 FROM jsonb_each_text(ns.steps) t(k, v) WHERE t.v <> 'pending') THEN 'running'
		           ELSE 'pending'
		       END,
		       updated_at = now(),
		       completed_at = CASE
		           WHEN NOT EXISTS (SELECT 1 FROM jsonb_each_text(ns.steps) t(k, v) WHERE t.v <> 'completed') THEN now()
		           ELSE sp.completed_at
		       END
		  FROM new_steps ns
		 WHERE sp.sbom_id = $1
		RETURNING ` + processingColumns
	p, err := scanProcessing(r.db.QueryRow(ctx, q, sbomID, []string{step}, status, errArg))
	if errors.Is(err, pgx.ErrNoRows) {
		return ProcessingStatus{}, ErrNoProcessing
	}
	if err != nil {
		return ProcessingStatus{}, fmt.Errorf("mark sbom processing step: %w", err)
	}
	return p, nil
}

// GetProcessing returns an SBOM's processing record (GET /sboms/{id}/status).
func (r *Repository) GetProcessing(ctx context.Context, sbomID string) (ProcessingStatus, error) {
	const q = `SELECT ` + processingColumns + ` FROM sbom_processing WHERE sbom_id = $1`
	p, err := scanProcessing(r.db.QueryRow(ctx, q, sbomID))
	if errors.Is(err, pgx.ErrNoRows) {
		return ProcessingStatus{}, ErrNoProcessing
	}
	if err != nil {
		return ProcessingStatus{}, fmt.Errorf("get sbom processing: %w", err)
	}
	return p, nil
}
