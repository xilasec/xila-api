// Package connector pulls findings from a running Dependency-Track or DefectDojo
// instance into a Xila project version, on demand and on a schedule.
//
// Each pull is one synthetic scan (scanner "dependency-track" / "defectdojo")
// applied through scan.Service.ApplyFindings, so it gets the whole ingest
// pipeline — including auto-close of what the remote no longer reports. That is
// why a pull applies only a complete fetch: a failed or partial one records
// last_error and leaves the findings alone.
package connector

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
)

// Sentinel errors.
var (
	ErrNotFound  = errors.New("connector not found")
	ErrNoProject = errors.New("project not found")
	ErrDuplicate = errors.New("a connector of this kind already imports into this version")
	ErrBusy      = errors.New("a pull of this connector is already running")
)

// Kind is the remote product.
type Kind string

// Supported remotes. The kind is also the scanner name of the findings a pull
// records.
const (
	KindDependencyTrack Kind = "dependency-track"
	KindDefectDojo      Kind = "defectdojo"
)

// Valid reports whether k is a supported remote.
func (k Kind) Valid() bool { return k == KindDependencyTrack || k == KindDefectDojo }

// Connector is a project's pull configuration plus the outcome of its last run.
// The token is never serialized; HasToken says one is stored.
type Connector struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Kind      Kind   `json:"kind"`
	Name      string `json:"name"`
	BaseURL   string `json:"base_url"`
	// RemoteProject is the Dependency-Track project UUID, or the DefectDojo
	// product id ("42") or engagement id ("engagement:42").
	RemoteProject string `json:"remote_project"`
	HasToken      bool   `json:"has_token"`
	// Version is the project version (branch) findings land in; "" = default.
	Version string `json:"version"`
	Enabled bool   `json:"enabled"`
	// LastPulledAt is the last attempt, LastSuccessAt the last applied pull.
	LastPulledAt  *time.Time `json:"last_pulled_at"`
	LastSuccessAt *time.Time `json:"last_success_at"`
	LastError     string     `json:"last_error"`
	LastCount     int        `json:"last_count"`
	LastScanID    *string    `json:"last_scan_id"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`

	tokenEnc []byte
}

// Repository stores connector configs.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

const columns = `id, project_id, kind, name, base_url, remote_project, token_enc, version, enabled,
	last_pulled_at, last_success_at, last_error, last_count, last_scan_id, created_at, updated_at`

func scanConnector(row pgx.Row) (Connector, error) {
	var c Connector
	err := row.Scan(&c.ID, &c.ProjectID, &c.Kind, &c.Name, &c.BaseURL, &c.RemoteProject, &c.tokenEnc,
		&c.Version, &c.Enabled, &c.LastPulledAt, &c.LastSuccessAt, &c.LastError, &c.LastCount,
		&c.LastScanID, &c.CreatedAt, &c.UpdatedAt)
	c.HasToken = len(c.tokenEnc) > 0
	return c, err
}

func one(row pgx.Row, what string) (Connector, error) {
	c, err := scanConnector(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return Connector{}, ErrNotFound
	}
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) {
			switch pgErr.Code {
			case "23505":
				return Connector{}, ErrDuplicate
			case "23503":
				return Connector{}, ErrNoProject
			}
		}
		return Connector{}, fmt.Errorf("%s connector: %w", what, err)
	}
	return c, nil
}

func many(rows pgx.Rows, err error) ([]Connector, error) {
	if err != nil {
		return nil, fmt.Errorf("list connectors: %w", err)
	}
	defer rows.Close()
	out := []Connector{}
	for rows.Next() {
		c, err := scanConnector(rows)
		if err != nil {
			return nil, fmt.Errorf("scan connector: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// List returns the project's connectors.
func (r *Repository) List(ctx context.Context, projectID string) ([]Connector, error) {
	return many(r.db.Query(ctx, `SELECT `+columns+` FROM connectors WHERE project_id = $1 ORDER BY created_at, id`, projectID))
}

// Get returns one of the project's connectors.
func (r *Repository) Get(ctx context.Context, projectID, id string) (Connector, error) {
	return one(r.db.QueryRow(ctx, `SELECT `+columns+` FROM connectors WHERE project_id = $1 AND id = $2`, projectID, id), "get")
}

// Create inserts a connector with its sealed token.
func (r *Repository) Create(ctx context.Context, c Connector, tokenEnc []byte) (Connector, error) {
	return one(r.db.QueryRow(ctx, `
		INSERT INTO connectors (project_id, kind, name, base_url, remote_project, token_enc, version, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING `+columns,
		c.ProjectID, c.Kind, c.Name, c.BaseURL, c.RemoteProject, tokenEnc, c.Version, c.Enabled), "create")
}

// Update rewrites a connector's config. A nil tokenEnc keeps the stored token.
func (r *Repository) Update(ctx context.Context, c Connector, tokenEnc []byte) (Connector, error) {
	return one(r.db.QueryRow(ctx, `
		UPDATE connectors SET name = $3, base_url = $4, remote_project = $5,
		    token_enc = COALESCE($6, token_enc), version = $7, enabled = $8, updated_at = now()
		WHERE project_id = $1 AND id = $2
		RETURNING `+columns,
		c.ProjectID, c.ID, c.Name, c.BaseURL, c.RemoteProject, tokenEnc, c.Version, c.Enabled), "update")
}

// Delete removes a connector. The findings it imported stay.
func (r *Repository) Delete(ctx context.Context, projectID, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM connectors WHERE project_id = $1 AND id = $2`, projectID, id)
	if err != nil {
		return fmt.Errorf("delete connector: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// dueClause selects enabled connectors not attempted within $1 seconds. A
// failed attempt counts, so an unreachable remote is retried on the schedule
// rather than on every tick.
const dueClause = `enabled AND (last_pulled_at IS NULL OR last_pulled_at <= now() - make_interval(secs => $1))`

// ListDue returns the enabled connectors whose last attempt is older than every.
func (r *Repository) ListDue(ctx context.Context, every time.Duration) ([]Connector, error) {
	return many(r.db.Query(ctx, `SELECT `+columns+` FROM connectors WHERE `+dueClause+` ORDER BY last_pulled_at NULLS FIRST, id`,
		every.Seconds()))
}

// StillDue re-checks one connector under its pull lock: another instance may
// have pulled it between ListDue and the lock.
func (r *Repository) StillDue(ctx context.Context, id string, every time.Duration) (bool, error) {
	var due bool
	err := r.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM connectors WHERE id = $2 AND `+dueClause+`)`,
		every.Seconds(), id).Scan(&due)
	if err != nil {
		return false, fmt.Errorf("check connector due: %w", err)
	}
	return due, nil
}

// pullLockNamespace keys the per-connector advisory lock that serializes pulls
// across instances and against a concurrent "pull now" (1 = dedup, 2 = vulnmatch).
const pullLockNamespace = 3

// TryLock takes the connector's pull lock on a dedicated connection. ok=false
// means another pull holds it. release unlocks and returns the connection.
func (r *Repository) TryLock(ctx context.Context, id string) (release func(), ok bool, err error) {
	conn, err := r.db.Acquire(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("acquire pull lock conn: %w", err)
	}
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1, hashtext($2))`, pullLockNamespace, id).Scan(&ok); err != nil {
		conn.Release()
		return nil, false, fmt.Errorf("pull lock: %w", err)
	}
	if !ok {
		conn.Release()
		return nil, false, nil
	}
	return func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1, hashtext($2))`, pullLockNamespace, id)
		conn.Release()
	}, true, nil
}

// ResolveVersion returns the id of the project version named name (creating it
// on first use, like a scan does); "" is the default version.
func (r *Repository) ResolveVersion(ctx context.Context, projectID, name string) (string, error) {
	var id string
	if err := r.db.QueryRow(ctx, `SELECT project_version($1, $2, 'branch')`, projectID, name).Scan(&id); err != nil {
		return "", fmt.Errorf("resolve version: %w", err)
	}
	return id, nil
}

// RecordSuccess stamps an applied pull.
func (r *Repository) RecordSuccess(ctx context.Context, id, scanID string, count int) (Connector, error) {
	return one(r.db.QueryRow(ctx, `
		UPDATE connectors SET last_pulled_at = now(), last_success_at = now(), last_error = '',
		    last_count = $2, last_scan_id = $3
		WHERE id = $1 RETURNING `+columns, id, count, scanID), "record")
}

// RecordFailure stamps a pull that applied nothing.
func (r *Repository) RecordFailure(ctx context.Context, id, msg string) (Connector, error) {
	return one(r.db.QueryRow(ctx, `
		UPDATE connectors SET last_pulled_at = now(), last_error = $2
		WHERE id = $1 RETURNING `+columns, id, msg), "record")
}

// Outcome counts what a pull's scan did to the version: findings it created and
// findings of its scanner it auto-closed.
func (r *Repository) Outcome(ctx context.Context, scanID string) (created, closed int, err error) {
	err = r.db.QueryRow(ctx, `
		SELECT
		    (SELECT count(*) FROM findings f WHERE f.first_scan_id = s.id AND f.duplicate_of IS NULL),
		    (SELECT count(*) FROM findings f
		     WHERE f.project_id = s.project_id AND f.version_id = s.version_id AND f.scanner = s.scanner
		       AND f.status = 'remediated' AND f.resolved_at >= s.started_at
		       AND f.last_scan_id IS DISTINCT FROM s.id)
		FROM scans s WHERE s.id = $1`, scanID).Scan(&created, &closed)
	if err != nil {
		return 0, 0, fmt.Errorf("pull outcome: %w", err)
	}
	return created, closed, nil
}

// triageCandidate is a finding a scan just created that carries a remote
// (imported) triage verdict.
type triageCandidate struct {
	ID      string
	Scanner string
	Status  domain.FindingStatus
	Reason  string
	Expires string // RFC 3339, "" = none
}

// RemoteTriageCandidates returns the findings first reported by scanID that
// are still untriaged (open) and carry a verdict in their metadata
// (`remote_triage`, optional `remote_triage_reason` / `remote_triage_expires`).
// Any producer may set them: connectors and importing parsers alike.
func (r *Repository) RemoteTriageCandidates(ctx context.Context, projectID, scanID string) ([]triageCandidate, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, scanner, metadata->>'remote_triage', COALESCE(metadata->>'remote_triage_reason', ''),
		       COALESCE(metadata->>'remote_triage_expires', '')
		FROM findings
		WHERE project_id = $1 AND last_scan_id = $2 AND first_scan_id = $2
		  AND status = 'open' AND metadata ? 'remote_triage'`, projectID, scanID)
	if err != nil {
		return nil, fmt.Errorf("list remote triage: %w", err)
	}
	defer rows.Close()
	out := []triageCandidate{}
	for rows.Next() {
		var c triageCandidate
		if err := rows.Scan(&c.ID, &c.Scanner, &c.Status, &c.Reason, &c.Expires); err != nil {
			return nil, fmt.Errorf("scan remote triage: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
