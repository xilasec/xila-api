// Package scan records scanner runs and ingests their output into findings.
package scan

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/domain"
)

// ErrNotFound is returned when a scan does not exist.
var ErrNotFound = errors.New("scan not found")

// ErrUnknownEngagement is returned for a scan filed under an engagement that
// isn't one of its project's.
var ErrUnknownEngagement = errors.New("engagement_id is not an engagement of this project")

// ErrCollection is returned for a scan filed on a collection project, which
// holds no scans of its own (its children do).
var ErrCollection = errors.New("project is a collection: upload to one of its child projects")

// Scan is a single ingestion event: one tool run against one project.
type Scan struct {
	ID        string            `json:"id"`
	ProjectID string            `json:"project_id"`
	AssetID   *string           `json:"asset_id"`
	Scanner   string            `json:"scanner"`
	Category  domain.Category   `json:"category"`
	Status    domain.ScanStatus `json:"status"`
	CommitSHA string            `json:"commit_sha"`
	Branch    string            `json:"branch"`
	// VersionID is the project version the scan belongs to. On Create, an empty
	// VersionID is resolved from Branch + Kind (created on first use; empty
	// Branch = the project's default version).
	VersionID string `json:"version_id"`
	// EngagementID files the scan as a test of one of the project's engagements.
	EngagementID *string `json:"engagement_id"`
	// Kind is "branch" (default) or "release" — only used to resolve a new version.
	Kind       string         `json:"-"`
	Summary    map[string]int `json:"summary"`
	Error      string         `json:"error"`
	StartedAt  *time.Time     `json:"started_at"`
	FinishedAt *time.Time     `json:"finished_at"`
	CreatedAt  time.Time      `json:"created_at"`
	// ArchivedAt / ArchivedBy: set while the scan is archived (internal/archive).
	ArchivedAt *time.Time `json:"archived_at"`
	ArchivedBy *string    `json:"archived_by"`
	// ContentHash is a deterministic digest of everything a report's upsert
	// would write (see scan.contentHash), set once parsing finishes — even on a
	// scan that was NOT skipped, so the *next* upload has something to compare
	// against. nil for scans with no raw report (manual findings, ApplyFindings)
	// and for ones where hashing itself failed.
	ContentHash *string `json:"content_hash"`
	// UnchangedOf is set when this scan's content hash matched its target's
	// previous completed scan: the pipeline was skipped and this scan merely
	// carried the earlier findings forward (see scan.Service.runPipeline).
	UnchangedOf *string `json:"unchanged_of"`
	// SplitAssets attributes each finding to the asset of the host it names
	// (one host asset per scanned machine) instead of to AssetID.
	SplitAssets bool `json:"split_assets"`
}

// Repository provides access to the scans table.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

const scanColumns = `id, project_id, asset_id, scanner, category, status, commit_sha,
	branch, summary, error, started_at, finished_at, created_at, version_id, engagement_id, archived_at, archived_by,
	content_hash, unchanged_of, split_assets`

func scanScan(row pgx.Row) (Scan, error) {
	var s Scan
	err := row.Scan(&s.ID, &s.ProjectID, &s.AssetID, &s.Scanner, &s.Category, &s.Status, &s.CommitSHA,
		&s.Branch, &s.Summary, &s.Error, &s.StartedAt, &s.FinishedAt, &s.CreatedAt, &s.VersionID, &s.EngagementID, &s.ArchivedAt, &s.ArchivedBy,
		&s.ContentHash, &s.UnchangedOf, &s.SplitAssets)
	return s, err
}

// Create records a new scan in the "processing" state with started_at set.
func (r *Repository) Create(ctx context.Context, s Scan) (Scan, error) {
	const q = `
		INSERT INTO scans (project_id, asset_id, scanner, category, status, commit_sha, branch, started_at, version_id, engagement_id, split_assets)
		VALUES ($1, $2, $3, $4, 'processing', $5, $6, now(), COALESCE($7::uuid, project_version($1, $6, $8)), $9, $10)
		RETURNING ` + scanColumns
	var version *string
	if s.VersionID != "" {
		version = &s.VersionID
	}
	out, err := scanScan(r.db.QueryRow(ctx, q, s.ProjectID, s.AssetID, s.Scanner, s.Category, s.CommitSHA, s.Branch, version, s.Kind, s.EngagementID, s.SplitAssets))
	// The FK is (engagement_id, project_id): another project's engagement fails it.
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.ConstraintName == "scans_engagement_fk" {
		return Scan{}, ErrUnknownEngagement
	}
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.ConstraintName == "project_is_collection" {
		return Scan{}, ErrCollection
	}
	if err != nil {
		return Scan{}, fmt.Errorf("insert scan: %w", err)
	}
	return out, nil
}

// Finalize records the outcome of processing: status, per-severity summary and
// any error, stamping finished_at. contentHash ("" = leave it NULL) is the
// digest runPipeline computed from the parsed report, stored so the *next*
// upload for this target has something to compare against — see
// LatestCompletedTarget and Service.contentHash.
func (r *Repository) Finalize(ctx context.Context, id string, status domain.ScanStatus, summary map[string]int, errMsg, contentHash string) (Scan, error) {
	const q = `
		UPDATE scans
		SET status = $2, summary = $3, error = $4, finished_at = now(), content_hash = NULLIF($5, '')
		WHERE id = $1
		RETURNING ` + scanColumns
	if summary == nil {
		summary = map[string]int{}
	}
	out, err := scanScan(r.db.QueryRow(ctx, q, id, status, summary, errMsg, contentHash))
	if err != nil {
		return Scan{}, fmt.Errorf("finalize scan: %w", err)
	}
	return out, nil
}

// LatestCompletedTarget returns the most recently completed scan for the same
// target CloseMissing would use — project, scanner, version and asset (NULL
// asset matches NULL asset only) — the previous run a new upload might be
// repeating. ok is false when the target has no completed scan yet.
func (r *Repository) LatestCompletedTarget(ctx context.Context, projectID, scannerName, versionID string, assetID *string) (Scan, bool, error) {
	const q = `SELECT ` + scanColumns + ` FROM scans
		WHERE project_id = $1 AND scanner = $2 AND version_id = $3
		  AND asset_id IS NOT DISTINCT FROM $4
		  AND status = 'completed'
		ORDER BY created_at DESC
		LIMIT 1`
	s, err := scanScan(r.db.QueryRow(ctx, q, projectID, scannerName, versionID, assetID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Scan{}, false, nil
	}
	if err != nil {
		return Scan{}, false, fmt.Errorf("latest completed scan for target: %w", err)
	}
	return s, true, nil
}

// MarkUnchanged finalizes a scan as a cheap repeat of an earlier one with an
// identical content hash: completed, the same summary, content_hash carried
// over, and unchanged_of pointing at the scan it repeated. The caller is
// responsible for moving the target's findings onto this scan first (see
// findingWriter.CarryForward) — this only touches the scan row.
func (r *Repository) MarkUnchanged(ctx context.Context, id, repeatOf, contentHash string, summary map[string]int) (Scan, error) {
	const q = `
		UPDATE scans
		SET status = 'completed', summary = $3, content_hash = $4, unchanged_of = $2, finished_at = now()
		WHERE id = $1
		RETURNING ` + scanColumns
	if summary == nil {
		summary = map[string]int{}
	}
	out, err := scanScan(r.db.QueryRow(ctx, q, id, repeatOf, summary, contentHash))
	if err != nil {
		return Scan{}, fmt.Errorf("mark scan unchanged: %w", err)
	}
	return out, nil
}

// List returns scans for a project, newest first; archived lists the archived
// ones instead.
func (r *Repository) List(ctx context.Context, projectID string, archived bool) ([]Scan, error) {
	q := `SELECT ` + scanColumns + ` FROM scans WHERE project_id = $1 AND` + archive.Only(archive.Scan(""), archived) + ` ORDER BY created_at DESC`
	rows, err := r.db.Query(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("list scans: %w", err)
	}
	defer rows.Close()

	scans := []Scan{}
	for rows.Next() {
		s, err := scanScan(rows)
		if err != nil {
			return nil, fmt.Errorf("scan scan: %w", err)
		}
		scans = append(scans, s)
	}
	return scans, rows.Err()
}

// Get returns a scan by id.
func (r *Repository) Get(ctx context.Context, id string) (Scan, error) {
	const q = `SELECT ` + scanColumns + ` FROM scans WHERE id = $1`
	s, err := scanScan(r.db.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Scan{}, ErrNotFound
	}
	if err != nil {
		return Scan{}, fmt.Errorf("get scan: %w", err)
	}
	return s, nil
}
