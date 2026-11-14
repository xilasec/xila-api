// Package engagement groups a project's security work the way DefectDojo does:
// an engagement is a time-boxed effort (a pentest, an audit, a CI/CD
// pipeline); the scans uploaded into it are its tests, and manual findings —
// what a person found, not a tool — are filed under it too. Findings stay the
// project's findings: the engagement is a view and a lineage, not a silo.
package engagement

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
)

// Errors.
var (
	ErrNotFound   = errors.New("engagement not found")
	ErrNoProject  = errors.New("project not found")
	ErrValidation = errors.New("invalid engagement")
)

// Kinds and statuses (DefectDojo's).
var (
	kinds    = []string{"interactive", "ci_cd"}
	statuses = []string{"not_started", "in_progress", "on_hold", "completed", "cancelled"}
)

// Engagement is one piece of security work on a project.
type Engagement struct {
	ID          string     `json:"id"`
	ProjectID   string     `json:"project_id"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`   // interactive | ci_cd
	Status      string     `json:"status"` // not_started | in_progress | on_hold | completed | cancelled
	Description string     `json:"description"`
	LeadID      *string    `json:"lead_id"`
	LeadEmail   *string    `json:"lead_email"`
	StartsOn    *string    `json:"starts_on"` // YYYY-MM-DD
	EndsOn      *string    `json:"ends_on"`
	CreatedBy   *string    `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	ArchivedAt  *time.Time `json:"archived_at"`
	ArchivedBy  *string    `json:"archived_by"`
	Stats       *Stats     `json:"stats,omitempty"`
	Scans       []ScanInfo `json:"scans,omitempty"`
}

// Stats summarises what an engagement found: its tests (scans) and the
// findings they reported (default listing rules: duplicates collapsed).
type Stats struct {
	Scans    int            `json:"scans"`
	Findings int            `json:"findings"`
	Open     map[string]int `json:"open"` // open findings by severity
}

// ScanInfo is one test of an engagement.
type ScanInfo struct {
	ID        string         `json:"id"`
	Scanner   string         `json:"scanner"`
	Status    string         `json:"status"`
	Branch    string         `json:"branch"`
	Summary   map[string]int `json:"summary"`
	CreatedAt time.Time      `json:"created_at"`
}

// Validate normalizes and checks e.
func (e *Engagement) Validate() error {
	e.Name = strings.TrimSpace(e.Name)
	if e.Name == "" || len(e.Name) > 200 {
		return fmt.Errorf("%w: name is required (≤ 200 characters)", ErrValidation)
	}
	if e.Kind == "" {
		e.Kind = "interactive"
	}
	if e.Status == "" {
		e.Status = "in_progress"
	}
	if !slices.Contains(kinds, e.Kind) {
		return fmt.Errorf("%w: kind must be interactive or ci_cd", ErrValidation)
	}
	if !slices.Contains(statuses, e.Status) {
		return fmt.Errorf("%w: status must be one of %s", ErrValidation, strings.Join(statuses, ", "))
	}
	var from, to time.Time
	for _, d := range []struct {
		p *string
		t *time.Time
	}{{e.StartsOn, &from}, {e.EndsOn, &to}} {
		if d.p == nil || *d.p == "" {
			continue
		}
		t, err := time.Parse(time.DateOnly, *d.p)
		if err != nil {
			return fmt.Errorf("%w: dates are YYYY-MM-DD", ErrValidation)
		}
		*d.t = t
	}
	if !from.IsZero() && !to.IsZero() && to.Before(from) {
		return fmt.Errorf("%w: ends_on is before starts_on", ErrValidation)
	}
	return nil
}

// Repository stores engagements.
type Repository struct{ db *pgxpool.Pool }

// NewRepository constructs the repository.
func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

const columns = `e.id, e.project_id, e.name, e.kind, e.status, e.description, e.lead_id,
	(SELECT email FROM users u WHERE u.id = e.lead_id), to_char(e.starts_on, 'YYYY-MM-DD'), to_char(e.ends_on, 'YYYY-MM-DD'),
	e.created_by, e.created_at, e.updated_at, e.archived_at, e.archived_by`

func scanEngagement(row pgx.Row) (Engagement, error) {
	var e Engagement
	err := row.Scan(&e.ID, &e.ProjectID, &e.Name, &e.Kind, &e.Status, &e.Description, &e.LeadID, &e.LeadEmail,
		&e.StartsOn, &e.EndsOn, &e.CreatedBy, &e.CreatedAt, &e.UpdatedAt, &e.ArchivedAt, &e.ArchivedBy)
	return e, err
}

func emptyNil(p *string) *string {
	if p == nil || *p == "" {
		return nil
	}
	return p
}

// Create inserts an engagement.
func (r *Repository) Create(ctx context.Context, e Engagement, actor string) (Engagement, error) {
	var id string
	err := r.db.QueryRow(ctx, `INSERT INTO engagements (project_id, name, kind, status, description, lead_id, starts_on, ends_on, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7::date, $8::date, NULLIF($9, '')::uuid) RETURNING id`,
		e.ProjectID, e.Name, e.Kind, e.Status, e.Description, emptyNil(e.LeadID), emptyNil(e.StartsOn), emptyNil(e.EndsOn), actor).Scan(&id)
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23503" {
		if strings.Contains(pgErr.ConstraintName, "lead") {
			return Engagement{}, fmt.Errorf("%w: lead_id is not a user", ErrValidation)
		}
		return Engagement{}, ErrNoProject
	}
	if err != nil {
		return Engagement{}, fmt.Errorf("insert engagement: %w", err)
	}
	return r.Get(ctx, id)
}

// Get returns an engagement with its stats and scans.
func (r *Repository) Get(ctx context.Context, id string) (Engagement, error) {
	e, err := scanEngagement(r.db.QueryRow(ctx, `SELECT `+columns+` FROM engagements e WHERE e.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Engagement{}, ErrNotFound
	}
	if err != nil {
		return Engagement{}, fmt.Errorf("get engagement: %w", err)
	}
	stats, err := r.stats(ctx, []string{id})
	if err != nil {
		return Engagement{}, err
	}
	e.Stats = stats[id]
	rows, err := r.db.Query(ctx, `SELECT id, scanner, status, branch, summary, created_at FROM scans
		WHERE engagement_id = $1 AND`+archive.Scan("")+` ORDER BY created_at DESC`, id)
	if err != nil {
		return Engagement{}, fmt.Errorf("engagement scans: %w", err)
	}
	defer rows.Close()
	e.Scans = []ScanInfo{}
	for rows.Next() {
		var s ScanInfo
		if err := rows.Scan(&s.ID, &s.Scanner, &s.Status, &s.Branch, &s.Summary, &s.CreatedAt); err != nil {
			return Engagement{}, err
		}
		e.Scans = append(e.Scans, s)
	}
	return e, rows.Err()
}

// List returns a project's engagements, newest first, with stats; archived
// lists the archived ones instead.
func (r *Repository) List(ctx context.Context, projectID string, archived bool) ([]Engagement, error) {
	rows, err := r.db.Query(ctx, `SELECT `+columns+` FROM engagements e WHERE e.project_id = $1 AND`+archive.Only(archive.Engagement("e"), archived)+`
		ORDER BY COALESCE(e.starts_on, e.created_at::date) DESC, e.created_at DESC`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list engagements: %w", err)
	}
	out := []Engagement{}
	var ids []string
	for rows.Next() {
		e, err := scanEngagement(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, e)
		ids = append(ids, e.ID)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	stats, err := r.stats(ctx, ids)
	if err != nil {
		return nil, err
	}
	for i := range out {
		out[i].Stats = stats[out[i].ID]
	}
	return out, nil
}

// stats counts each engagement's scans and the findings they reported (first
// or last seen in one of its scans; duplicates collapsed).
func (r *Repository) stats(ctx context.Context, ids []string) (map[string]*Stats, error) {
	out := make(map[string]*Stats, len(ids))
	for _, id := range ids {
		out[id] = &Stats{Open: map[string]int{}}
	}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := r.db.Query(ctx, `
		SELECT s.engagement_id, count(DISTINCT s.id)::int FROM scans s WHERE s.engagement_id = ANY($1) AND`+archive.Scan("s")+` GROUP BY 1`, ids)
	if err != nil {
		return nil, fmt.Errorf("engagement scan counts: %w", err)
	}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			rows.Close()
			return nil, err
		}
		out[id].Scans = n
	}
	rows.Close()
	rows, err = r.db.Query(ctx, `
		SELECT s.engagement_id, f.severity, f.status IN ('open', 'confirmed'), count(DISTINCT f.id)::int
		FROM findings f JOIN scans s ON s.id IN (f.first_scan_id, f.last_scan_id)
		WHERE s.engagement_id = ANY($1) AND f.duplicate_of IS NULL AND`+archive.Scan("s")+` AND`+archive.Finding("f")+`
		GROUP BY 1, 2, 3`, ids)
	if err != nil {
		return nil, fmt.Errorf("engagement finding counts: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, sev string
		var open bool
		var n int
		if err := rows.Scan(&id, &sev, &open, &n); err != nil {
			return nil, err
		}
		out[id].Findings += n
		if open {
			out[id].Open[sev] += n
		}
	}
	return out, rows.Err()
}

// Update rewrites an engagement's editable fields.
func (r *Repository) Update(ctx context.Context, e Engagement) (Engagement, error) {
	tag, err := r.db.Exec(ctx, `UPDATE engagements SET name = $2, kind = $3, status = $4, description = $5,
			lead_id = $6, starts_on = $7::date, ends_on = $8::date, updated_at = now()
		WHERE id = $1`, e.ID, e.Name, e.Kind, e.Status, e.Description, emptyNil(e.LeadID), emptyNil(e.StartsOn), emptyNil(e.EndsOn))
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23503" {
		return Engagement{}, fmt.Errorf("%w: lead_id is not a user", ErrValidation)
	}
	if err != nil {
		return Engagement{}, fmt.Errorf("update engagement: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return Engagement{}, ErrNotFound
	}
	return r.Get(ctx, e.ID)
}
