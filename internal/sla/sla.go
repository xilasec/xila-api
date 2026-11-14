// Package sla manages remediation SLAs: how many days a finding of each severity
// may stay open, set globally, per organization, or per project.
//
// The per-finding clock (sla_days / sla_due_at, paused during exceptions) is kept
// by the findings_sla trigger (migration 000027), so every code path that writes
// a status or severity gets it right without knowing about SLAs. This package
// owns the policies, re-applies them to existing findings when one changes, and
// runs the breach / due-soon sweep.
package sla

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
)

// ErrNotFound is returned when a policy's org or project does not exist.
var ErrNotFound = errors.New("organization or project not found")

// Scope names where an effective policy came from.
const (
	ScopeProject = "project"
	ScopeOrg     = "org"
	ScopeGlobal  = "global"
	ScopeDefault = "default" // nothing stored: the built-in 7/30/90/120 days
)

// MaxDays bounds a policy's windows (ten years) so a typo can't create a
// deadline nobody will ever see.
const MaxDays = 3650

// Days is the window per severity. nil means no SLA for that severity.
type Days struct {
	Critical *int `json:"critical_days"`
	High     *int `json:"high_days"`
	Medium   *int `json:"medium_days"`
	Low      *int `json:"low_days"`
	Info     *int `json:"info_days"`
}

// Validate checks every window is within 1..MaxDays.
func (d Days) Validate() error {
	for name, v := range map[string]*int{
		"critical_days": d.Critical, "high_days": d.High, "medium_days": d.Medium,
		"low_days": d.Low, "info_days": d.Info,
	} {
		if v != nil && (*v < 1 || *v > MaxDays) {
			return fmt.Errorf("%s must be between 1 and %d (or null for no SLA)", name, MaxDays)
		}
	}
	return nil
}

// Target identifies a policy's scope: a project, an org, or (both nil) global.
type Target struct {
	OrgID     *string
	ProjectID *string
}

// Global is the instance-wide target.
var Global = Target{}

// Policy is a stored SLA policy.
type Policy struct {
	OrgID     *string    `json:"org_id"`
	ProjectID *string    `json:"project_id"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	Days
}

// Effective is the policy in force for a target and where it came from. For a
// project while criticality scaling is on, Applied holds the windows its
// findings actually get (the policy scaled by Criticality's factor).
type Effective struct {
	Scope string `json:"scope"`
	Days
	Criticality string `json:"criticality,omitempty"`
	Applied     *Days  `json:"applied,omitempty"`
}

// Repository stores SLA policies and re-applies them to findings.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

const policyColumns = `org_id, project_id, updated_at, critical_days, high_days, medium_days, low_days, info_days`

func scanPolicy(row pgx.Row) (Policy, error) {
	var p Policy
	err := row.Scan(&p.OrgID, &p.ProjectID, &p.UpdatedAt, &p.Critical, &p.High, &p.Medium, &p.Low, &p.Info)
	return p, err
}

// targetWhere matches exactly one scope's row.
const targetWhere = `org_id IS NOT DISTINCT FROM $1 AND project_id IS NOT DISTINCT FROM $2`

// Get returns the policy stored for exactly this target, if any.
func (r *Repository) Get(ctx context.Context, t Target) (Policy, bool, error) {
	p, err := scanPolicy(r.db.QueryRow(ctx,
		`SELECT `+policyColumns+` FROM sla_policies WHERE `+targetWhere, t.OrgID, t.ProjectID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, false, nil
	}
	if err != nil {
		return Policy{}, false, fmt.Errorf("get sla policy: %w", err)
	}
	return p, true, nil
}

// EffectiveFor returns the policy in force for a target: its own if stored,
// else the nearest enclosing scope (project → org → global → built-in default).
func (r *Repository) EffectiveFor(ctx context.Context, t Target) (Effective, error) {
	var (
		e   Effective
		err error
	)
	const cols = `scope, critical_days, high_days, medium_days, low_days, info_days`
	scan := func(row pgx.Row) error {
		return row.Scan(&e.Scope, &e.Critical, &e.High, &e.Medium, &e.Low, &e.Info)
	}
	switch {
	case t.ProjectID != nil:
		err = scan(r.db.QueryRow(ctx, `SELECT `+cols+` FROM sla_policy_for($1)`, *t.ProjectID))
		if err == nil {
			err = r.applied(ctx, *t.ProjectID, &e)
		}
	case t.OrgID != nil:
		if p, ok, gerr := r.Get(ctx, t); gerr != nil {
			return Effective{}, gerr
		} else if ok {
			return Effective{Scope: ScopeOrg, Days: p.Days}, nil
		}
		// No org policy: the org inherits whatever a project without one would.
		err = scan(r.db.QueryRow(ctx, `SELECT `+cols+` FROM sla_policy_for(NULL)`))
	default:
		err = scan(r.db.QueryRow(ctx, `SELECT `+cols+` FROM sla_policy_for(NULL)`))
	}
	if err != nil {
		return Effective{}, fmt.Errorf("effective sla policy: %w", err)
	}
	return e, nil
}

// applied fills e.Applied / e.Criticality for a project when criticality
// scaling is on (left empty otherwise: the policy days are what applies).
func (r *Repository) applied(ctx context.Context, projectID string, e *Effective) error {
	var (
		on   bool
		crit string
		d    Days
	)
	err := r.db.QueryRow(ctx, `
		SELECT COALESCE((SELECT scale_by_criticality FROM sla_settings), false), p.business_criticality,
		       sla_scaled_days($2, p.business_criticality), sla_scaled_days($3, p.business_criticality),
		       sla_scaled_days($4, p.business_criticality), sla_scaled_days($5, p.business_criticality),
		       sla_scaled_days($6, p.business_criticality)
		FROM projects p WHERE p.id = $1`,
		projectID, e.Critical, e.High, e.Medium, e.Low, e.Info).
		Scan(&on, &crit, &d.Critical, &d.High, &d.Medium, &d.Low, &d.Info)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("scaled sla policy: %w", err)
	}
	if on {
		e.Criticality, e.Applied = crit, &d
	}
	return nil
}

// Put stores the policy for a target and re-applies the result to the findings
// it governs, in one transaction — a policy that's saved but not applied would
// show deadlines nobody is held to.
func (r *Repository) Put(ctx context.Context, t Target, d Days) (Policy, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Policy{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	args := []any{t.OrgID, t.ProjectID, d.Critical, d.High, d.Medium, d.Low, d.Info}
	p, err := scanPolicy(tx.QueryRow(ctx, `
		UPDATE sla_policies SET critical_days=$3, high_days=$4, medium_days=$5, low_days=$6, info_days=$7, updated_at=now()
		WHERE `+targetWhere+` RETURNING `+policyColumns, args...))
	if errors.Is(err, pgx.ErrNoRows) {
		p, err = scanPolicy(tx.QueryRow(ctx, `
			INSERT INTO sla_policies (org_id, project_id, critical_days, high_days, medium_days, low_days, info_days)
			VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING `+policyColumns, args...))
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("put sla policy: %w", err)
	}
	if err := reapply(ctx, tx, t); err != nil {
		return Policy{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Policy{}, fmt.Errorf("commit: %w", err)
	}
	return p, nil
}

// Delete removes a target's policy (it then inherits the enclosing scope) and
// re-applies the inherited one to its findings.
func (r *Repository) Delete(ctx context.Context, t Target) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	if _, err := tx.Exec(ctx, `DELETE FROM sla_policies WHERE `+targetWhere, t.OrgID, t.ProjectID); err != nil {
		return fmt.Errorf("delete sla policy: %w", err)
	}
	if err := reapply(ctx, tx, t); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// reapply re-resolves sla_days for every finding the target governs; the
// findings_sla trigger then recomputes each deadline. It runs one statement per
// project so a global change on a large instance stays under the per-statement
// timeout, and writes only rows whose window actually changed.
func reapply(ctx context.Context, tx pgx.Tx, t Target) error {
	var projectIDs []string
	switch {
	case t.ProjectID != nil:
		projectIDs = []string{*t.ProjectID}
	default:
		rows, err := tx.Query(ctx, `
			SELECT DISTINCT f.project_id FROM findings f
			JOIN projects p ON p.id = f.project_id
			JOIN teams tm ON tm.id = p.team_id
			WHERE $1::uuid IS NULL OR tm.org_id = $1`, t.OrgID)
		if err != nil {
			return fmt.Errorf("sla reapply scope: %w", err)
		}
		projectIDs, err = pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return fmt.Errorf("sla reapply scope: %w", err)
		}
	}
	const q = `
		UPDATE findings f SET sla_days = d.days
		FROM (SELECT id, sla_days_for(project_id, severity) AS days FROM findings WHERE project_id = $1) d
		WHERE f.id = d.id AND f.sla_days IS DISTINCT FROM d.days`
	for _, pid := range projectIDs {
		if _, err := tx.Exec(ctx, q, pid); err != nil {
			return fmt.Errorf("sla reapply: %w", err)
		}
	}
	return nil
}

// Hit is one finding a sweep is alerting about.
type Hit struct {
	FindingID   string
	ProjectID   string
	ProjectName string
	Severity    string
	Title       string
	DueAt       time.Time
}

// MarkBreached returns live findings that are past their deadline and haven't
// been alerted for this deadline yet, recording that they now have. Keyed on
// the deadline itself, so a finding whose deadline moves (exception paused it,
// severity changed) is alerted again when it breaches the new one — and never
// twice for the same one.
func (r *Repository) MarkBreached(ctx context.Context) ([]Hit, error) {
	return r.mark(ctx, `
		UPDATE findings f SET sla_notified_due = f.sla_due_at
		FROM projects p
		WHERE p.id = f.project_id
		  AND f.status IN ('open', 'confirmed') AND f.duplicate_of IS NULL
		  AND f.version_id IN (SELECT id FROM project_versions WHERE is_default)
		  AND`+archive.Finding("f")+`
		  AND f.sla_due_at < now()
		  AND f.sla_notified_due IS DISTINCT FROM f.sla_due_at
		RETURNING f.id, f.project_id, p.name, f.severity, f.title, f.sla_due_at`)
}

// MarkDueSoon is MarkBreached for findings entering the last fraction of their
// window (not yet breached).
func (r *Repository) MarkDueSoon(ctx context.Context, fraction float64) ([]Hit, error) {
	return r.mark(ctx, `
		UPDATE findings f SET sla_warned_due = f.sla_due_at
		FROM projects p
		WHERE p.id = f.project_id
		  AND f.status IN ('open', 'confirmed') AND f.duplicate_of IS NULL
		  AND f.version_id IN (SELECT id FROM project_versions WHERE is_default)
		  AND`+archive.Finding("f")+`
		  AND f.sla_due_at >= now()
		  AND f.sla_due_at - now() <= make_interval(days => f.sla_days) * $1
		  AND f.sla_warned_due IS DISTINCT FROM f.sla_due_at
		RETURNING f.id, f.project_id, p.name, f.severity, f.title, f.sla_due_at`, fraction)
}

func (r *Repository) mark(ctx context.Context, q string, args ...any) ([]Hit, error) {
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("sla sweep: %w", err)
	}
	defer rows.Close()
	hits := []Hit{}
	for rows.Next() {
		var h Hit
		if err := rows.Scan(&h.FindingID, &h.ProjectID, &h.ProjectName, &h.Severity, &h.Title, &h.DueAt); err != nil {
			return nil, fmt.Errorf("scan sla hit: %w", err)
		}
		hits = append(hits, h)
	}
	return hits, rows.Err()
}
