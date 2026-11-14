// Package policy is the component policy engine (Dependency-Track parity):
// admin-defined rules over SBOM components — security, license and operational
// facts — whose violations become findings (scanner "policy"), so triage,
// gates, SLA and alerts apply to them unchanged, and a violation that stops
// applying auto-closes.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/domain"
)

// Scanner is the source name recorded on violation findings.
const Scanner = "policy"

// Domain errors.
var (
	ErrNotFound  = errors.New("policy not found")
	ErrDuplicate = errors.New("a policy with this name already exists")
	ErrNoProject = errors.New("project not found")
)

// Combine is how a policy's conditions combine into a violation.
type Combine string

// Combinators.
const (
	CombineAny Combine = "any" // one matching condition is a violation
	CombineAll Combine = "all" // every condition must match
)

// State is how serious a violation is; it sets the finding's severity.
type State string

// Violation states.
const (
	StateFail State = "fail" // high
	StateWarn State = "warn" // medium
	StateInfo State = "info" // low
)

// Severity is the finding severity a violation in state s gets.
func (s State) Severity() domain.Severity {
	switch s {
	case StateFail:
		return domain.SeverityHigh
	case StateWarn:
		return domain.SeverityMedium
	}
	return domain.SeverityLow
}

// Scope is where a policy applies.
type Scope string

// Scopes.
const (
	ScopeGlobal   Scope = "global"   // every project
	ScopeProjects Scope = "projects" // only ProjectIDs
)

// Versions is which project versions a policy judges.
type Versions string

// Version scopes.
const (
	VersionsAll     Versions = "all"     // every version with a current snapshot
	VersionsDefault Versions = "default" // the project's default version only
)

// Policy is a named set of conditions over components.
type Policy struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Description    string   `json:"description"`
	Enabled        bool     `json:"enabled"`
	Operator       Combine  `json:"operator"`
	ViolationState State    `json:"violation_state"`
	Scope          Scope    `json:"scope"`
	ProjectIDs     []string `json:"project_ids"`
	// IncludeTags narrows the scope to projects with any of these tags (empty =
	// no narrowing); ExcludeTags drops projects with any of them.
	IncludeTags []string    `json:"include_tags"`
	ExcludeTags []string    `json:"exclude_tags"`
	Versions    Versions    `json:"versions"`
	Conditions  []Condition `json:"conditions"`
	CreatedBy   *string     `json:"created_by"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
	// Violations is how many open violations the policy has on the default
	// versions the caller can see (set by list endpoints).
	Violations *int `json:"violations,omitempty"`
}

// Draft is a policy with the API's defaults (enabled, any, fail, global, all
// versions) for a request body to override.
func Draft() Policy {
	return Policy{Enabled: true, Operator: CombineAny, ViolationState: StateFail,
		Scope: ScopeGlobal, Versions: VersionsAll, ProjectIDs: []string{}, IncludeTags: []string{}, ExcludeTags: []string{},
		Conditions: []Condition{}}
}

// AppliesTo reports whether p is in force for a project with these tags.
func (p Policy) AppliesTo(projectID string, tags []string) bool {
	return p.Enabled && p.covers(projectID, tags)
}

// covers is the scope alone (enabled or not): the scope covers the project,
// the project has an included tag (if any are set) and no excluded one.
// inForceSQL is its SQL twin — change them together.
func (p Policy) covers(projectID string, tags []string) bool {
	if p.Scope != ScopeGlobal && !slices.Contains(p.ProjectIDs, projectID) {
		return false
	}
	if len(p.IncludeTags) > 0 && !slices.ContainsFunc(tags, func(t string) bool { return slices.Contains(p.IncludeTags, t) }) {
		return false
	}
	return !slices.ContainsFunc(tags, func(t string) bool { return slices.Contains(p.ExcludeTags, t) })
}

// Repository provides access to policies and policy_projects, and the policy
// findings the engine maintains.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

const policyColumns = `p.id, p.name, p.description, p.enabled, p.operator, p.violation_state, p.scope,
	p.versions, p.conditions, p.created_by, p.created_at, p.updated_at, p.include_tags, p.exclude_tags,
	COALESCE((SELECT array_agg(pp.project_id::text ORDER BY pp.project_id) FROM policy_projects pp WHERE pp.policy_id = p.id), '{}')`

func scanPolicy(row pgx.Row) (Policy, error) {
	var (
		p    Policy
		cond []byte
	)
	if err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &p.Operator, &p.ViolationState, &p.Scope,
		&p.Versions, &cond, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt, &p.IncludeTags, &p.ExcludeTags, &p.ProjectIDs); err != nil {
		return Policy{}, err
	}
	if err := json.Unmarshal(cond, &p.Conditions); err != nil {
		return Policy{}, fmt.Errorf("decode policy conditions: %w", err)
	}
	if p.Conditions == nil {
		p.Conditions = []Condition{}
	}
	return p, nil
}

func (r *Repository) list(ctx context.Context, where string, args ...any) ([]Policy, error) {
	rows, err := r.db.Query(ctx, `SELECT `+policyColumns+` FROM policies p `+where+` ORDER BY p.name`, args...)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()
	out := []Policy{}
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// List returns every policy, by name.
func (r *Repository) List(ctx context.Context) ([]Policy, error) {
	return r.list(ctx, "")
}

// Enabled returns every enabled policy, by name.
func (r *Repository) Enabled(ctx context.Context) ([]Policy, error) {
	return r.list(ctx, "WHERE p.enabled")
}

// inForceSQL is Policy.covers in SQL, for any project of the set $1.
const inForceSQL = `EXISTS (SELECT 1 FROM projects pr WHERE pr.id = ANY($1::uuid[])
	AND (p.scope = 'global'
		OR EXISTS (SELECT 1 FROM policy_projects pp WHERE pp.policy_id = p.id AND pp.project_id = pr.id))
	AND (cardinality(p.include_tags) = 0 OR p.include_tags && pr.tags)
	AND NOT (p.exclude_tags && pr.tags))`

// InForce returns the enabled policies that apply to any of projectIDs (one
// project, or a project and its descendants).
func (r *Repository) InForce(ctx context.Context, projectIDs []string) ([]Policy, error) {
	return r.list(ctx, `WHERE p.enabled AND `+inForceSQL, projectIDs)
}

// ProjectTags returns each project's tags (projects that don't exist are absent).
func (r *Repository) ProjectTags(ctx context.Context, ids []string) (map[string][]string, error) {
	rows, err := r.db.Query(ctx, `SELECT id::text, tags FROM projects WHERE id = ANY($1::uuid[])`, ids)
	if err != nil {
		return nil, fmt.Errorf("project tags: %w", err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var id string
		var tags []string
		if err := rows.Scan(&id, &tags); err != nil {
			return nil, err
		}
		out[id] = tags
	}
	return out, rows.Err()
}

// Get returns one policy.
func (r *Repository) Get(ctx context.Context, id string) (Policy, error) {
	p, err := scanPolicy(r.db.QueryRow(ctx, `SELECT `+policyColumns+` FROM policies p WHERE p.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("get policy: %w", err)
	}
	return p, nil
}

// Create stores a validated policy; actor ("" for none) is its author.
func (r *Repository) Create(ctx context.Context, p Policy, actor string) (Policy, error) {
	return r.write(ctx, func(tx pgx.Tx, cond []byte) (string, error) {
		var id string
		err := tx.QueryRow(ctx, `
			INSERT INTO policies (name, description, enabled, operator, violation_state, scope, versions, conditions, created_by,
			                      include_tags, exclude_tags)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, '')::uuid, $10, $11) RETURNING id`,
			p.Name, p.Description, p.Enabled, p.Operator, p.ViolationState, p.Scope, p.Versions, cond, actor,
			p.IncludeTags, p.ExcludeTags).Scan(&id)
		return id, err
	}, p)
}

// Update replaces a policy.
func (r *Repository) Update(ctx context.Context, p Policy) (Policy, error) {
	return r.write(ctx, func(tx pgx.Tx, cond []byte) (string, error) {
		tag, err := tx.Exec(ctx, `
			UPDATE policies SET name = $2, description = $3, enabled = $4, operator = $5, violation_state = $6,
			       scope = $7, versions = $8, conditions = $9, include_tags = $10, exclude_tags = $11, updated_at = now()
			WHERE id = $1`,
			p.ID, p.Name, p.Description, p.Enabled, p.Operator, p.ViolationState, p.Scope, p.Versions, cond,
			p.IncludeTags, p.ExcludeTags)
		if err == nil && tag.RowsAffected() == 0 {
			err = ErrNotFound
		}
		return p.ID, err
	}, p)
}

// write runs a create/update and replaces the policy's project set, atomically.
func (r *Repository) write(ctx context.Context, upsert func(pgx.Tx, []byte) (string, error), p Policy) (Policy, error) {
	cond, err := json.Marshal(p.Conditions)
	if err != nil {
		return Policy{}, fmt.Errorf("encode policy conditions: %w", err)
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Policy{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	id, err := upsert(tx, cond)
	if err != nil {
		return Policy{}, writeErr(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM policy_projects WHERE policy_id = $1`, id); err != nil {
		return Policy{}, fmt.Errorf("clear policy projects: %w", err)
	}
	projects := p.ProjectIDs
	if p.Scope == ScopeGlobal {
		projects = nil
	}
	if len(projects) > 0 {
		if _, err := tx.Exec(ctx, `INSERT INTO policy_projects (policy_id, project_id)
			SELECT $1, unnest($2::uuid[]) ON CONFLICT DO NOTHING`, id, projects); err != nil {
			return Policy{}, writeErr(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Policy{}, fmt.Errorf("commit: %w", err)
	}
	return r.Get(ctx, id)
}

func writeErr(err error) error {
	var pg *pgconn.PgError
	switch {
	case errors.Is(err, ErrNotFound):
		return err
	case errors.As(err, &pg) && pg.Code == "23505":
		return ErrDuplicate
	case errors.As(err, &pg) && pg.Code == "23503":
		return ErrNoProject
	}
	return fmt.Errorf("write policy: %w", err)
}

// Delete removes a policy. Its findings stay, and are closed by the
// re-evaluation that follows.
func (r *Repository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM policies WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ViolationCounts returns open violations per policy id on default versions,
// optionally only in projectIDs (nil = every project). Cross-tool duplicates
// don't count, like every finding metric.
func (r *Repository) ViolationCounts(ctx context.Context, projectIDs []string) (map[string]int, error) {
	rows, err := r.db.Query(ctx, `
		SELECT rule_id, count(*)::int FROM findings
		WHERE scanner = 'policy' AND status IN ('open', 'confirmed') AND duplicate_of IS NULL
		  AND version_id IN (SELECT id FROM project_versions WHERE is_default)
		  AND`+archive.Finding("")+`
		  AND ($1::uuid[] IS NULL OR project_id = ANY($1))
		GROUP BY rule_id`, projectIDs)
	if err != nil {
		return nil, fmt.Errorf("policy violation counts: %w", err)
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var (
			id string
			n  int
		)
		if err := rows.Scan(&id, &n); err != nil {
			return nil, fmt.Errorf("scan violation count: %w", err)
		}
		out[id] = n
	}
	return out, rows.Err()
}

// target is one project version evaluation applies findings to.
type target struct {
	VersionID string
	IsDefault bool
	// HasOpen: the version has open policy findings (which an empty result
	// must close); without them and without violations it can be skipped.
	HasOpen bool
}

// Targets returns a project's versions to evaluate: those with an SBOM, plus
// any still carrying open policy findings (so they get closed).
func (r *Repository) Targets(ctx context.Context, projectID, versionID string) ([]target, error) {
	rows, err := r.db.Query(ctx, `
		SELECT pv.id, pv.is_default,
		       EXISTS (SELECT 1 FROM findings f WHERE f.version_id = pv.id AND f.scanner = 'policy'
		               AND f.status IN ('open', 'confirmed')) AS has_open
		FROM project_versions pv
		WHERE pv.project_id = $1 AND ($2::uuid IS NULL OR pv.id = $2)
		  AND (EXISTS (SELECT 1 FROM sboms s WHERE s.version_id = pv.id)
		    OR EXISTS (SELECT 1 FROM findings f WHERE f.version_id = pv.id AND f.scanner = 'policy'
		               AND f.status IN ('open', 'confirmed')))
		ORDER BY pv.id`, projectID, nilIfEmpty(versionID))
	if err != nil {
		return nil, fmt.Errorf("policy targets: %w", err)
	}
	defer rows.Close()
	var out []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.VersionID, &t.IsDefault, &t.HasOpen); err != nil {
			return nil, fmt.Errorf("scan policy target: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Projects returns the projects evaluation covers: those with an SBOM or open
// policy findings, optionally only within ids (nil = all).
func (r *Repository) Projects(ctx context.Context, ids []string) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id FROM projects p
		WHERE`+archive.Project("p")+` AND ($1::uuid[] IS NULL OR p.id = ANY($1))
		  AND (EXISTS (SELECT 1 FROM sboms s WHERE s.project_id = p.id)
		    OR EXISTS (SELECT 1 FROM findings f WHERE f.project_id = p.id AND f.scanner = 'policy'
		               AND f.status IN ('open', 'confirmed')))
		ORDER BY id`, ids)
	if err != nil {
		return nil, fmt.Errorf("policy projects: %w", err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("policy projects: %w", err)
	}
	return out, nil
}

// ProjectExists reports whether a project exists.
func (r *Repository) ProjectExists(ctx context.Context, id string) (bool, error) {
	var ok bool
	err := r.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM projects WHERE id = $1)`, id).Scan(&ok)
	if err != nil {
		return false, fmt.Errorf("project exists: %w", err)
	}
	return ok, nil
}

// lockNamespace keys the per-project advisory lock policy evaluation holds
// (1 dedup, 2 vulnmatch, 3 connectors).
const lockNamespace = 4

// LockProject serializes policy evaluation of one project across goroutines
// and instances, so two runs can't apply stale violation sets in the wrong
// order. Everything under it is local database work. The returned func
// releases it.
func (r *Repository) LockProject(ctx context.Context, projectID string) (func(), error) {
	conn, err := r.db.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire: %w", err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1, hashtext($2))`, lockNamespace, projectID); err != nil {
		conn.Release()
		return nil, fmt.Errorf("policy lock: %w", err)
	}
	return func() {
		// Session locks outlive the request context, so release with a fresh one.
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1, hashtext($2))`, lockNamespace, projectID)
		conn.Release()
	}, nil
}

// NewViolation is a violation a scan introduced and that is still open.
type NewViolation struct {
	PolicyID string
	Title    string
}

// NewViolations returns the violations first seen in scanID that are still
// open (auto-triage may already have dismissed some).
func (r *Repository) NewViolations(ctx context.Context, scanID string) ([]NewViolation, error) {
	rows, err := r.db.Query(ctx, `
		SELECT rule_id, title FROM findings
		WHERE first_scan_id = $1 AND scanner = 'policy' AND status IN ('open', 'confirmed') AND duplicate_of IS NULL
		ORDER BY title`, scanID)
	if err != nil {
		return nil, fmt.Errorf("new policy violations: %w", err)
	}
	defer rows.Close()
	var out []NewViolation
	for rows.Next() {
		var v NewViolation
		if err := rows.Scan(&v.PolicyID, &v.Title); err != nil {
			return nil, fmt.Errorf("scan new violation: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
