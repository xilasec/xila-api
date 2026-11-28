// Package vulnpolicy implements vulnerability policies (Dependency-Track 5
// parity): admin-managed rules with a CEL condition over a component +
// vulnerability pair that set an analysis state and/or a rating override
// atomically, with a priority, a validity window, a project/tag scope and an
// apply/log-only mode.
//
// A policy's effect is tracked (vuln_policy_matches), so a later evaluation
// can tell "still this policy's doing" from "a person changed it since" (and
// leave it alone) and revert exactly what it set when the policy stops
// matching, is disabled, or falls outside its validity window — the same way
// an expired triage exception reopens a finding. See Service.reconcile.
package vulnpolicy

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

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/expr"
	"github.com/xilasec/xila-api/internal/triage"
)

// Domain errors.
var (
	ErrNotFound  = errors.New("vulnerability policy not found")
	ErrDuplicate = errors.New("a vulnerability policy with that name already exists")
	ErrNoProject = errors.New("project not found")
)

// AnalysisState is the Dependency-Track-style verdict a policy's analysis
// sets. "" (no Analysis) means the policy carries no analysis action.
type AnalysisState string

// States.
const (
	AnalysisNotAffected   AnalysisState = "not_affected"
	AnalysisFalsePositive AnalysisState = "false_positive"
	AnalysisExploitable   AnalysisState = "exploitable"
	AnalysisInTriage      AnalysisState = "in_triage"
)

var analysisStates = []AnalysisState{AnalysisNotAffected, AnalysisFalsePositive, AnalysisExploitable, AnalysisInTriage}

// Valid reports whether s is a known analysis state.
func (s AnalysisState) Valid() bool { return slices.Contains(analysisStates, s) }

// Status maps the analysis state onto a finding lifecycle status. not_affected
// and false_positive both land on domain.FindingFalsePositive — Dependency-Track
// keeps them distinct justifications of the same outcome, like VEX's
// not_affected/fixed collapsing the same way (internal/vex). exploitable maps
// to confirmed. in_triage (and "") set no status: ok is false, so a policy
// that only wants to flag "still being looked at" or carries a rating-only
// action never touches lifecycle state.
func (s AnalysisState) Status() (domain.FindingStatus, bool) {
	switch s {
	case AnalysisNotAffected, AnalysisFalsePositive:
		return domain.FindingFalsePositive, true
	case AnalysisExploitable:
		return domain.FindingConfirmed, true
	}
	return "", false
}

// Analysis is the verdict a policy records on a matching finding.
type Analysis struct {
	State         AnalysisState `json:"state"`
	Justification string        `json:"justification"`
	Details       string        `json:"details"`
}

// Rating is a severity/CVSS override a policy applies to a matching finding.
// Severity is required; CVSSVector/CVSSScore are optional detail kept for
// display and the bundle — only Severity is currently enforced on the
// finding (internal/enrichment owns CVSS provenance; a policy never
// overwrites a scanner- or NVD-sourced CVSS).
type Rating struct {
	Severity   domain.Severity `json:"severity"`
	CVSSVector string          `json:"cvss_vector"`
	CVSSScore  *float64        `json:"cvss_score"`
}

// Scope is where a policy applies.
type Scope string

// Scopes.
const (
	ScopeGlobal   Scope = "global"
	ScopeProjects Scope = "projects"
	ScopeTag      Scope = "tag"
)

var scopes = []Scope{ScopeGlobal, ScopeProjects, ScopeTag}

// Valid reports whether s is a known scope.
func (s Scope) Valid() bool { return slices.Contains(scopes, s) }

// Mode is whether a policy's match is applied or only recorded.
type Mode string

// Modes.
const (
	ModeApply Mode = "apply"
	ModeLog   Mode = "log"
)

var modes = []Mode{ModeApply, ModeLog}

// Valid reports whether m is a known mode.
func (m Mode) Valid() bool { return slices.Contains(modes, m) }

// Policy is a named CEL condition over a component + vulnerability pair,
// with the verdict it sets when it matches.
type Policy struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	// Condition is the CEL expression over Schema's component/vulnerability/
	// project facts (expression.go). Empty never matches.
	Condition string `json:"condition"`
	// Priority: the highest-priority policy whose condition matches wins when
	// several do (Elect). Ties break by created_at, oldest first.
	Priority int `json:"priority"`
	// Analysis / Rating: at least one must be set (Validate enforces it).
	Analysis *Analysis `json:"analysis"`
	Rating   *Rating   `json:"rating"`
	// ValidFrom/ValidUntil: nil = unbounded on that side. Outside the window
	// the policy doesn't apply, and AppliesNow reports so — reconcile reverts
	// what it previously set, exactly like an expired triage exception.
	ValidFrom  *time.Time `json:"valid_from"`
	ValidUntil *time.Time `json:"valid_until"`
	Scope      Scope      `json:"scope"`
	ProjectIDs []string   `json:"project_ids"`
	// OwnerProjectID is set on a policy a project owner made for their own
	// project (M13 13.10, read-only through the API): its scope is that
	// project alone and the GitOps bundle never replaces it.
	OwnerProjectID *string   `json:"owner_project_id"`
	Tag            string    `json:"tag"`
	Mode           Mode      `json:"mode"`
	CreatedBy      string    `json:"created_by"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`

	prg    *expr.Program
	broken bool
}

// Draft is a policy with the API's defaults for a request body to override.
func Draft() Policy {
	return Policy{Enabled: true, Scope: ScopeGlobal, Mode: ModeApply}
}

// compile loads the condition (already validated when saved — see Validate)
// so a fact that has since disappeared makes it not match rather than fail
// to load (expr.Load's contract).
func (p *Policy) compile(vars []string) {
	p.prg, p.broken = nil, false
	if strings.TrimSpace(p.Condition) == "" {
		p.broken = true
		return
	}
	prg, err := expr.Load(vars, p.Condition)
	if err != nil {
		p.broken = true
		return
	}
	p.prg = prg
}

// Validate checks p's shape and compiles its condition against schema (dry
// run: a misspelled fact is refused at save time).
func (p *Policy) Validate(schema expr.Schema) error {
	if strings.TrimSpace(p.Name) == "" {
		return &ValidationError{"name is required"}
	}
	if !p.Scope.Valid() {
		return &ValidationError{"invalid scope"}
	}
	if !p.Mode.Valid() {
		return &ValidationError{"invalid mode"}
	}
	if p.Scope == ScopeProjects && len(p.ProjectIDs) == 0 {
		return &ValidationError{"scope \"projects\" requires at least one project_id"}
	}
	if p.Scope == ScopeTag && strings.TrimSpace(p.Tag) == "" {
		return &ValidationError{"scope \"tag\" requires a tag"}
	}
	if p.Scope != ScopeProjects {
		p.ProjectIDs = nil
	}
	if p.Scope != ScopeTag {
		p.Tag = ""
	}
	if p.ValidFrom != nil && p.ValidUntil != nil && !p.ValidFrom.Before(*p.ValidUntil) {
		return &ValidationError{"valid_from must be before valid_until"}
	}
	if p.Analysis == nil && p.Rating == nil {
		return &ValidationError{"a policy needs an analysis, a rating, or both"}
	}
	if p.Analysis != nil && !p.Analysis.State.Valid() {
		return &ValidationError{"invalid analysis state"}
	}
	if p.Rating != nil && !p.Rating.Severity.Valid() {
		return &ValidationError{"rating requires a valid severity"}
	}
	if strings.TrimSpace(p.Condition) == "" {
		return &ValidationError{"condition is required"}
	}
	if _, err := expr.Compile(schema, p.Condition); err != nil {
		return &ValidationError{err.Error()}
	}
	p.compile(schema.Vars)
	return nil
}

// ValidationError is a policy the API must reject (400).
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

// AppliesNow reports whether p is in force right now for a project: enabled,
// inside its validity window, and in scope.
func (p Policy) AppliesNow(now time.Time, projectID string, facts ProjectFacts) bool {
	if !p.Enabled {
		return false
	}
	if p.ValidFrom != nil && now.Before(*p.ValidFrom) {
		return false
	}
	if p.ValidUntil != nil && !now.Before(*p.ValidUntil) {
		return false
	}
	return p.covers(projectID, facts)
}

// covers is the scope alone, ignoring enabled/time. A project that opted out
// of global policies (facts.SkipsGlobal) is outside every global one; a
// policy an admin aimed at it by id or tag still applies.
func (p Policy) covers(projectID string, facts ProjectFacts) bool {
	switch p.Scope {
	case ScopeProjects:
		return slices.Contains(p.ProjectIDs, projectID)
	case ScopeTag:
		return slices.Contains(facts.Tags, p.Tag)
	default:
		return !facts.SkipsGlobal
	}
}

// Match evaluates the compiled condition against doc. A broken/uncompiled
// policy (deleted/invalid since saved) never matches.
func (p Policy) Match(ctx context.Context, doc map[string]any) bool {
	if p.broken || p.prg == nil {
		return false
	}
	return p.prg.Match(ctx, doc)
}

// Elect returns the highest-priority apply-mode policy that applies now and
// whose condition matches doc, among policies (ties break oldest-first, so
// election is deterministic). Log-mode policies never win — they record
// nothing and never block an apply-mode policy underneath them. Pure and
// side-effect free: the unit-tested core of "priority resolution".
func Elect(ctx context.Context, policies []Policy, now time.Time, projectID string, facts ProjectFacts, doc map[string]any) (Policy, bool) {
	var best Policy
	found := false
	for _, p := range policies {
		if p.Mode != ModeApply {
			continue
		}
		if !p.AppliesNow(now, projectID, facts) {
			continue
		}
		if !p.Match(ctx, doc) {
			continue
		}
		if !found || p.Priority > best.Priority || (p.Priority == best.Priority && p.CreatedAt.Before(best.CreatedAt)) {
			best, found = p, true
		}
	}
	return best, found
}

// Repository provides access to vuln_policies, their project scope, and the
// per-finding match tracking that makes a policy's effect reversible.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

const policyColumns = `p.id, p.name, p.description, p.enabled, p.condition, p.priority,
	p.analysis_state, p.analysis_justification, p.analysis_details,
	p.rating_severity, p.rating_cvss_vector, p.rating_cvss_score,
	p.valid_from, p.valid_until, p.scope, p.tag, p.mode, p.created_by, p.created_at, p.updated_at,
	p.owner_project_id::text,
	COALESCE((SELECT array_agg(pp.project_id::text ORDER BY pp.project_id) FROM vuln_policy_projects pp WHERE pp.policy_id = p.id), '{}')`

func scanPolicy(row pgx.Row) (Policy, error) {
	var (
		p                              Policy
		analysisState, severity        string
		justification, details, vector string
		score                          *float64
	)
	if err := row.Scan(&p.ID, &p.Name, &p.Description, &p.Enabled, &p.Condition, &p.Priority,
		&analysisState, &justification, &details, &severity, &vector, &score,
		&p.ValidFrom, &p.ValidUntil, &p.Scope, &p.Tag, &p.Mode, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
		&p.OwnerProjectID, &p.ProjectIDs); err != nil {
		return Policy{}, err
	}
	if analysisState != "" {
		p.Analysis = &Analysis{State: AnalysisState(analysisState), Justification: justification, Details: details}
	}
	if severity != "" {
		p.Rating = &Rating{Severity: domain.Severity(severity), CVSSVector: vector, CVSSScore: score}
	}
	p.compile(Schema.Vars) // sets p.broken on failure rather than erroring the scan
	return p, nil
}

func (r *Repository) list(ctx context.Context, where string, args ...any) ([]Policy, error) {
	rows, err := r.db.Query(ctx, `SELECT `+policyColumns+` FROM vuln_policies p `+where+` ORDER BY p.priority DESC, p.created_at`, args...)
	if err != nil {
		return nil, fmt.Errorf("list vuln policies: %w", err)
	}
	defer rows.Close()
	out := []Policy{}
	for rows.Next() {
		p, err := scanPolicy(rows)
		if err != nil {
			return nil, fmt.Errorf("scan vuln policy: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// List returns every policy, highest priority first.
func (r *Repository) List(ctx context.Context) ([]Policy, error) { return r.list(ctx, "") }

// ListAdmin returns the admin policies only: the GitOps bundle's set.
func (r *Repository) ListAdmin(ctx context.Context) ([]Policy, error) {
	return r.list(ctx, "WHERE p.owner_project_id IS NULL")
}

// ListOwned returns the policies a project's owners made for it.
func (r *Repository) ListOwned(ctx context.Context, projectID string) ([]Policy, error) {
	return r.list(ctx, "WHERE p.owner_project_id = $1", projectID)
}

// Enabled returns every enabled policy (time/scope not yet applied).
func (r *Repository) Enabled(ctx context.Context) ([]Policy, error) {
	return r.list(ctx, "WHERE p.enabled")
}

// Get returns one policy.
func (r *Repository) Get(ctx context.Context, id string) (Policy, error) {
	p, err := scanPolicy(r.db.QueryRow(ctx, `SELECT `+policyColumns+` FROM vuln_policies p WHERE p.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, ErrNotFound
	}
	if err != nil {
		return Policy{}, fmt.Errorf("get vuln policy: %w", err)
	}
	return p, nil
}

// Create stores a validated policy; actor ("" for none) is its author.
func (r *Repository) Create(ctx context.Context, p Policy, actor string) (Policy, error) {
	return r.write(ctx, func(tx pgx.Tx) (string, error) {
		var id string
		err := tx.QueryRow(ctx, `
			INSERT INTO vuln_policies (name, description, enabled, condition, priority,
			                           analysis_state, analysis_justification, analysis_details,
			                           rating_severity, rating_cvss_vector, rating_cvss_score,
			                           valid_from, valid_until, scope, tag, mode, created_by, owner_project_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) RETURNING id`,
			p.Name, p.Description, p.Enabled, p.Condition, p.Priority,
			analysisStateOf(p), justificationOf(p), detailsOf(p),
			severityOf(p), vectorOf(p), scoreOf(p),
			p.ValidFrom, p.ValidUntil, p.Scope, p.Tag, p.Mode, actor, p.OwnerProjectID).Scan(&id)
		return id, err
	}, p)
}

// Update replaces a policy.
func (r *Repository) Update(ctx context.Context, p Policy) (Policy, error) {
	return r.write(ctx, func(tx pgx.Tx) (string, error) {
		tag, err := tx.Exec(ctx, `
			UPDATE vuln_policies SET name = $2, description = $3, enabled = $4, condition = $5, priority = $6,
			       analysis_state = $7, analysis_justification = $8, analysis_details = $9,
			       rating_severity = $10, rating_cvss_vector = $11, rating_cvss_score = $12,
			       valid_from = $13, valid_until = $14, scope = $15, tag = $16, mode = $17, updated_at = now()
			WHERE id = $1`,
			p.ID, p.Name, p.Description, p.Enabled, p.Condition, p.Priority,
			analysisStateOf(p), justificationOf(p), detailsOf(p),
			severityOf(p), vectorOf(p), scoreOf(p),
			p.ValidFrom, p.ValidUntil, p.Scope, p.Tag, p.Mode)
		if err == nil && tag.RowsAffected() == 0 {
			err = ErrNotFound
		}
		return p.ID, err
	}, p)
}

func analysisStateOf(p Policy) string {
	if p.Analysis == nil {
		return ""
	}
	return string(p.Analysis.State)
}
func justificationOf(p Policy) string {
	if p.Analysis == nil {
		return ""
	}
	return p.Analysis.Justification
}
func detailsOf(p Policy) string {
	if p.Analysis == nil {
		return ""
	}
	return p.Analysis.Details
}
func severityOf(p Policy) string {
	if p.Rating == nil {
		return ""
	}
	return string(p.Rating.Severity)
}
func vectorOf(p Policy) string {
	if p.Rating == nil {
		return ""
	}
	return p.Rating.CVSSVector
}
func scoreOf(p Policy) *float64 {
	if p.Rating == nil {
		return nil
	}
	return p.Rating.CVSSScore
}

// write runs a create/update and replaces the policy's project set, atomically.
func (r *Repository) write(ctx context.Context, upsert func(pgx.Tx) (string, error), p Policy) (Policy, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Policy{}, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	id, err := upsert(tx)
	if err != nil {
		return Policy{}, writeErr(err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM vuln_policy_projects WHERE policy_id = $1`, id); err != nil {
		return Policy{}, fmt.Errorf("clear vuln policy projects: %w", err)
	}
	if p.Scope == ScopeProjects && len(p.ProjectIDs) > 0 {
		if _, err := tx.Exec(ctx, `INSERT INTO vuln_policy_projects (policy_id, project_id)
			SELECT $1, unnest($2::uuid[]) ON CONFLICT DO NOTHING`, id, p.ProjectIDs); err != nil {
			return Policy{}, writeErr(err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Policy{}, fmt.Errorf("commit: %w", err)
	}
	return r.Get(ctx, id)
}

// ReplaceAll atomically replaces the whole policy set (GitOps bundle import):
// every existing policy and its project scope is deleted and ps re-inserted,
// all in one transaction. ps must already be validated (schema-compiled,
// unique names) by the caller. Tracked matches (vuln_policy_matches) are left
// alone — they reference policies by id/name without an FK, so a policy a
// replace drops is reconciled (reverted) by the evaluation that follows, the
// same way deleting one policy is.
func (r *Repository) ReplaceAll(ctx context.Context, ps []Policy, actor string) ([]Policy, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// A project owner's policies (owner_project_id) aren't the bundle's: kept.
	if _, err := tx.Exec(ctx, `DELETE FROM vuln_policies WHERE owner_project_id IS NULL`); err != nil {
		return nil, fmt.Errorf("clear vuln policies: %w", err)
	}
	ids := make([]string, len(ps))
	for i, p := range ps {
		var id string
		err := tx.QueryRow(ctx, `
			INSERT INTO vuln_policies (name, description, enabled, condition, priority,
			                           analysis_state, analysis_justification, analysis_details,
			                           rating_severity, rating_cvss_vector, rating_cvss_score,
			                           valid_from, valid_until, scope, tag, mode, created_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17) RETURNING id`,
			p.Name, p.Description, p.Enabled, p.Condition, p.Priority,
			analysisStateOf(p), justificationOf(p), detailsOf(p),
			severityOf(p), vectorOf(p), scoreOf(p),
			p.ValidFrom, p.ValidUntil, p.Scope, p.Tag, p.Mode, actor).Scan(&id)
		if err != nil {
			return nil, writeErr(err)
		}
		if p.Scope == ScopeProjects && len(p.ProjectIDs) > 0 {
			if _, err := tx.Exec(ctx, `INSERT INTO vuln_policy_projects (policy_id, project_id)
				SELECT $1, unnest($2::uuid[]) ON CONFLICT DO NOTHING`, id, p.ProjectIDs); err != nil {
				return nil, writeErr(err)
			}
		}
		ids[i] = id
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	out := make([]Policy, len(ids))
	for i, id := range ids {
		p, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		out[i] = p
	}
	return out, nil
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
	return fmt.Errorf("write vuln policy: %w", err)
}

// Delete removes a policy. Findings it was holding are reverted by the
// evaluation that follows (its match rows reference it ON DELETE CASCADE,
// so they vanish with it — Service treats a tracked policy that no longer
// exists the same as "policy no longer matches").
func (r *Repository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM vuln_policies WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete vuln policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ProjectFacts is a project's facts a condition may read.
type ProjectFacts struct {
	Name        string
	Tags        []string
	Criticality domain.Criticality
	Custom      map[string]any
	// SkipsGlobal: the project opted out of global policies (and an instance
	// admin allows that; triage.ProjectSkipsGlobalSQL).
	SkipsGlobal bool
}

// ProjectFacts returns one project's facts.
func (r *Repository) ProjectFacts(ctx context.Context, projectID string) (ProjectFacts, error) {
	var p ProjectFacts
	err := r.db.QueryRow(ctx, `SELECT name, tags, business_criticality, custom, `+triage.ProjectSkipsGlobalSQL+`
		FROM projects WHERE id = $1`, projectID).
		Scan(&p.Name, &p.Tags, &p.Criticality, &p.Custom, &p.SkipsGlobal)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProjectFacts{}, ErrNoProject
	}
	if p.Custom == nil {
		p.Custom = map[string]any{}
	}
	return p, err
}

// ProjectsWithCandidates returns the distinct projects a full evaluation must
// visit: those with an active (open/confirmed, non-duplicate) finding, plus
// any still carrying a tracked policy match (so an evaluation that finds
// nothing further matching still reverts it).
func (r *Repository) ProjectsWithCandidates(ctx context.Context) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT project_id::text FROM findings
		WHERE status IN ('open', 'confirmed') AND duplicate_of IS NULL
		UNION
		SELECT DISTINCT f.project_id::text FROM vuln_policy_matches m JOIN findings f ON f.id = m.finding_id`)
	if err != nil {
		return nil, fmt.Errorf("vuln policy candidate projects: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// CandidateFindingIDs returns a project's findings an evaluation must
// (re-)consider: its active (open/confirmed, non-duplicate) findings — new
// match candidates — union any finding still carrying a tracked match from an
// earlier evaluation, whatever its current status, so a policy that stops
// matching (or expires) can be reverted even though it moved the finding out
// of that scope.
func (r *Repository) CandidateFindingIDs(ctx context.Context, projectID string) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT f.id::text
		FROM findings f LEFT JOIN vuln_policy_matches m ON m.finding_id = f.id
		WHERE f.project_id = $1 AND f.duplicate_of IS NULL
		  AND (f.status IN ('open', 'confirmed') OR m.finding_id IS NOT NULL)`, projectID)
	if err != nil {
		return nil, fmt.Errorf("vuln policy candidates: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// Match is what a policy is currently holding on one finding: ” in
// AppliedStatus/AppliedSeverity means that half isn't tracked.
type Match struct {
	FindingID       string
	PolicyID        string
	PolicyName      string
	AppliedStatus   string
	PriorStatus     string
	AppliedSeverity string
	PriorSeverity   string
}

// MatchesByProject returns every tracked match for findings in projectID, by
// finding id.
func (r *Repository) MatchesByProject(ctx context.Context, projectID string) (map[string]Match, error) {
	rows, err := r.db.Query(ctx, `
		SELECT m.finding_id::text, m.policy_id::text, m.policy_name, m.applied_status, m.prior_status,
		       m.applied_severity, m.prior_severity
		FROM vuln_policy_matches m JOIN findings f ON f.id = m.finding_id
		WHERE f.project_id = $1`, projectID)
	if err != nil {
		return nil, fmt.Errorf("vuln policy matches: %w", err)
	}
	defer rows.Close()
	out := map[string]Match{}
	for rows.Next() {
		var m Match
		if err := rows.Scan(&m.FindingID, &m.PolicyID, &m.PolicyName, &m.AppliedStatus, &m.PriorStatus,
			&m.AppliedSeverity, &m.PriorSeverity); err != nil {
			return nil, err
		}
		out[m.FindingID] = m
	}
	return out, rows.Err()
}

// UpsertMatch records (or updates) what a policy is holding on a finding.
func (r *Repository) UpsertMatch(ctx context.Context, m Match) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO vuln_policy_matches (finding_id, policy_id, policy_name, applied_status, prior_status,
		                                 applied_severity, prior_severity, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now())
		ON CONFLICT (finding_id) DO UPDATE SET
			policy_id = EXCLUDED.policy_id, policy_name = EXCLUDED.policy_name,
			applied_status = EXCLUDED.applied_status, prior_status = EXCLUDED.prior_status,
			applied_severity = EXCLUDED.applied_severity, prior_severity = EXCLUDED.prior_severity,
			updated_at = now()`,
		m.FindingID, m.PolicyID, m.PolicyName, m.AppliedStatus, m.PriorStatus, m.AppliedSeverity, m.PriorSeverity)
	if err != nil {
		return fmt.Errorf("upsert vuln policy match: %w", err)
	}
	return nil
}

// DeleteMatch drops a finding's tracked match: its effect is no longer
// policy-owned (reverted, or overturned by something else).
func (r *Repository) DeleteMatch(ctx context.Context, findingID string) error {
	if _, err := r.db.Exec(ctx, `DELETE FROM vuln_policy_matches WHERE finding_id = $1`, findingID); err != nil {
		return fmt.Errorf("delete vuln policy match: %w", err)
	}
	return nil
}
