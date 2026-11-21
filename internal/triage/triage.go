// Package triage implements auto-triage rules: persistent conditions that map to
// an action (suppress / accept / downgrade), applied automatically on every scan
// ingest and across the existing backlog to cut finding noise.
package triage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/expr"
	"github.com/xilasec/xila-api/internal/finding"
)

// Domain errors.
var (
	ErrNotFound  = errors.New("triage rule not found")
	ErrNoProject = errors.New("project not found")
	// ErrNotPending is returned when approving/rejecting a rule that isn't
	// awaiting review.
	ErrNotPending = errors.New("triage rule is not pending approval")
	// ErrSelfApproval enforces four-eyes: the author or last editor of a rule
	// can't approve it.
	ErrSelfApproval = errors.New("a rule cannot be approved by its author or last editor")
)

// Action is what a matching rule does to a finding.
type Action string

const (
	ActionFalsePositive Action = "false_positive"
	ActionRiskAccepted  Action = "risk_accepted"
	ActionWontFix       Action = "wont_fix"
	ActionSetSeverity   Action = "set_severity"
	// ActionSetCustomField sets the finding custom field CustomField to
	// CustomValue (null clears it).
	ActionSetCustomField Action = "set_custom_field"
)

var actions = []Action{ActionFalsePositive, ActionRiskAccepted, ActionWontFix, ActionSetSeverity, ActionSetCustomField}

// Valid reports whether a is a known action.
func (a Action) Valid() bool {
	for _, x := range actions {
		if a == x {
			return true
		}
	}
	return false
}

// ApprovalStatus is where a rule stands in the (optional) four-eyes workflow.
// Only approved rules ever apply.
type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalRejected ApprovalStatus = "rejected"
)

// Rule is a match-condition → action policy. Empty conditions match anything;
// all set conditions are AND-ed. ProjectID nil applies to every project.
type Rule struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Enabled   bool   `json:"enabled"`
	SortOrder int    `json:"sort_order"`
	// Continue chains the rule: after it acts on a finding, the rules after
	// it (in sort order) still evaluate, against the finding as it left it.
	// Without it the first matching rule is the only one that acts.
	Continue  bool    `json:"continue"`
	ProjectID *string `json:"project_id"`

	// Conditions.
	Scanner      string            `json:"scanner"`
	Category     domain.Category   `json:"category"`
	Severities   []domain.Severity `json:"severities"`
	CWE          *int              `json:"cwe"`
	RuleID       string            `json:"rule_id"`
	CVEIn        []string          `json:"cve_in"`
	PathRegex    string            `json:"path_regex"`
	PackageRegex string            `json:"package_regex"`
	// Reachability conditions, from the SBOM's own dependency graph. DepScope
	// matches components with that scope (e.g. "dev" = never ships); DepTransitive
	// matches only dependencies the project never asked for. Both are unset by
	// default, and a finding with no reachability data matches neither — an
	// unknown dependency is never auto-suppressed.
	DepScope      domain.DepScope `json:"dep_scope"`
	DepTransitive bool            `json:"dep_transitive"`
	// Exploit / business conditions. MinEPSS matches findings whose EPSS is at
	// least it (an unknown EPSS never matches); KEV matches only KEV-listed
	// findings; ProjectCriticality matches findings whose project has one of
	// those business criticalities.
	MinEPSS            *float64             `json:"min_epss"`
	KEV                bool                 `json:"kev"`
	ProjectCriticality []domain.Criticality `json:"project_criticality"`
	// Expression is an optional CEL condition over the finding's facts
	// (FindingDoc), for what the fixed conditions can't say:
	// `finding.cvss >= 9 && finding.tags.exists(t, t == "internet-facing")`.
	Expression string `json:"expression"`

	// Action.
	Action      Action          `json:"action"`
	NewSeverity domain.Severity `json:"new_severity"`
	Reason      string          `json:"reason"`
	// CustomField / CustomValue: set_custom_field's finding field key and
	// value, validated against the field's definition when the rule is saved.
	CustomField string `json:"custom_field"`
	CustomValue any    `json:"custom_value"`
	// VexJustification / VexResponse: optional CycloneDX impact-analysis
	// fields (M13 13.2) set on findings a false_positive / wont_fix action
	// moves; ignored (cleared on save) for every other action.
	VexJustification domain.VexJustification `json:"vex_justification"`
	VexResponse      []domain.VexResponse    `json:"vex_response"`

	// Hit metrics (read-only): findings this rule actually changed.
	HitCount  int64      `json:"hit_count"`
	LastHitAt *time.Time `json:"last_hit_at"`

	// Approval workflow (read-only; driven by TRIAGE_RULES_REQUIRE_APPROVAL).
	ApprovalStatus ApprovalStatus `json:"approval_status"`
	CreatedBy      *string        `json:"created_by"`
	UpdatedBy      *string        `json:"updated_by"`
	ApprovedBy     *string        `json:"approved_by"`
	ApprovedAt     *time.Time     `json:"approved_at"`
	RejectedBy     *string        `json:"rejected_by"`
	RejectedAt     *time.Time     `json:"rejected_at"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	pathRe, packageRe *regexp.Regexp
	expr              *expr.Program
	// broken: a stored condition no longer compiles; the rule matches nothing
	// rather than everything.
	broken bool
}

// compile compiles the regex conditions and the expression. The expression
// was validated against its document when saved (Validate); here it is only
// loaded, so a custom field deleted since then makes it not match.
func (r *Rule) compile() error {
	r.pathRe, r.packageRe, r.expr = nil, nil, nil
	if strings.TrimSpace(r.Expression) != "" {
		p, err := expr.Load(FindingSchema.Vars, r.Expression)
		if err != nil {
			return err
		}
		r.expr, r.Expression = p, p.Source
	}
	if r.PathRegex != "" {
		re, err := regexp.Compile(r.PathRegex)
		if err != nil {
			return fmt.Errorf("path_regex: %w", err)
		}
		r.pathRe = re
	}
	if r.PackageRegex != "" {
		re, err := regexp.Compile(r.PackageRegex)
		if err != nil {
			return fmt.Errorf("package_regex: %w", err)
		}
		r.packageRe = re
	}
	return nil
}

// Validate checks a rule's fields and compiles its conditions before
// persisting; the expression is dry-run against schema (FindingSchemaFor the
// current custom fields), so a misspelled fact is refused.
func (r *Rule) Validate(schema expr.Schema) error {
	if r.Name == "" {
		return errors.New("name is required")
	}
	if !r.Action.Valid() {
		return errors.New("invalid action")
	}
	if r.Action == ActionSetSeverity && !r.NewSeverity.Valid() {
		return errors.New("set_severity requires a valid new_severity")
	}
	if r.Action == ActionSetCustomField && r.CustomField == "" {
		return errors.New("set_custom_field requires a custom_field")
	}
	if r.Action != ActionSetCustomField {
		r.CustomField, r.CustomValue = "", nil
	}
	if r.Action != ActionFalsePositive && r.Action != ActionWontFix {
		r.VexJustification, r.VexResponse = "", nil
	}
	if !r.VexJustification.Valid() {
		return errors.New("invalid vex_justification")
	}
	if !domain.ValidVexResponses(r.VexResponse) {
		return errors.New("invalid vex_response")
	}
	if r.Category != "" && !r.Category.Valid() {
		return errors.New("invalid category")
	}
	for _, s := range r.Severities {
		if !s.Valid() {
			return errors.New("invalid severity in conditions")
		}
	}
	if r.MinEPSS != nil && (*r.MinEPSS < 0 || *r.MinEPSS > 1) {
		return errors.New("min_epss must be between 0 and 1")
	}
	for _, c := range r.ProjectCriticality {
		if !c.Valid() {
			return errors.New("invalid project_criticality")
		}
	}
	if strings.TrimSpace(r.Expression) != "" {
		if _, err := expr.Compile(schema, r.Expression); err != nil {
			return err
		}
	}
	return r.compile()
}

// Matches reports whether every set condition holds for the finding, whose
// project's facts are p. Regex conditions require compile() to have run (the
// repository does this on load).
func (r *Rule) Matches(f finding.Finding, p ProjectFacts) bool {
	if r.broken {
		return false
	}
	crit := p.Criticality
	if r.Scanner != "" && f.Scanner != r.Scanner {
		return false
	}
	if r.Category != "" && f.Category != r.Category {
		return false
	}
	if len(r.Severities) > 0 && !containsSeverity(r.Severities, f.Severity) {
		return false
	}
	if r.CWE != nil && (f.CWE == nil || *f.CWE != *r.CWE) {
		return false
	}
	if r.RuleID != "" && f.RuleID != r.RuleID {
		return false
	}
	if len(r.CVEIn) > 0 && !anyCVE(f.CVE, r.CVEIn) {
		return false
	}
	if r.pathRe != nil && !r.pathRe.MatchString(f.FilePath) {
		return false
	}
	if r.packageRe != nil && !r.packageRe.MatchString(f.PackageName) {
		return false
	}
	if r.DepScope != "" && f.DepScope != r.DepScope {
		return false
	}
	// Only fires on a dependency we know to be transitive. Unknown (no SBOM graph)
	// must not be silently treated as "not chosen on purpose".
	if r.DepTransitive && (f.DepDirect == nil || *f.DepDirect) {
		return false
	}
	// Unknown EPSS never matches: "not scored yet" is not "unlikely exploited".
	// Compared at float32 precision because findings.epss is a REAL — a stored
	// 0.9 reads back as 0.8999999761…, and must still satisfy min_epss 0.9.
	if r.MinEPSS != nil && (f.EPSS == nil || float32(*f.EPSS) < float32(*r.MinEPSS)) {
		return false
	}
	if r.KEV && !f.KEV {
		return false
	}
	if len(r.ProjectCriticality) > 0 && !slices.Contains(r.ProjectCriticality, crit) {
		return false
	}
	if r.expr != nil && !r.expr.Match(context.Background(), FindingDoc(f, p)) {
		return false
	}
	return true
}

// needsProject reports whether evaluating the rule needs the project's facts
// (criticality, custom fields), so callers can skip the lookup otherwise.
func (r *Rule) needsProject() bool { return len(r.ProjectCriticality) > 0 || r.expr != nil }

func containsSeverity(set []domain.Severity, s domain.Severity) bool {
	for _, x := range set {
		if x == s {
			return true
		}
	}
	return false
}

func anyCVE(have, want []string) bool {
	for _, h := range have {
		for _, w := range want {
			if h == w {
				return true
			}
		}
	}
	return false
}

// Repository stores triage rules.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

const ruleColumns = `id, name, enabled, sort_order, project_id, scanner, category,
	severities, cwe, rule_id, cve_in, path_regex, package_regex, dep_scope, dep_transitive,
	min_epss, kev, project_criticality, expression,
	action, new_severity, reason, custom_field, custom_value, vex_justification, vex_response, hit_count, last_hit_at,
	approval_status, created_by, updated_by, approved_by, approved_at, rejected_by, rejected_at,
	created_at, updated_at, continue_matching`

func scanRule(row pgx.Row) (Rule, error) {
	var r Rule
	err := row.Scan(&r.ID, &r.Name, &r.Enabled, &r.SortOrder, &r.ProjectID, &r.Scanner, &r.Category,
		&r.Severities, &r.CWE, &r.RuleID, &r.CVEIn, &r.PathRegex, &r.PackageRegex,
		&r.DepScope, &r.DepTransitive, &r.MinEPSS, &r.KEV, &r.ProjectCriticality, &r.Expression,
		&r.Action, &r.NewSeverity, &r.Reason, &r.CustomField, &r.CustomValue, &r.VexJustification, &r.VexResponse, &r.HitCount, &r.LastHitAt,
		&r.ApprovalStatus, &r.CreatedBy, &r.UpdatedBy, &r.ApprovedBy, &r.ApprovedAt,
		&r.RejectedBy, &r.RejectedAt, &r.CreatedAt, &r.UpdatedAt, &r.Continue)
	if err != nil {
		return Rule{}, err
	}
	if err := r.compile(); err != nil {
		r.broken = true // validated on write; if it no longer loads, it matches nothing
	}
	return r, nil
}

// approvalFor is the status a freshly created or edited rule lands in: pending
// review when the approval workflow is on, approved otherwise.
func approvalFor(requireApproval bool) ApprovalStatus {
	if requireApproval {
		return ApprovalPending
	}
	return ApprovalApproved
}

// Create inserts a rule after validating + compiling it. actor (may be "")
// becomes created_by/updated_by. With requireApproval the rule starts pending
// and never applies until a different admin approves it.
func (r *Repository) Create(ctx context.Context, rule Rule, actor string, requireApproval bool) (Rule, error) {
	if err := rule.compile(); err != nil {
		return Rule{}, err
	}
	const q = `INSERT INTO triage_rules (
		name, enabled, sort_order, project_id, scanner, category, severities, cwe,
		rule_id, cve_in, path_regex, package_regex, dep_scope, dep_transitive,
		min_epss, kev, project_criticality,
		action, new_severity, reason, approval_status, created_by, updated_by, approved_at, expression,
		custom_field, custom_value, continue_matching, vex_justification, vex_response
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,
		$21, $22::uuid, $22::uuid, CASE WHEN $21 = 'approved' THEN now() END, $23, $24, $25, $26, $27, $28)
	RETURNING ` + ruleColumns
	out, err := scanRule(r.db.QueryRow(ctx, q,
		rule.Name, rule.Enabled, rule.SortOrder, rule.ProjectID, rule.Scanner, rule.Category,
		coalesceSlice(rule.Severities), rule.CWE, rule.RuleID, coalesceStr(rule.CVEIn),
		rule.PathRegex, rule.PackageRegex, rule.DepScope, rule.DepTransitive,
		rule.MinEPSS, rule.KEV, coalesceCrit(rule.ProjectCriticality),
		rule.Action, rule.NewSeverity, rule.Reason, approvalFor(requireApproval), nilIfEmpty(actor), rule.Expression,
		rule.CustomField, customValueArg(rule), rule.Continue, rule.VexJustification, vexResponseArgs(rule.VexResponse)))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return Rule{}, ErrNoProject
	}
	if err != nil {
		return Rule{}, fmt.Errorf("insert rule: %w", err)
	}
	return out, nil
}

// Get fetches a rule by id.
func (r *Repository) Get(ctx context.Context, id string) (Rule, error) {
	out, err := scanRule(r.db.QueryRow(ctx, `SELECT `+ruleColumns+` FROM triage_rules WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Rule{}, ErrNotFound
	}
	if err != nil {
		return Rule{}, fmt.Errorf("get rule: %w", err)
	}
	return out, nil
}

// List returns all rules, ordered for evaluation.
func (r *Repository) List(ctx context.Context) ([]Rule, error) {
	return r.query(ctx, `SELECT `+ruleColumns+` FROM triage_rules ORDER BY sort_order, created_at`)
}

// ListEnabledForProject returns the enabled, approved rules that apply to a
// project (global rules + that project's rules), in evaluation order. Pending
// and rejected rules never apply.
func (r *Repository) ListEnabledForProject(ctx context.Context, projectID string) ([]Rule, error) {
	const q = `SELECT ` + ruleColumns + ` FROM triage_rules
		WHERE enabled AND approval_status = 'approved' AND (project_id IS NULL OR project_id = $1)
		ORDER BY sort_order, created_at`
	return r.query(ctx, q, projectID)
}

func (r *Repository) query(ctx context.Context, q string, args ...any) ([]Rule, error) {
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list rules: %w", err)
	}
	defer rows.Close()
	rules := []Rule{}
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan rule: %w", err)
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

// Update replaces a rule's mutable fields; actor (may be "") becomes
// updated_by. With requireApproval ANY edit — including of an approved rule —
// resets it to pending, so it stops applying until a different admin
// re-approves it. Without it the rule is (re)marked approved.
func (r *Repository) Update(ctx context.Context, rule Rule, actor string, requireApproval bool) (Rule, error) {
	if err := rule.compile(); err != nil {
		return Rule{}, err
	}
	const q = `UPDATE triage_rules SET
		name=$2, enabled=$3, sort_order=$4, project_id=$5, scanner=$6, category=$7,
		severities=$8, cwe=$9, rule_id=$10, cve_in=$11, path_regex=$12, package_regex=$13,
		dep_scope=$14, dep_transitive=$15, min_epss=$16, kev=$17, project_criticality=$18,
		action=$19, new_severity=$20, reason=$21,
		approval_status=$22, updated_by=$23::uuid, expression=$24, custom_field=$25, custom_value=$26,
		continue_matching=$27, vex_justification=$28, vex_response=$29,
		approved_by = CASE WHEN $22 = 'approved' AND approval_status = 'approved' THEN approved_by END,
		approved_at = CASE WHEN $22 = 'approved' THEN COALESCE(approved_at, now()) END,
		rejected_by = NULL, rejected_at = NULL,
		updated_at=now()
		WHERE id=$1 RETURNING ` + ruleColumns
	out, err := scanRule(r.db.QueryRow(ctx, q,
		rule.ID, rule.Name, rule.Enabled, rule.SortOrder, rule.ProjectID, rule.Scanner, rule.Category,
		coalesceSlice(rule.Severities), rule.CWE, rule.RuleID, coalesceStr(rule.CVEIn),
		rule.PathRegex, rule.PackageRegex, rule.DepScope, rule.DepTransitive,
		rule.MinEPSS, rule.KEV, coalesceCrit(rule.ProjectCriticality),
		rule.Action, rule.NewSeverity, rule.Reason, approvalFor(requireApproval), nilIfEmpty(actor), rule.Expression,
		rule.CustomField, customValueArg(rule), rule.Continue, rule.VexJustification, vexResponseArgs(rule.VexResponse)))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return Rule{}, ErrNoProject
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return Rule{}, ErrNotFound
	}
	if err != nil {
		return Rule{}, fmt.Errorf("update rule: %w", err)
	}
	return out, nil
}

// Approve moves a pending rule to approved. Four-eyes: approver must differ
// from the rule's author and last editor (ErrSelfApproval); a rule not awaiting
// review returns ErrNotPending.
func (r *Repository) Approve(ctx context.Context, id, approver string) (Rule, error) {
	rule, err := r.Get(ctx, id)
	if err != nil {
		return Rule{}, err
	}
	if rule.ApprovalStatus != ApprovalPending {
		return Rule{}, ErrNotPending
	}
	if isActor(rule.CreatedBy, approver) || isActor(rule.UpdatedBy, approver) {
		return Rule{}, ErrSelfApproval
	}
	// Re-check both conditions in the write so a concurrent edit (which changes
	// updated_by) can't slip an unreviewed version through.
	const q = `UPDATE triage_rules SET approval_status = 'approved',
		approved_by = $2::uuid, approved_at = now(), rejected_by = NULL, rejected_at = NULL
		WHERE id = $1 AND approval_status = 'pending' AND updated_at = $3
		  AND created_by IS DISTINCT FROM $2::uuid AND updated_by IS DISTINCT FROM $2::uuid
		RETURNING ` + ruleColumns
	out, err := scanRule(r.db.QueryRow(ctx, q, id, nilIfEmpty(approver), rule.UpdatedAt))
	if errors.Is(err, pgx.ErrNoRows) {
		return Rule{}, ErrNotPending
	}
	if err != nil {
		return Rule{}, fmt.Errorf("approve rule: %w", err)
	}
	return out, nil
}

// Reject marks a pending rule rejected. The row is kept for audit and never
// applies; editing it puts it back up for review.
func (r *Repository) Reject(ctx context.Context, id, reviewer string) (Rule, error) {
	const q = `UPDATE triage_rules SET approval_status = 'rejected',
		rejected_by = $2::uuid, rejected_at = now(), approved_by = NULL, approved_at = NULL
		WHERE id = $1 AND approval_status = 'pending'
		RETURNING ` + ruleColumns
	out, err := scanRule(r.db.QueryRow(ctx, q, id, nilIfEmpty(reviewer)))
	if errors.Is(err, pgx.ErrNoRows) {
		if _, gerr := r.Get(ctx, id); gerr != nil {
			return Rule{}, gerr
		}
		return Rule{}, ErrNotPending
	}
	if err != nil {
		return Rule{}, fmt.Errorf("reject rule: %w", err)
	}
	return out, nil
}

// RecordHits adds each rule's changed-finding count to its hit_count and stamps
// last_hit_at. Rules with zero hits are left alone.
func (r *Repository) RecordHits(ctx context.Context, hits map[string]int) error {
	ids := make([]string, 0, len(hits))
	counts := make([]int64, 0, len(hits))
	for id, n := range hits {
		if n > 0 {
			ids = append(ids, id)
			counts = append(counts, int64(n))
		}
	}
	if len(ids) == 0 {
		return nil
	}
	const q = `UPDATE triage_rules t SET hit_count = t.hit_count + h.n, last_hit_at = now()
		FROM unnest($1::uuid[], $2::bigint[]) AS h(id, n) WHERE t.id = h.id`
	if _, err := r.db.Exec(ctx, q, ids, counts); err != nil {
		return fmt.Errorf("record rule hits: %w", err)
	}
	return nil
}

// ProjectFacts is what a rule may condition on about a finding's project.
type ProjectFacts struct {
	Criticality domain.Criticality
	Custom      map[string]any
}

// ProjectFacts returns a project's business criticality and custom fields.
func (r *Repository) ProjectFacts(ctx context.Context, projectID string) (ProjectFacts, error) {
	var p ProjectFacts
	err := r.db.QueryRow(ctx, `SELECT business_criticality, custom FROM projects WHERE id = $1`, projectID).
		Scan(&p.Criticality, &p.Custom)
	if errors.Is(err, pgx.ErrNoRows) {
		return ProjectFacts{}, ErrNoProject
	}
	if err != nil {
		return ProjectFacts{}, fmt.Errorf("project facts: %w", err)
	}
	return p, nil
}

// customValueArg is custom_value as a jsonb parameter: JSON text for
// set_custom_field (null clears the field), SQL NULL for other actions.
func customValueArg(r Rule) []byte {
	if r.Action != ActionSetCustomField {
		return nil
	}
	b, err := json.Marshal(r.CustomValue)
	if err != nil {
		return []byte("null")
	}
	return b
}

// Delete removes a rule.
func (r *Repository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM triage_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func isActor(who *string, actor string) bool { return who != nil && actor != "" && *who == actor }

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func coalesceCrit(s []domain.Criticality) []domain.Criticality {
	if s == nil {
		return []domain.Criticality{}
	}
	return s
}

// severities/cve_in are NOT NULL text[]; coalesce nil to empty so inserts don't
// send SQL NULL.
func coalesceSlice(s []domain.Severity) []domain.Severity {
	if s == nil {
		return []domain.Severity{}
	}
	return s
}

func coalesceStr(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// vexResponseArgs converts to the plain []string the vex_response text[]
// column takes (never nil — the column is NOT NULL DEFAULT '{}').
func vexResponseArgs(rs []domain.VexResponse) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = string(r)
	}
	return out
}
