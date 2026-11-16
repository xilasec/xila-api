// Package gate implements security gates: a pass/fail policy evaluated against a
// project's deduped, triaged backlog, so CI can break the build on unacceptable
// risk. Evaluation is pure; policies are stored per-project with a global default.
package gate

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

	"github.com/xilasec/xila-api/internal/finding"
)

// ErrNoProject is returned when a policy references a missing project.
var ErrNoProject = errors.New("project not found")

// Policy is the set of thresholds a gate enforces. A nil pointer means "no limit
// on this dimension"; an empty policy passes everything.
type Policy struct {
	ProjectID   *string `json:"project_id"`
	MaxCritical *int    `json:"max_critical"`
	MaxHigh     *int    `json:"max_high"`
	MaxMedium   *int    `json:"max_medium"`
	MaxLow      *int    `json:"max_low"`
	MaxInfo     *int    `json:"max_info"`
	BlockKEV    bool    `json:"block_kev"`
	// KEVSources limits block_kev to findings these catalogs assert (cisa,
	// enisa, vulncheck); empty = any catalog.
	KEVSources   []string `json:"kev_sources"`
	MaxEPSS      *float64 `json:"max_epss"`
	BlockLicense bool     `json:"block_license"`
	// BlockSLABreach fails the gate while any live finding is past its SLA.
	BlockSLABreach bool `json:"block_sla_breach"`
	// NewOnly gates on newly-introduced findings only (ignores pre-existing debt).
	NewOnly bool `json:"new_only"`
	// BaselineBranch names the branch/version that decides what counts as "new"
	// under NewOnly: a finding is new when no open/confirmed finding with the
	// same fingerprint already lives there. Nil keeps the original heuristic
	// (seen in a single scan so far). See gateStatsQuery for why fingerprint,
	// not correlation_key, is the stable cross-branch identity.
	BaselineBranch *string `json:"baseline_branch"`
	// MaxRiskScore fails the gate when the gated version's business-weighted
	// risk score (the same figure project.Summary shows) exceeds this.
	MaxRiskScore *float64   `json:"max_risk_score"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
}

// Violation is one failed condition.
type Violation struct {
	Rule    string `json:"rule"`
	Message string `json:"message"`
}

// Result is a gate evaluation outcome.
type Result struct {
	Passed     bool        `json:"passed"`
	Scope      string      `json:"scope"`    // "project", "global", or "none"
	NewOnly    bool        `json:"new_only"` // whether only new findings were evaluated
	Violations []Violation `json:"violations"`
	// VersionID is the project version evaluated; "" means the default version.
	VersionID string `json:"version_id"`
	// Baseline is the branch/version name "new" was compared against, when one
	// was used (query override or the policy's baseline_branch); "" means the
	// original single-scan heuristic.
	Baseline string            `json:"baseline,omitempty"`
	Stats    finding.GateStats `json:"stats"`
}

// Evaluate applies a policy to the live stats, producing pass/fail + violations.
// Pure — no I/O — so it's exhaustively unit-tested.
func Evaluate(p Policy, s finding.GateStats) Result {
	violations := []Violation{}
	add := func(rule, msg string) { violations = append(violations, Violation{Rule: rule, Message: msg}) }

	if p.MaxCritical != nil && s.OpenCritical > *p.MaxCritical {
		add("max_critical", fmt.Sprintf("%d open critical findings exceed the limit of %d", s.OpenCritical, *p.MaxCritical))
	}
	if p.MaxHigh != nil && s.OpenHigh > *p.MaxHigh {
		add("max_high", fmt.Sprintf("%d open high findings exceed the limit of %d", s.OpenHigh, *p.MaxHigh))
	}
	for _, c := range []struct {
		rule, sev string
		max       *int
		open      int
	}{{"max_medium", "medium", p.MaxMedium, s.OpenMedium}, {"max_low", "low", p.MaxLow, s.OpenLow}, {"max_info", "info", p.MaxInfo, s.OpenInfo}} {
		if c.max != nil && c.open > *c.max {
			add(c.rule, fmt.Sprintf("%d open %s findings exceed the limit of %d", c.open, c.sev, *c.max))
		}
	}
	if p.BlockKEV {
		if n := openKEV(p.KEVSources, s); n > 0 {
			add("block_kev", fmt.Sprintf("%d open finding(s) are on a KEV list (%s)", n, kevLabel(p.KEVSources)))
		}
	}
	if p.MaxEPSS != nil && s.MaxEPSS >= *p.MaxEPSS {
		add("max_epss", fmt.Sprintf("an open finding has EPSS %.3f (≥ the limit of %.3f)", s.MaxEPSS, *p.MaxEPSS))
	}
	if p.BlockLicense && s.OpenLicense > 0 {
		add("block_license", fmt.Sprintf("%d open license violation(s)", s.OpenLicense))
	}
	if p.BlockSLABreach && s.SLABreached > 0 {
		add("block_sla_breach", fmt.Sprintf("%d open finding(s) are past their remediation SLA", s.SLABreached))
	}
	if p.MaxRiskScore != nil && s.RiskScore > *p.MaxRiskScore {
		add("max_risk_score", fmt.Sprintf("risk score %.1f exceeds the limit of %.1f", s.RiskScore, *p.MaxRiskScore))
	}
	return Result{Passed: len(violations) == 0, Violations: violations, Stats: s}
}

// openKEV counts the open KEV findings any of sources asserts (all of them
// when sources is empty).
func openKEV(sources []string, s finding.GateStats) int {
	if len(sources) == 0 {
		return s.OpenKEV
	}
	n := 0
	for set, count := range s.OpenKEVSources {
		for src := range strings.SplitSeq(set, ",") {
			if slices.Contains(sources, src) {
				n += count
				break
			}
		}
	}
	return n
}

func kevLabel(sources []string) string {
	if len(sources) == 0 {
		return "any catalog"
	}
	return strings.Join(sources, ", ")
}

// Repository stores gate policies (one per project + one global with NULL project).
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

const policyColumns = `project_id, max_critical, max_high, max_medium, max_low, max_info, block_kev, kev_sources, max_epss, block_license, new_only, block_sla_breach, baseline_branch, max_risk_score, updated_at`

func scanPolicy(row pgx.Row) (Policy, error) {
	var p Policy
	err := row.Scan(&p.ProjectID, &p.MaxCritical, &p.MaxHigh, &p.MaxMedium, &p.MaxLow, &p.MaxInfo, &p.BlockKEV, &p.KEVSources, &p.MaxEPSS, &p.BlockLicense, &p.NewOnly, &p.BlockSLABreach, &p.BaselineBranch, &p.MaxRiskScore, &p.UpdatedAt)
	return p, err
}

// Get returns the policy for an exact scope (a project id, or nil for the global
// default) and whether one exists.
func (r *Repository) Get(ctx context.Context, projectID *string) (Policy, bool, error) {
	const q = `SELECT ` + policyColumns + ` FROM gate_policies WHERE project_id IS NOT DISTINCT FROM $1`
	p, err := scanPolicy(r.db.QueryRow(ctx, q, projectID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Policy{}, false, nil
	}
	if err != nil {
		return Policy{}, false, fmt.Errorf("get policy: %w", err)
	}
	return p, true, nil
}

// Effective returns the policy that applies to a project — its own if set, else
// the global default — plus its scope ("project"/"global"/"none").
func (r *Repository) Effective(ctx context.Context, projectID string) (Policy, string, error) {
	if p, ok, err := r.Get(ctx, &projectID); err != nil {
		return Policy{}, "", err
	} else if ok {
		return p, "project", nil
	}
	if p, ok, err := r.Get(ctx, nil); err != nil {
		return Policy{}, "", err
	} else if ok {
		return p, "global", nil
	}
	return Policy{}, "none", nil
}

// Upsert stores a policy for its scope (Policy.ProjectID; nil = global).
func (r *Repository) Upsert(ctx context.Context, p Policy) (Policy, error) {
	const q = `
		UPDATE gate_policies SET
			max_critical=$2, max_high=$3, block_kev=$4, max_epss=$5, block_license=$6, new_only=$7, block_sla_breach=$8,
			kev_sources=$9, baseline_branch=$10, max_risk_score=$11, max_medium=$12, max_low=$13, max_info=$14, updated_at=now()
		WHERE project_id IS NOT DISTINCT FROM $1
		RETURNING ` + policyColumns
	out, err := scanPolicy(r.db.QueryRow(ctx, q, p.ProjectID, p.MaxCritical, p.MaxHigh, p.BlockKEV, p.MaxEPSS, p.BlockLicense, p.NewOnly, p.BlockSLABreach, kevSources(p), p.BaselineBranch, p.MaxRiskScore, p.MaxMedium, p.MaxLow, p.MaxInfo))
	if errors.Is(err, pgx.ErrNoRows) {
		return r.insert(ctx, p)
	}
	if err != nil {
		return Policy{}, fmt.Errorf("update policy: %w", err)
	}
	return out, nil
}

// kevSources is the policy's catalog list as stored (never NULL).
func kevSources(p Policy) []string {
	if p.KEVSources == nil {
		return []string{}
	}
	return p.KEVSources
}

func (r *Repository) insert(ctx context.Context, p Policy) (Policy, error) {
	const q = `INSERT INTO gate_policies (project_id, max_critical, max_high, block_kev, max_epss, block_license, new_only, block_sla_breach, kev_sources, baseline_branch, max_risk_score, max_medium, max_low, max_info)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) RETURNING ` + policyColumns
	out, err := scanPolicy(r.db.QueryRow(ctx, q, p.ProjectID, p.MaxCritical, p.MaxHigh, p.BlockKEV, p.MaxEPSS, p.BlockLicense, p.NewOnly, p.BlockSLABreach, kevSources(p), p.BaselineBranch, p.MaxRiskScore, p.MaxMedium, p.MaxLow, p.MaxInfo))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return Policy{}, ErrNoProject
	}
	if err != nil {
		return Policy{}, fmt.Errorf("insert policy: %w", err)
	}
	return out, nil
}

// Delete removes a scope's policy (nil = global).
func (r *Repository) Delete(ctx context.Context, projectID *string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM gate_policies WHERE project_id IS NOT DISTINCT FROM $1`, projectID)
	if err != nil {
		return fmt.Errorf("delete policy: %w", err)
	}
	return nil
}
