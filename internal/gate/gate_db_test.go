package gate_test

import (
	"context"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/gate"
	"github.com/xilasec/xila-api/internal/pgtest"
)

func TestGatePolicyLifecycle(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	frepo := finding.NewRepository(pool)
	grepo := gate.NewRepository(pool)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-g','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	// One open critical finding.
	if _, err := frepo.Upsert(ctx, finding.Finding{
		ProjectID: projectID, Fingerprint: "fp", Scanner: "trivy",
		Category: domain.CategorySCA, RuleID: "CVE-1", Title: "boom", Severity: domain.SeverityCritical,
	}); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	stats, err := frepo.ComputeGateStats(ctx, projectID, "", false, "")
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.OpenCritical != 1 {
		t.Fatalf("open critical = %d, want 1", stats.OpenCritical)
	}

	// No policy anywhere -> scope "none" -> passes.
	if p, scope, _ := grepo.Effective(ctx, projectID); scope != "none" || !gate.Evaluate(p, stats).Passed {
		t.Errorf("no policy should pass with scope none, got scope=%q", scope)
	}

	// Project policy blocks criticals -> fails.
	zero := 0
	if _, err := grepo.Upsert(ctx, gate.Policy{ProjectID: &projectID, MaxCritical: &zero}); err != nil {
		t.Fatalf("upsert project policy: %v", err)
	}
	p, scope, _ := grepo.Effective(ctx, projectID)
	if scope != "project" {
		t.Errorf("scope = %q, want project", scope)
	}
	if res := gate.Evaluate(p, stats); res.Passed || len(res.Violations) != 1 || res.Violations[0].Rule != "max_critical" {
		t.Errorf("expected a max_critical failure, got %+v", res)
	}

	// Removing the project policy falls back to a lenient global -> passes.
	if err := grepo.Delete(ctx, &projectID); err != nil {
		t.Fatalf("delete project policy: %v", err)
	}
	five := 5
	if _, err := grepo.Upsert(ctx, gate.Policy{ProjectID: nil, MaxCritical: &five}); err != nil {
		t.Fatalf("upsert global policy: %v", err)
	}
	p, scope, _ = grepo.Effective(ctx, projectID)
	if scope != "global" || !gate.Evaluate(p, stats).Passed {
		t.Errorf("should inherit lenient global and pass, got scope=%q", scope)
	}

	// The global row is a singleton: re-upsert updates in place, no duplicate.
	if _, err := grepo.Upsert(ctx, gate.Policy{ProjectID: nil, BlockKEV: true}); err != nil {
		t.Fatalf("re-upsert global: %v", err)
	}
	var globals int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM gate_policies WHERE project_id IS NULL`).Scan(&globals); err != nil {
		t.Fatalf("count globals: %v", err)
	}
	if globals != 1 {
		t.Errorf("global policies = %d, want exactly 1", globals)
	}
}

// TestGateMaxRiskScoreThreshold pins RiskScore to the same business-weighted
// formula project.Summary uses (severity weight × count × criticality
// multiplier), computed over the live backlog ComputeGateStats already scopes.
func TestGateMaxRiskScoreThreshold(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	frepo := finding.NewRepository(pool)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-risk','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name, business_criticality) SELECT id,'p','p','high' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	// One open high finding: weight 7 × "high" criticality multiplier 2 = 14.
	if _, err := frepo.Upsert(ctx, finding.Finding{
		ProjectID: projectID, Fingerprint: "fp", Scanner: "trivy",
		Category: domain.CategorySCA, RuleID: "CVE-1", Title: "boom", Severity: domain.SeverityHigh,
	}); err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	stats, err := frepo.ComputeGateStats(ctx, projectID, "", false, "")
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.RiskScore != 14 {
		t.Fatalf("risk score = %v, want 14 (7 × high multiplier 2)", stats.RiskScore)
	}

	low := 10.0
	if res := gate.Evaluate(gate.Policy{MaxRiskScore: &low}, stats); res.Passed {
		t.Errorf("risk 14 should fail a max_risk_score of 10, got %+v", res)
	}
	high := 20.0
	if res := gate.Evaluate(gate.Policy{MaxRiskScore: &high}, stats); !res.Passed {
		t.Errorf("risk 14 should pass a max_risk_score of 20, got %+v", res)
	}
}
