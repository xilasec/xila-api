package portfolio_test

import (
	"context"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/compliance"
	"github.com/xilasec/xila-api/internal/metrics"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/portfolio"
)

func seedProject(t *testing.T, pool *pgxpool.Pool, slug, criticality string) string {
	t.Helper()
	ctx := context.Background()
	var teamID, projectID string
	if err := pool.QueryRow(ctx, `WITH o AS (INSERT INTO organizations (slug, name) VALUES ('o-'||$1, $1) RETURNING id) INSERT INTO teams (org_id, slug, name) SELECT id, $1, $1 FROM o RETURNING id`, "team-"+slug).Scan(&teamID); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (team_id, slug, name, business_criticality) VALUES ($1,$2,$2,$3) RETURNING id`,
		teamID, slug, criticality).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return projectID
}

func addFinding(t *testing.T, pool *pgxpool.Pool, projectID, fp, scanner, category, severity, status string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO findings (project_id, fingerprint, scanner, category, title, severity, status)
		 VALUES ($1,$2,$3,$4,'t',$5,$6)`, projectID, fp, scanner, category, severity, status); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
}

func TestPortfolioOverview(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := portfolio.NewRepository(pool)
	ctx := context.Background()

	pHigh := seedProject(t, pool, "web", "high") // multiplier 2
	pLow := seedProject(t, pool, "batch", "low") // multiplier 1
	_ = seedProject(t, pool, "empty", "medium")  // no findings

	// web: 1 critical SCA (open) + 1 high secret (open)
	addFinding(t, pool, pHigh, "a", "trivy", "sca", "critical", "open")
	addFinding(t, pool, pHigh, "b", "trivy", "secret", "high", "open")
	// batch: 1 medium cloud (open) + 1 remediated (ignored)
	addFinding(t, pool, pLow, "c", "prowler", "cloud", "medium", "open")
	addFinding(t, pool, pLow, "d", "prowler", "cloud", "high", "remediated")
	// batch: 1 risk-accepted finding expiring in ~10 days.
	if _, err := pool.Exec(ctx, `
		WITH f AS (
			INSERT INTO findings (project_id, fingerprint, scanner, category, title, severity, status)
			VALUES ($1, 'e', 'trivy', 'sca', 't', 'low', 'risk_accepted') RETURNING id
		), ra AS (
			INSERT INTO risk_acceptances (project_id, title, state, expires_at)
			VALUES ($1, 'accepted', 'approved', now() + interval '10 days') RETURNING id
		)
		INSERT INTO risk_acceptance_findings (acceptance_id, finding_id) SELECT ra.id, f.id FROM ra, f`, pLow); err != nil {
		t.Fatalf("insert accepted finding: %v", err)
	}

	ov, err := repo.Overview(ctx, nil)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}

	if ov.Projects != 3 {
		t.Errorf("projects = %d, want 3", ov.Projects)
	}
	if ov.TotalOpen != 3 { // remediated + risk_accepted excluded
		t.Errorf("total_open = %d, want 3", ov.TotalOpen)
	}
	if ov.ExpiringSoon != 1 { // the acceptance lapsing in 10 days
		t.Errorf("expiring_soon = %d, want 1", ov.ExpiringSoon)
	}
	// web risk = (15 + 7) * 2 = 44 ; batch risk = 3 * 1 = 3 ; total 47
	if ov.RiskScore != 47 {
		t.Errorf("risk_score = %v, want 47", ov.RiskScore)
	}
	if ov.OpenBySeverity["critical"] != 1 || ov.OpenBySeverity["high"] != 1 || ov.OpenBySeverity["medium"] != 1 {
		t.Errorf("open_by_severity = %v", ov.OpenBySeverity)
	}
	if ov.OpenByCategory["sca"] != 1 || ov.OpenByCategory["secret"] != 1 || ov.OpenByCategory["cloud"] != 1 {
		t.Errorf("open_by_category = %v", ov.OpenByCategory)
	}
	// Top project is web (44) ahead of batch (3); empty project has no risk row.
	if len(ov.TopProjects) != 2 || ov.TopProjects[0].Slug != "web" || ov.TopProjects[0].RiskScore != 44 {
		t.Errorf("top_projects = %+v", ov.TopProjects)
	}
	// Compliance is averaged across all 3 projects for each seeded framework.
	if len(ov.Compliance) < 2 {
		t.Errorf("compliance frameworks = %d, want >= 2", len(ov.Compliance))
	}
	for _, fa := range ov.Compliance {
		if fa.ProjectsAssessed != 3 {
			t.Errorf("%s assessed %d projects, want 3", fa.Framework, fa.ProjectsAssessed)
		}
		if fa.AvgScore <= 0 || fa.AvgScore > 100 {
			t.Errorf("%s avg score = %v out of range", fa.Framework, fa.AvgScore)
		}
	}
}

// The portfolio's compliance average is the mean of each project's own score
// (compliance.Evaluate): the same rule, aggregated. Projects differ in CWE
// findings, KEV, an SBOM and an attestation so every kind of input moves a score.
func TestPortfolioComplianceMatchesEvaluate(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	a := seedProject(t, pool, "cmp-a", "high")
	b := seedProject(t, pool, "cmp-b", "medium")
	c := seedProject(t, pool, "cmp-c", "low")
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO findings (project_id, fingerprint, scanner, category, title, severity, status, cwe, kev) VALUES ($1,'a1','semgrep','sast','t','critical','open',89,true)`, []any{a}},
		{`INSERT INTO findings (project_id, fingerprint, scanner, category, title, severity, status, cwe) VALUES ($1,'a2','semgrep','sast','t','high','confirmed',79)`, []any{a}},
		{`INSERT INTO findings (project_id, fingerprint, scanner, category, title, severity, status, cwe) VALUES ($1,'b1','semgrep','sast','t','low','open',502)`, []any{b}},
		{`INSERT INTO findings (project_id, fingerprint, scanner, category, title, severity, status, cwe) VALUES ($1,'b2','semgrep','sast','t','high','remediated',89)`, []any{b}},
		{`INSERT INTO sboms (project_id, format, spec_version, artifact) VALUES ($1,'cyclonedx','1.6','web')`, []any{c}},
		{`INSERT INTO control_attestations (project_id, control_id, note, attested_by_email)
		  SELECT $1, c.id, 'process documented', 'a@x' FROM controls c JOIN frameworks fw ON fw.id = c.framework_id
		  WHERE fw.key = 'eu-cra' AND c.assessment = 'manual' LIMIT 1`, []any{c}},
	} {
		if _, err := pool.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatalf("%s: %v", q.sql, err)
		}
	}

	ov, err := portfolio.NewRepository(pool).Overview(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	cmp := compliance.NewRepository(pool)
	if len(ov.Compliance) == 0 {
		t.Fatal("no framework averages")
	}
	for _, fa := range ov.Compliance {
		var sum float64
		for _, p := range []string{a, b, c} {
			res, err := cmp.Evaluate(ctx, p, fa.Framework)
			if err != nil {
				t.Fatal(err)
			}
			sum += res.Score
		}
		// Evaluate rounds each score to 0.1; the portfolio averages unrounded
		// scores and rounds once, so allow that rounding.
		if diff := math.Abs(fa.AvgScore - sum/3); diff > 0.11 {
			t.Errorf("%s: portfolio average %.2f, mean of Evaluate %.2f", fa.Framework, fa.AvgScore, sum/3)
		}
		if fa.ProjectsAssessed != 3 {
			t.Errorf("%s: %d projects assessed, want 3", fa.Framework, fa.ProjectsAssessed)
		}
	}
}

// PORTFOLIO_FROM_SNAPSHOTS: after a snapshot run, the overview served from the
// snapshot rows equals the live one (same rules), says where it came from,
// and narrows to the caller's projects. Before any snapshot exists it falls
// back to live.
func TestPortfolioFromSnapshotsMatchesLive(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	pHigh := seedProject(t, pool, "web", "high")
	pLow := seedProject(t, pool, "batch", "low")
	addFinding(t, pool, pHigh, "a", "trivy", "sca", "critical", "open")
	addFinding(t, pool, pHigh, "b", "trivy", "secret", "high", "confirmed")
	addFinding(t, pool, pLow, "c", "prowler", "cloud", "medium", "open")
	addFinding(t, pool, pLow, "d", "prowler", "cloud", "high", "remediated")
	if _, err := pool.Exec(ctx, `UPDATE findings SET kev = true WHERE fingerprint = 'a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE findings SET epss = 0.7 WHERE fingerprint = 'c'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		WITH f AS (
			INSERT INTO findings (project_id, fingerprint, scanner, category, title, severity, status)
			VALUES ($1, 'e', 'trivy', 'sca', 't', 'low', 'risk_accepted') RETURNING id
		), ra AS (
			INSERT INTO risk_acceptances (project_id, title, state, expires_at)
			VALUES ($1, 'accepted', 'approved', now() + interval '10 days') RETURNING id
		)
		INSERT INTO risk_acceptance_findings (acceptance_id, finding_id) SELECT ra.id, f.id FROM ra, f`, pLow); err != nil {
		t.Fatalf("insert accepted finding: %v", err)
	}

	snap := portfolio.NewRepository(pool).WithSnapshots(true)
	if ov, err := snap.Overview(ctx, nil); err != nil || ov.Source != "live" {
		t.Fatalf("before any snapshot: source %q, %v; want live", ov.Source, err)
	}
	if _, err := metrics.NewRepository(pool).Run(ctx, time.Now()); err != nil {
		t.Fatalf("snapshot run: %v", err)
	}
	if err := portfolio.NewRepository(pool).SnapshotParts(ctx); err != nil {
		t.Fatalf("snapshot parts: %v", err)
	}
	frozen := map[int]portfolio.Overview{}
	for i, pids := range [][]string{nil, {pLow}} {
		live, err := portfolio.NewRepository(pool).Overview(ctx, pids)
		if err != nil {
			t.Fatal(err)
		}
		got, err := snap.Overview(ctx, pids)
		if err != nil {
			t.Fatal(err)
		}
		if got.Source != "snapshots" || got.AsOf == nil {
			t.Errorf("source = %q (as of %v), want snapshots", got.Source, got.AsOf)
		}
		got.Source, got.AsOf = live.Source, live.AsOf
		if !reflect.DeepEqual(got, live) {
			t.Errorf("projects %v:\n snapshots %+v\n live      %+v", pids, got, live)
		}
		if len(got.Compliance) == 0 || got.SLA.OnTrack+got.SLA.DueSoon+got.SLA.Breached == 0 {
			t.Errorf("projects %v: compliance %v / SLA %+v empty, the comparison proves nothing", pids, got.Compliance, got.SLA)
		}
		frozen[i] = got
	}

	// Every part is served from the snapshot run: a finding added since
	// moves the live view but not the snapshot one, SLA included.
	addFinding(t, pool, pLow, "f", "trivy", "sca", "critical", "open")
	for i, pids := range [][]string{nil, {pLow}} {
		live, _ := portfolio.NewRepository(pool).Overview(ctx, pids)
		got, err := snap.Overview(ctx, pids)
		if err != nil {
			t.Fatal(err)
		}
		got.Source, got.AsOf = frozen[i].Source, frozen[i].AsOf
		if !reflect.DeepEqual(got, frozen[i]) {
			t.Errorf("projects %v: snapshot view moved with live data:\n now    %+v\n before %+v", pids, got, frozen[i])
		}
		if reflect.DeepEqual(live.SLA, got.SLA) && live.TotalOpen == got.TotalOpen {
			t.Errorf("projects %v: live view didn't change either; the check proves nothing", pids)
		}
	}
}
