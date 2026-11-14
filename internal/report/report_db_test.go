package report_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/compliance"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/portfolio"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/report"
)

func seedProject(t *testing.T, pool *pgxpool.Pool, slug, criticality string) string {
	t.Helper()
	var teamID, projectID string
	ctx := context.Background()
	if err := pool.QueryRow(ctx, `WITH o AS (INSERT INTO organizations (slug, name) VALUES ('o-'||$1, $1) RETURNING id)
		INSERT INTO teams (org_id, slug, name) SELECT id, $1, $1 FROM o RETURNING id`, "team-"+slug).Scan(&teamID); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (team_id, slug, name, business_criticality) VALUES ($1,$2,$2,$3) RETURNING id`,
		teamID, slug, criticality).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return projectID
}

// addFinding inserts a finding first seen `age` ago (so SLA deadlines can be
// past) and returns its id.
func addFinding(t *testing.T, pool *pgxpool.Pool, projectID, fp, severity, status, age string, kev bool) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO findings (project_id, fingerprint, scanner, category, title, severity, status, kev, first_seen_at, priority)
		 VALUES ($1,$2,'trivy','sca',$2,$3,$4,$5, now() - $6::interval,
		         CASE $3 WHEN 'critical' THEN 15 WHEN 'high' THEN 7 WHEN 'medium' THEN 3 ELSE 1 END) RETURNING id`,
		projectID, fp, severity, status, kev, age).Scan(&id); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	return id
}

func TestProjectRowsMatchPortfolioRollup(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()

	web := seedProject(t, pool, "web", "high")    // multiplier 2
	batch := seedProject(t, pool, "batch", "low") // multiplier 1
	empty := seedProject(t, pool, "empty", "medium")

	primary := addFinding(t, pool, web, "crit", "critical", "open", "60 days", true)
	addFinding(t, pool, web, "high", "high", "confirmed", "1 hour", false)
	addFinding(t, pool, web, "fixed", "critical", "remediated", "1 hour", false)
	// A cross-tool duplicate of the critical: never counted twice.
	dup := addFinding(t, pool, web, "crit-grype", "critical", "open", "60 days", true)
	if _, err := pool.Exec(ctx, `UPDATE findings SET duplicate_of = $1 WHERE id = $2`, primary, dup); err != nil {
		t.Fatal(err)
	}
	// The same issue on a feature branch: not part of what the report covers.
	var branch string
	if err := pool.QueryRow(ctx, `INSERT INTO project_versions (project_id, name, kind) VALUES ($1, 'feature-x', 'branch') RETURNING id`, web).Scan(&branch); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO findings (project_id, version_id, fingerprint, scanner, category, title, severity, status)
		VALUES ($1, $2, 'branch-crit', 'trivy', 'sca', 't', 'critical', 'open')`, web, branch); err != nil {
		t.Fatal(err)
	}
	addFinding(t, pool, batch, "med", "medium", "open", "1 hour", false)

	repo := report.NewRepository(pool)
	rows, err := repo.ProjectRows(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("got %d rows, want all 3 projects (incl. the empty one)", len(rows))
	}
	// Ordered by risk: web (15+7)*2 = 44, batch 3*1 = 3, empty 0.
	if rows[0].ID != web || rows[1].ID != batch || rows[2].ID != empty {
		t.Fatalf("order = %s, %s, %s", rows[0].Slug, rows[1].Slug, rows[2].Slug)
	}
	w := rows[0]
	if w.Critical != 1 || w.High != 1 || w.TotalOpen != 2 || w.KEVOpen != 1 || w.RiskScore != 44 {
		t.Errorf("web row = %+v; want 1 critical, 1 high, 2 open, 1 KEV, risk 44 (no duplicate, no branch, no remediated)", w)
	}
	var defaultBranch string
	if err := pool.QueryRow(ctx, `SELECT name FROM project_versions WHERE project_id = $1 AND is_default`, web).Scan(&defaultBranch); err != nil {
		t.Fatal(err)
	}
	if w.DefaultBranch != defaultBranch {
		t.Errorf("default branch = %q, want %q", w.DefaultBranch, defaultBranch)
	}
	if rows[2].TotalOpen != 0 || rows[2].RiskScore != 0 {
		t.Errorf("empty row = %+v", rows[2])
	}

	// The table adds up to the rollup it sits under.
	pf := portfolio.NewRepository(pool)
	ov, err := pf.Overview(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var risk float64
	var open, breached int
	for _, r := range rows {
		risk += r.RiskScore
		open += r.TotalOpen
		breached += r.SLABreached
	}
	if risk != ov.RiskScore || open != ov.TotalOpen || breached != ov.SLA.Breached {
		t.Errorf("rows sum to risk %v / open %d / breached %d; rollup says %v / %d / %d",
			risk, open, breached, ov.RiskScore, ov.TotalOpen, ov.SLA.Breached)
	}

	// Scoped: only the requested projects; an empty scope is empty.
	if scoped, _ := repo.ProjectRows(ctx, []string{batch}); len(scoped) != 1 || scoped[0].ID != batch {
		t.Errorf("scoped rows = %+v", scoped)
	}
	if none, _ := repo.ProjectRows(ctx, []string{}); len(none) != 0 {
		t.Errorf("empty scope returned %d rows", len(none))
	}

	// End to end through the real repositories: the project report lists the
	// default-branch findings once, and names the excluded branch.
	svc := report.NewService(pf, finding.NewRepository(pool), compliance.NewRepository(pool),
		project.NewRepository(pool), repo)
	rep, err := svc.Project(ctx, web, report.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Top) != 2 || rep.Top[0].ID != primary {
		t.Errorf("top = %d findings (first %v), want the 2 live default-branch ones, critical first", len(rep.Top), rep.Top)
	}
	if rep.Branch != defaultBranch || strings.Join(rep.OtherBranches, ",") != "feature-x" {
		t.Errorf("branches = %q / %v", rep.Branch, rep.OtherBranches)
	}
	if rep.Overview.RiskScore != 44 || len(rep.Compliance) == 0 {
		t.Errorf("project report risk %v, %d frameworks", rep.Overview.RiskScore, len(rep.Compliance))
	}
}
