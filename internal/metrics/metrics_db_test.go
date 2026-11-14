package metrics_test

import (
	"context"
	"math"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/metrics"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/portfolio"
)

type fixture struct {
	pool             *pgxpool.Pool
	orgID            string
	team1, team2, t3 string
	p1, p2           string
}

func seed(t *testing.T, pool *pgxpool.Pool) fixture {
	t.Helper()
	ctx := context.Background()
	f := fixture{pool: pool}
	must := func(err error, what string) {
		if err != nil {
			t.Fatalf("seed %s: %v", what, err)
		}
	}
	must(pool.QueryRow(ctx, `INSERT INTO organizations (slug, name) VALUES ('acme', 'Acme') RETURNING id`).Scan(&f.orgID), "org")
	for _, tm := range []struct {
		slug string
		dst  *string
	}{{"t1", &f.team1}, {"t2", &f.team2}, {"t3", &f.t3}} {
		must(pool.QueryRow(ctx, `INSERT INTO teams (org_id, slug, name) VALUES ($1, $2, $2) RETURNING id`, f.orgID, tm.slug).Scan(tm.dst), "team")
	}
	must(pool.QueryRow(ctx, `INSERT INTO projects (team_id, slug, name, business_criticality) VALUES ($1, 'web', 'web', 'high') RETURNING id`, f.team1).Scan(&f.p1), "project")
	must(pool.QueryRow(ctx, `INSERT INTO projects (team_id, slug, name, business_criticality) VALUES ($1, 'batch', 'batch', 'low') RETURNING id`, f.team2).Scan(&f.p2), "project")
	return f
}

// add inserts a finding on the project's default version (or versionID) with
// explicit lifecycle timestamps; it returns the id.
func (f fixture) add(t *testing.T, projectID, sev, status string, firstSeen time.Time, resolved *time.Time, opts ...func(*addOpts)) string {
	t.Helper()
	o := addOpts{}
	for _, fn := range opts {
		fn(&o)
	}
	var id string
	if err := f.pool.QueryRow(context.Background(), `
		INSERT INTO findings (project_id, version_id, fingerprint, scanner, category, title, severity, status,
		                      first_seen_at, last_seen_at, resolved_at, duplicate_of)
		VALUES ($1, $2, gen_random_uuid()::text, 'trivy', 'sca', 't', $3, $4, $5, $5, $6, $7)
		RETURNING id`,
		projectID, o.versionID, sev, status, firstSeen, resolved, o.duplicateOf).Scan(&id); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	return id
}

type addOpts struct {
	versionID   *string
	duplicateOf *string
}

func dupOf(id string) func(*addOpts)     { return func(o *addOpts) { o.duplicateOf = &id } }
func onVersion(id string) func(*addOpts) { return func(o *addOpts) { o.versionID = &id } }

func utcDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func pointOn(t *testing.T, points []metrics.Point, day time.Time) metrics.Point {
	t.Helper()
	want := day.Format(time.DateOnly)
	for _, p := range points {
		if p.Date == want {
			return p
		}
	}
	t.Fatalf("no point for %s in %+v", want, points)
	return metrics.Point{}
}

func TestSnapshotPastDay(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := metrics.NewRepository(pool)
	ctx := context.Background()
	f := seed(t, pool)

	now := time.Now()
	d := utcDay(now).AddDate(0, 0, -10) // the day under test
	at := func(days float64) time.Time { return d.Add(time.Duration(days * 24 * float64(time.Hour))) }

	// web (criticality high ⇒ ×2). Default SLAs: critical 7d, high 30d, medium 90d, low 120d.
	a := f.add(t, f.p1, "critical", "open", at(-5), nil)              // open, due d+2: not breached
	f.add(t, f.p1, "high", "open", at(-40), nil)                      // open, due d-10: breached
	f.add(t, f.p1, "medium", "remediated", at(-20), new(at(0.25)))    // closed on d, on time, 20.25 days
	f.add(t, f.p1, "critical", "remediated", at(-10), new(at(0.5)))   // closed on d, late (due d-3), 10.5 days
	f.add(t, f.p1, "low", "open", at(0.125), nil)                     // new on d, open
	f.add(t, f.p1, "high", "open", at(5), nil)                        // first seen after d: absent
	f.add(t, f.p1, "critical", "risk_accepted", at(-30), new(at(-2))) // accepted before d: not open
	f.add(t, f.p1, "medium", "false_positive", at(-30), new(at(3)))   // dismissed after d: open on d
	f.add(t, f.p1, "high", "remediated", at(-50), new(at(2)))         // fixed after d: open + breached on d
	f.add(t, f.p1, "critical", "open", at(-5), nil, dupOf(a))         // cross-tool duplicate: excluded
	var branch string
	if err := pool.QueryRow(ctx, `SELECT project_version($1, 'feature/x', 'branch')`, f.p1).Scan(&branch); err != nil {
		t.Fatalf("branch version: %v", err)
	}
	f.add(t, f.p1, "critical", "open", at(-5), nil, onVersion(branch)) // feature branch: excluded
	// batch (criticality low ⇒ ×1).
	f.add(t, f.p2, "medium", "open", at(-1), nil)

	if err := repo.Snapshot(ctx, d.Add(13*time.Hour)); err != nil { // any instant in the day
		t.Fatalf("Snapshot: %v", err)
	}

	web, err := repo.Trend(ctx, metrics.ScopeProject, f.p1, 11, now)
	if err != nil {
		t.Fatalf("Trend: %v", err)
	}
	if len(web) != 1 {
		t.Fatalf("only the snapshotted day should be returned (no zero-fill), got %d points", len(web))
	}
	p := pointOn(t, web, d)
	wantOpen := map[domain.Severity]int{"critical": 1, "high": 2, "medium": 1, "low": 1, "info": 0}
	for sev, n := range wantOpen {
		if p.OpenBySeverity[sev] != n {
			t.Errorf("open %s = %d, want %d (all: %v)", sev, p.OpenBySeverity[sev], n, p.OpenBySeverity)
		}
	}
	if p.OpenTotal != 5 || p.New != 1 || p.Closed != 2 {
		t.Errorf("open/new/closed = %d/%d/%d, want 5/1/2", p.OpenTotal, p.New, p.Closed)
	}
	// (15 + 2×7 + 3 + 1) × 2
	if p.RiskScore != 66 {
		t.Errorf("risk = %v, want 66", p.RiskScore)
	}
	if p.SLABreached != 2 || p.SLAMet != 1 || p.SLAMissed != 1 {
		t.Errorf("sla breached/met/missed = %d/%d/%d, want 2/1/1", p.SLABreached, p.SLAMet, p.SLAMissed)
	}
	if p.SLACompliance == nil || *p.SLACompliance != 0.5 {
		t.Errorf("sla compliance = %v, want 0.5", p.SLACompliance)
	}
	// (20.25 + 10.5) / 2 = 15.375
	if p.MTTRDays == nil || math.Abs(*p.MTTRDays-15.4) > 1e-9 {
		t.Errorf("mttr = %v, want 15.4", p.MTTRDays)
	}
	if p.Reconstructed {
		t.Error("a direct Snapshot is not reconstructed")
	}

	// Rollups: team = its project, org/portfolio = both, empty team = zeros.
	org, _ := repo.Trend(ctx, metrics.ScopeOrg, f.orgID, 11, now)
	pf, _ := repo.Trend(ctx, metrics.ScopePortfolio, "", 11, now)
	for name, pts := range map[string][]metrics.Point{"org": org, "portfolio": pf} {
		q := pointOn(t, pts, d)
		if q.OpenTotal != 6 || q.RiskScore != 69 || q.Closed != 2 || q.SLABreached != 2 {
			t.Errorf("%s = open %d risk %v closed %d breached %d, want 6/69/2/2", name, q.OpenTotal, q.RiskScore, q.Closed, q.SLABreached)
		}
	}
	empty, _ := repo.Trend(ctx, metrics.ScopeTeam, f.t3, 11, now)
	if q := pointOn(t, empty, d); q.OpenTotal != 0 || q.SLACompliance != nil || q.MTTRDays != nil {
		t.Errorf("empty team = %+v, want zeros with nil ratios", q)
	}

	// Aggregating project rows (the RBAC-scoped path) matches the stored rows.
	only, _ := repo.ProjectsTrend(ctx, []string{f.p1}, "", 11, now)
	if q := pointOn(t, only, d); q.OpenTotal != 5 || q.RiskScore != 66 || q.MTTRDays == nil || *q.MTTRDays != 15.4 {
		t.Errorf("projects trend [web] = %+v", q)
	}
	both, _ := repo.ProjectsTrend(ctx, []string{f.p1, f.p2}, f.orgID, 11, now)
	if q := pointOn(t, both, d); q.OpenTotal != 6 || q.RiskScore != 69 {
		t.Errorf("projects trend [web, batch] in org = %+v", q)
	}
	otherOrg, _ := repo.ProjectsTrend(ctx, []string{f.p1, f.p2}, "00000000-0000-0000-0000-000000000001", 11, now)
	if len(otherOrg) != 0 {
		t.Errorf("projects outside the org must not count, got %+v", otherOrg)
	}

	// Re-running a day overwrites it: same rows, current state.
	if _, err := pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, f.p2); err != nil {
		t.Fatalf("delete project: %v", err)
	}
	if err := repo.Snapshot(ctx, d); err != nil {
		t.Fatalf("re-Snapshot: %v", err)
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM metric_snapshots WHERE day = $1`, d).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 6 { // portfolio + org + 3 teams + web (batch is gone)
		t.Errorf("rows for day after rerun = %d, want 6", rows)
	}
	pf, _ = repo.Trend(ctx, metrics.ScopePortfolio, "", 11, now)
	if q := pointOn(t, pf, d); q.OpenTotal != 5 || q.RiskScore != 66 {
		t.Errorf("portfolio after rerun = open %d risk %v, want 5/66", q.OpenTotal, q.RiskScore)
	}
}

// Today's snapshot must agree with the live views (portfolio rollup, project
// summary counts, SLA stats) — the trend's last point is "now".
func TestSnapshotTodayMatchesLiveViews(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := metrics.NewRepository(pool)
	ctx := context.Background()
	f := seed(t, pool)

	now := time.Now()
	ago := func(days int) time.Time { return now.Add(-time.Duration(days) * 24 * time.Hour) }
	f.add(t, f.p1, "critical", "open", ago(10), nil) // breached (7d)
	f.add(t, f.p1, "high", "confirmed", ago(1), nil)
	f.add(t, f.p1, "medium", "risk_accepted", ago(3), new(ago(1)))
	f.add(t, f.p1, "low", "remediated", ago(3), new(now.Add(-time.Minute)))
	f.add(t, f.p2, "info", "open", ago(400), nil)
	f.add(t, f.p2, "medium", "open", ago(100), nil) // breached (90d)

	if err := repo.Snapshot(ctx, now); err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	pts, err := repo.Trend(ctx, metrics.ScopePortfolio, "", 1, now)
	if err != nil || len(pts) != 1 {
		t.Fatalf("Trend = %v, %v", pts, err)
	}
	got := pts[0]

	ov, err := portfolio.NewRepository(pool).Overview(ctx, nil)
	if err != nil {
		t.Fatalf("Overview: %v", err)
	}
	if got.OpenTotal != ov.TotalOpen || got.RiskScore != ov.RiskScore {
		t.Errorf("snapshot open/risk = %d/%v, portfolio = %d/%v", got.OpenTotal, got.RiskScore, ov.TotalOpen, ov.RiskScore)
	}
	for sev, n := range ov.OpenBySeverity {
		if got.OpenBySeverity[sev] != n {
			t.Errorf("open %s = %d, portfolio %d", sev, got.OpenBySeverity[sev], n)
		}
	}
	sla, err := finding.NewRepository(pool).SLAStats(ctx, nil)
	if err != nil {
		t.Fatalf("SLAStats: %v", err)
	}
	if got.SLABreached != sla.Breached || sla.Breached != 2 {
		t.Errorf("breached = %d, live SLA = %d (want 2)", got.SLABreached, sla.Breached)
	}
	if got.Closed != 1 || got.New != 0 {
		t.Errorf("closed/new = %d/%d, want 1/0", got.Closed, got.New)
	}
}

func TestRunBackfillsOnce(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := metrics.NewRepository(pool)
	ctx := context.Background()
	f := seed(t, pool)
	now := time.Now()
	f.add(t, f.p1, "high", "open", now.Add(-30*24*time.Hour), nil) // first seen 30 days ago

	res, err := repo.Run(ctx, now)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	today := utcDay(now)
	if res.Backfilled != metrics.BackfillDays-2 || len(res.Days) != 2 ||
		res.Days[0] != today.AddDate(0, 0, -1).Format(time.DateOnly) || res.Days[1] != today.Format(time.DateOnly) {
		t.Errorf("Run = %+v, want %d backfilled + [yesterday today]", res, metrics.BackfillDays-2)
	}

	pts, err := repo.Trend(ctx, metrics.ScopeProject, f.p1, metrics.BackfillDays, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(pts) != metrics.BackfillDays {
		t.Fatalf("points = %d, want %d", len(pts), metrics.BackfillDays)
	}
	if pts[0].Date != today.AddDate(0, 0, -(metrics.BackfillDays-1)).Format(time.DateOnly) {
		t.Errorf("first point %s, want oldest first", pts[0].Date)
	}
	for i, p := range pts {
		wantRecon := i < len(pts)-2
		if p.Reconstructed != wantRecon {
			t.Errorf("%s reconstructed = %v, want %v", p.Date, p.Reconstructed, wantRecon)
		}
	}
	// The finding appears in history from the day it was first seen.
	firstSeen := utcDay(now.Add(-30 * 24 * time.Hour))
	if p := pointOn(t, pts, firstSeen.AddDate(0, 0, -1)); p.OpenTotal != 0 {
		t.Errorf("day before first seen open = %d, want 0", p.OpenTotal)
	}
	if p := pointOn(t, pts, firstSeen); p.OpenTotal != 1 || p.New != 1 {
		t.Errorf("first-seen day open/new = %d/%d, want 1/1", p.OpenTotal, p.New)
	}

	// Later runs only refresh yesterday + today.
	res, err = repo.Run(ctx, now)
	if err != nil || res.Backfilled != 0 {
		t.Errorf("second Run = %+v, %v; want no backfill", res, err)
	}
}
