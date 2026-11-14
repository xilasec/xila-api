package sla_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/sla"
)

const day = 24 * time.Hour

func seed(t *testing.T, pool *pgxpool.Pool) (orgID, projectID string) {
	t.Helper()
	ctx := context.Background()
	if err := pool.QueryRow(ctx, `INSERT INTO organizations (slug, name) VALUES ('o-sla', 'o') RETURNING id`).Scan(&orgID); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	var teamID string
	if err := pool.QueryRow(ctx, `INSERT INTO teams (org_id, slug, name) VALUES ($1, 't', 'T') RETURNING id`, orgID).Scan(&teamID); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO projects (team_id, slug, name) VALUES ($1, 'p', 'P') RETURNING id`, teamID).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return orgID, projectID
}

func upsert(t *testing.T, repo *finding.Repository, projectID, fp string, sev domain.Severity) finding.Finding {
	t.Helper()
	f, err := repo.Upsert(context.Background(), finding.Finding{
		ProjectID: projectID, Fingerprint: fp, Scanner: "trivy", Category: domain.CategorySCA,
		Title: fp, Severity: sev, Metadata: map[string]any{},
	})
	if err != nil {
		t.Fatalf("upsert %s: %v", fp, err)
	}
	return f
}

func get(t *testing.T, repo *finding.Repository, id string) finding.Finding {
	t.Helper()
	f, err := repo.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	return f
}

// window is how long a finding was given: due - first seen.
func window(f finding.Finding) time.Duration {
	if f.SLADueAt == nil {
		return -1
	}
	return f.SLADueAt.Sub(f.FirstSeenAt)
}

// The most specific stored policy wins (project > org > global > built-in), and
// changing or removing one re-applies the result to existing findings.
func TestPolicyPrecedenceReappliesToFindings(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := sla.NewRepository(pool)
	findings := finding.NewRepository(pool)
	orgID, projectID := seed(t, pool)
	crit := upsert(t, findings, projectID, "crit", domain.SeverityCritical)
	info := upsert(t, findings, projectID, "info", domain.SeverityInfo)
	project, org := sla.Target{ProjectID: &projectID}, sla.Target{OrgID: &orgID}

	check := func(step string, wantScope string, wantCritDays int) {
		t.Helper()
		eff, err := repo.EffectiveFor(ctx, project)
		if err != nil {
			t.Fatalf("%s: effective: %v", step, err)
		}
		if eff.Scope != wantScope {
			t.Errorf("%s: scope = %q, want %q", step, eff.Scope, wantScope)
		}
		got := get(t, findings, crit.ID)
		if got.SLADays == nil || *got.SLADays != wantCritDays || window(got) != time.Duration(wantCritDays)*day {
			t.Errorf("%s: critical sla_days=%v window=%v, want %d days", step, got.SLADays, window(got), wantCritDays)
		}
	}

	check("built-in default", sla.ScopeDefault, 7)
	if got := get(t, findings, info.ID); got.SLADueAt != nil || got.SLAStatus != domain.SLANone {
		t.Errorf("info has no default SLA, got due=%v status=%q", got.SLADueAt, got.SLAStatus)
	}

	put := func(target sla.Target, d sla.Days) {
		t.Helper()
		if _, err := repo.Put(ctx, target, d); err != nil {
			t.Fatalf("put: %v", err)
		}
	}
	put(sla.Global, sla.Days{Critical: new(10)})
	check("global", sla.ScopeGlobal, 10)
	put(org, sla.Days{Critical: new(5)})
	check("org overrides global", sla.ScopeOrg, 5)
	put(project, sla.Days{Critical: new(3), Info: new(30)})
	check("project overrides org", sla.ScopeProject, 3)
	if got := get(t, findings, info.ID); got.SLADays == nil || *got.SLADays != 30 {
		t.Errorf("project policy should give info an SLA, got %v", got.SLADays)
	}

	if err := repo.Delete(ctx, project); err != nil {
		t.Fatalf("delete project policy: %v", err)
	}
	check("project removed → org", sla.ScopeOrg, 5)
	if got := get(t, findings, info.ID); got.SLADueAt != nil {
		t.Errorf("org policy has no info SLA, so the deadline must be cleared, got %v", got.SLADueAt)
	}
	if err := repo.Delete(ctx, org); err != nil {
		t.Fatalf("delete org policy: %v", err)
	}
	check("org removed → global", sla.ScopeGlobal, 10)
	if err := repo.Delete(ctx, sla.Global); err != nil {
		t.Fatalf("delete global policy: %v", err)
	}
	check("global removed → default", sla.ScopeDefault, 7)
}

// An exception stops the clock; reopening adds the paused time to the deadline.
// A severity change re-resolves the window. Both happen in the trigger, so they
// hold no matter which code path changed the finding.
func TestClockPausesDuringExceptionAndFollowsSeverity(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findings := finding.NewRepository(pool)
	_, projectID := seed(t, pool)
	f := upsert(t, findings, projectID, "f", domain.SeverityCritical)

	if _, err := findings.SetStatus(ctx, f.ID, finding.Triage{Status: domain.FindingWontFix, Reason: "later"}); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if got := get(t, findings, f.ID); got.SLAStatus != domain.SLAPaused {
		t.Errorf("accepted finding status = %q, want paused", got.SLAStatus)
	}
	// Pretend the acceptance began three days ago. Exact hours, not '3 days': a
	// calendar day across a DST change is 23 or 25 hours.
	if _, err := pool.Exec(ctx, `UPDATE findings SET sla_paused_at = sla_paused_at - interval '72 hours' WHERE id = $1`, f.ID); err != nil {
		t.Fatalf("backdate pause: %v", err)
	}
	if _, err := findings.SetStatus(ctx, f.ID, finding.Triage{Status: domain.FindingOpen}); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got := get(t, findings, f.ID)
	if w := window(got); w < 10*day || w > 10*day+time.Minute {
		t.Errorf("window after a 3-day pause = %v, want 7d + 3d", w)
	}

	low, err := findings.SetSeverity(ctx, f.ID, domain.SeverityLow)
	if err != nil {
		t.Fatalf("set severity: %v", err)
	}
	if low.SLADays == nil || *low.SLADays != 120 {
		t.Errorf("low sla_days = %v, want 120", low.SLADays)
	}
	if w := window(low); w < 123*day || w > 123*day+time.Minute {
		t.Errorf("window after downgrade = %v, want 120d + the 3d already paused", w)
	}
}

// The sweep alerts each finding once per deadline; filters and stats agree with
// the per-finding status.
func TestSweepFiltersAndStats(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := sla.NewRepository(pool)
	findings := finding.NewRepository(pool)
	_, projectID := seed(t, pool)

	overdue := upsert(t, findings, projectID, "overdue", domain.SeverityCritical) // 7-day window
	soon := upsert(t, findings, projectID, "soon", domain.SeverityHigh)           // 30-day window
	fine := upsert(t, findings, projectID, "fine", domain.SeverityMedium)         // 90-day window
	age := func(id string, by time.Duration) {
		t.Helper()
		if _, err := pool.Exec(ctx, `UPDATE findings SET first_seen_at = now() - $2::interval WHERE id = $1`,
			id, by.String()); err != nil {
			t.Fatalf("age finding: %v", err)
		}
	}
	age(overdue.ID, 8*day) // 1 day past due
	age(soon.ID, 25*day)   // 5 days left of 30: inside the last 7.5

	breached, err := repo.MarkBreached(ctx)
	if err != nil {
		t.Fatalf("mark breached: %v", err)
	}
	if len(breached) != 1 || breached[0].FindingID != overdue.ID || breached[0].ProjectName != "P" {
		t.Fatalf("breached = %+v, want only the overdue finding", breached)
	}
	dueSoon, err := repo.MarkDueSoon(ctx, domain.SLADueSoonFraction)
	if err != nil {
		t.Fatalf("mark due soon: %v", err)
	}
	if len(dueSoon) != 1 || dueSoon[0].FindingID != soon.ID {
		t.Fatalf("due soon = %+v, want only the due-soon finding", dueSoon)
	}
	if again, _ := repo.MarkBreached(ctx); len(again) != 0 {
		t.Errorf("second sweep re-alerted %d finding(s); each deadline alerts once", len(again))
	}
	if again, _ := repo.MarkDueSoon(ctx, domain.SLADueSoonFraction); len(again) != 0 {
		t.Errorf("second sweep re-warned %d finding(s)", len(again))
	}

	for status, want := range map[domain.SLAStatus]string{
		domain.SLABreached: overdue.ID, domain.SLADueSoon: soon.ID, domain.SLAOnTrack: fine.ID,
	} {
		list, err := findings.List(ctx, finding.Filter{ProjectID: projectID, SLA: status})
		if err != nil {
			t.Fatalf("list %s: %v", status, err)
		}
		if len(list) != 1 || list[0].ID != want || list[0].SLAStatus != status {
			t.Errorf("?sla=%s → %d finding(s), want exactly %s", status, len(list), want)
		}
	}

	// Fixing the overdue finding now is a missed SLA.
	if _, err := findings.SetStatus(ctx, overdue.ID, finding.Triage{Status: domain.FindingRemediated}); err != nil {
		t.Fatalf("remediate: %v", err)
	}
	stats, err := findings.SLAStats(ctx, []string{projectID})
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Breached != 0 || stats.DueSoon != 1 || stats.OnTrack != 1 || stats.Missed != 1 || stats.Met != 0 {
		t.Errorf("stats = %+v, want 0 breached / 1 due soon / 1 on track / 1 missed", stats)
	}
	if stats.Compliance == nil || *stats.Compliance != 0 {
		t.Errorf("compliance = %v, want 0 (the only fix was late)", stats.Compliance)
	}
	if mttr := stats.MTTRDays[domain.SeverityCritical]; mttr < 7.9 || mttr > 8.1 {
		t.Errorf("critical MTTR = %.2f days, want ≈ 8", mttr)
	}
	if other, _ := findings.SLAStats(ctx, []string{}); other.OnTrack != 0 {
		t.Errorf("an empty project scope must see nothing, got %+v", other)
	}
}
