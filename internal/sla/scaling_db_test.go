package sla_test

import (
	"context"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/sla"
)

// Criticality scaling is one switch that moves every deadline: turning it on
// re-windows the existing backlog, editing a project's criticality re-windows
// that project, and turning it off restores the policy's own windows.
func TestCriticalityScalingMovesExistingDeadlines(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := sla.NewRepository(pool)
	findings := finding.NewRepository(pool)
	_, projectID := seed(t, pool)
	var mediumProject string
	if err := pool.QueryRow(ctx, `INSERT INTO projects (team_id, slug, name)
		SELECT team_id, 'p2', 'P2' FROM projects WHERE id = $1 RETURNING id`, projectID).Scan(&mediumProject); err != nil {
		t.Fatalf("seed second project: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE projects SET business_criticality = 'critical' WHERE id = $1`, projectID); err != nil {
		t.Fatalf("set criticality: %v", err)
	}
	crit := upsert(t, findings, projectID, "crit", domain.SeverityCritical)
	high := upsert(t, findings, projectID, "high", domain.SeverityHigh)
	info := upsert(t, findings, projectID, "info", domain.SeverityInfo)
	other := upsert(t, findings, mediumProject, "crit", domain.SeverityCritical)

	days := func(f finding.Finding) int {
		t.Helper()
		g := get(t, findings, f.ID)
		if g.SLADays == nil {
			return 0
		}
		if got := window(g); got != time.Duration(*g.SLADays)*day {
			t.Fatalf("%s: due date window %v does not match sla_days %d", f.Fingerprint, got, *g.SLADays)
		}
		return *g.SLADays
	}
	expect := func(step string, want map[*finding.Finding]int) {
		t.Helper()
		for f, w := range want {
			if got := days(*f); got != w {
				t.Errorf("%s: %s (%s project) = %d days, want %d", step, f.Fingerprint, f.ProjectID[:8], got, w)
			}
		}
	}

	// Off (the default): the built-in 7/30/90/120 applies to everyone.
	expect("off", map[*finding.Finding]int{&crit: 7, &high: 30, &info: 0, &other: 7})

	defaults, err := repo.Settings(ctx)
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	if defaults.ScaleByCriticality || defaults.Factors != (sla.Factors{Critical: 0.5, High: 0.75, Medium: 1, Low: 1.5}) {
		t.Fatalf("default settings = %+v", defaults)
	}

	// On: the critical project's existing findings tighten (7×0.5 = 3.5 → 4,
	// 30×0.5 = 15); no-SLA stays no SLA; a medium project is unchanged.
	on := defaults
	on.ScaleByCriticality = true
	if _, err := repo.PutSettings(ctx, on); err != nil {
		t.Fatalf("enable scaling: %v", err)
	}
	expect("on", map[*finding.Finding]int{&crit: 4, &high: 15, &info: 0, &other: 7})

	// Editing the project's criticality moves its deadlines (7×1.5 = 10.5 → 11).
	if _, err := pool.Exec(ctx, `UPDATE projects SET business_criticality = 'low' WHERE id = $1`, projectID); err != nil {
		t.Fatalf("lower criticality: %v", err)
	}
	expect("project now low", map[*finding.Finding]int{&crit: 11, &high: 45, &other: 7})

	// The API's views agree with what the findings got.
	eff, err := repo.EffectiveFor(ctx, sla.Target{ProjectID: &projectID})
	if err != nil {
		t.Fatalf("effective: %v", err)
	}
	if eff.Criticality != "low" || eff.Applied == nil || *eff.Applied.Critical != 11 || *eff.Critical != 7 {
		t.Errorf("effective = %+v (applied %+v), want policy 7 scaled to 11 for a low project", eff, eff.Applied)
	}
	m, err := repo.Matrix(ctx)
	if err != nil {
		t.Fatalf("matrix: %v", err)
	}
	if *m["critical"].Critical != 4 || *m["medium"].Critical != 7 || *m["low"].Low != 180 || m["critical"].Info != nil {
		t.Errorf("matrix = critical %+v, medium %+v, low %+v", m["critical"], m["medium"], m["low"])
	}

	// A window never scales below one day.
	tiny := on
	tiny.Factors.Low = 0.1
	if _, err := repo.Put(ctx, sla.Global, sla.Days{Critical: new(1), High: new(30)}); err != nil {
		t.Fatalf("put policy: %v", err)
	}
	if _, err := repo.PutSettings(ctx, tiny); err != nil {
		t.Fatalf("tiny factor: %v", err)
	}
	expect("factor 0.1 on a 1-day window", map[*finding.Finding]int{&crit: 1, &high: 3})

	// Off again: the policy's own windows, for the whole backlog.
	if _, err := repo.PutSettings(ctx, defaults); err != nil {
		t.Fatalf("disable scaling: %v", err)
	}
	expect("off again", map[*finding.Finding]int{&crit: 1, &high: 30, &other: 1})
	if eff, _ := repo.EffectiveFor(ctx, sla.Target{ProjectID: &projectID}); eff.Applied != nil {
		t.Errorf("applied = %+v with scaling off, want none", eff.Applied)
	}
}
