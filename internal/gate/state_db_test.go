package gate_test

import (
	"context"
	"sync"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/gate"
	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
)

// recordingNotifier records every event.
type recordingNotifier struct {
	mu     sync.Mutex
	events []notify.Event
}

func (r *recordingNotifier) Notify(_ context.Context, e notify.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// The stored gate result (13.7) flips on a change, alerts once per flip in
// each direction and never while steady, and fails_gate shows the backlog of
// a project whose default-version gate fails, and not because a branch fails.
func TestGateStateFlipsAndFilter(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	frepo := finding.NewRepository(pool)
	grepo := gate.NewRepository(pool)
	projects := project.NewRepository(pool)
	rec := &recordingNotifier{}
	eval := gate.NewEvaluator(grepo, frepo, projects, nil, rec)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-gs','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	// The first version a project gets is its default.
	var mainID, branch string
	if err := pool.QueryRow(ctx, `SELECT project_version($1, 'main', 'branch')`, projectID).Scan(&mainID); err != nil {
		t.Fatalf("main: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT project_version($1, 'feature', 'branch')`, projectID).Scan(&branch); err != nil {
		t.Fatalf("branch: %v", err)
	}
	zero := 0
	if _, err := grepo.Upsert(ctx, gate.Policy{ProjectID: &projectID, MaxCritical: &zero}); err != nil {
		t.Fatalf("policy: %v", err)
	}
	mk := func(fp, versionID string, sev domain.Severity) finding.Finding {
		f, err := frepo.Upsert(ctx, finding.Finding{ProjectID: projectID, VersionID: versionID, Fingerprint: fp, Scanner: "trivy",
			Category: domain.CategorySCA, RuleID: fp, Title: fp, Severity: sev, Metadata: map[string]any{}})
		if err != nil {
			t.Fatalf("seed %s: %v", fp, err)
		}
		return f
	}
	failsGate := func() int {
		t.Helper()
		list, err := frepo.List(ctx, finding.Filter{FailsGate: true, Limit: 100})
		if err != nil {
			t.Fatalf("list fails_gate: %v", err)
		}
		return len(list)
	}
	flips := func() []string {
		var out []string
		for _, e := range rec.events {
			if e.Type == notify.EventGateChanged {
				out = append(out, e.Fields["passed"])
			}
		}
		return out
	}

	// Default version: a low passes (first evaluation: stored, no alert).
	low := mk("low", "", domain.SeverityLow)
	if r, err := eval.EvaluateVersion(ctx, projectID, ""); err != nil || !r.Passed {
		t.Fatalf("first evaluation = %+v, %v", r, err)
	}
	// The branch fails on its own critical: its gate fails, the default's doesn't.
	mk("crit-branch", branch, domain.SeverityCritical)
	if r, err := eval.EvaluateVersion(ctx, projectID, branch); err != nil || r.Passed {
		t.Fatalf("branch evaluation = %+v, %v", r, err)
	}
	if n := failsGate(); n != 0 {
		t.Errorf("fails_gate with only the branch failing = %d, want 0", n)
	}

	// A critical on the default version flips it to failing: one alert.
	mk("crit", "", domain.SeverityCritical)
	for range 2 { // steady after the flip: still one alert
		if _, err := eval.EvaluateVersion(ctx, projectID, ""); err != nil {
			t.Fatalf("evaluate: %v", err)
		}
	}
	if got := flips(); len(got) != 1 || got[0] != "false" {
		t.Errorf("flips = %v, want one to failing", got)
	}
	if n := failsGate(); n != 2 {
		t.Errorf("fails_gate on a failing default gate = %d, want its 2 open findings", n)
	}

	// Fixed: one alert back to passing, and the filter empties.
	if _, err := frepo.SetStatus(ctx, low.ID, finding.Triage{Status: domain.FindingRemediated, Actor: "bob"}); err != nil {
		t.Fatalf("triage: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE findings SET status = 'remediated' WHERE fingerprint = 'crit' AND project_id = $1`, projectID); err != nil {
		t.Fatalf("fix: %v", err)
	}
	if _, err := eval.EvaluateVersion(ctx, projectID, ""); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if got := flips(); len(got) != 2 || got[1] != "true" {
		t.Errorf("flips = %v, want back to passing", got)
	}
	if n := failsGate(); n != 0 {
		t.Errorf("fails_gate after the fix = %d, want 0", n)
	}
}

// Of concurrent evaluations that all flip a stored passing result to failing,
// exactly one sees "it was passing": the flip alerts once, not once each.
func TestUpsertStateReportsAFlipOnce(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	grepo := gate.NewRepository(pool)
	var projectID, versionID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-gc','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT project_version($1, 'main', 'branch')`, projectID).Scan(&versionID); err != nil {
		t.Fatalf("version: %v", err)
	}
	if _, err := grepo.UpsertState(ctx, gate.State{ProjectID: projectID, VersionID: versionID, Passed: true}); err != nil {
		t.Fatalf("seed state: %v", err)
	}

	const n = 8
	var wg sync.WaitGroup
	sawPassing := make(chan bool, n)
	for range n {
		wg.Go(func() {
			prev, err := grepo.UpsertState(ctx, gate.State{ProjectID: projectID, VersionID: versionID, Passed: false})
			if err != nil {
				t.Errorf("upsert: %v", err)
				return
			}
			sawPassing <- prev != nil && *prev
		})
	}
	wg.Wait()
	close(sawPassing)
	flips := 0
	for saw := range sawPassing {
		if saw {
			flips++
		}
	}
	if flips != 1 {
		t.Errorf("%d of %d concurrent writers saw the passing result, want exactly 1", flips, n)
	}
}
