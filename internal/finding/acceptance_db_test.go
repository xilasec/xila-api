package finding_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
)

type slaState struct {
	due      *time.Time
	pausedAt *time.Time
	total    time.Duration
}

// The whole lifecycle on real rows: a request changes nothing, approval
// accepts and pauses the SLA, expiry reopens and resumes the clock (deadline
// pushed by exactly the paused time), and the ledger keeps every stay.
func TestRiskAcceptanceLifecycle(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	a1, b1 := sampleFinding(projectID), sampleFinding(projectID)
	b1.Fingerprint = "fp-2"
	fa, _ := repo.Upsert(ctx, a1)
	fb, _ := repo.Upsert(ctx, b1)
	sla := func(id string) slaState {
		var s slaState
		var secs float64
		if err := pool.QueryRow(ctx, `SELECT sla_due_at, sla_paused_at, extract(epoch FROM sla_paused_total)
			FROM findings WHERE id = $1`, id).Scan(&s.due, &s.pausedAt, &secs); err != nil {
			t.Fatal(err)
		}
		s.total = time.Duration(secs * float64(time.Second))
		return s
	}
	before := sla(fa.ID)
	if before.due == nil {
		t.Fatal("seed finding has no SLA")
	}

	exp := time.Now().Add(30 * 24 * time.Hour)
	ra, skipped, err := repo.CreateAcceptance(ctx, finding.AcceptanceInput{ProjectID: projectID, Title: "WAF",
		Justification: "virtual patch", ExpiresAt: &exp, FindingIDs: []string{fa.ID, fb.ID}}, "alice")
	if err != nil || len(skipped) != 0 || ra.State != finding.AcceptanceRequested || ra.FindingCount != 2 {
		t.Fatalf("request = %+v skipped %v err %v", ra, skipped, err)
	}
	// Requested: still open, clock running, counted as live.
	if got, _ := repo.Get(ctx, fa.ID); got.Status != domain.FindingOpen || got.RiskAcceptance == nil || got.RiskAcceptance.State != finding.AcceptanceRequested {
		t.Fatalf("requested finding = %q %+v", got.Status, got.RiskAcceptance)
	}
	if s := sla(fa.ID); s.pausedAt != nil || !s.due.Equal(*before.due) {
		t.Fatalf("a request moved the SLA: %+v vs %+v", s, before)
	}
	if open, _ := repo.List(ctx, finding.Filter{ProjectID: projectID, OpenOnly: true}); len(open) != 2 {
		t.Fatalf("open findings under a request = %d, want 2", len(open))
	}
	// A second request can't take the same finding.
	if _, sk, _ := repo.CreateAcceptance(ctx, finding.AcceptanceInput{ProjectID: projectID, Title: "x", Justification: "x",
		FindingIDs: []string{fa.ID}}, "bob"); len(sk) != 1 {
		t.Errorf("finding joined two live acceptances (skipped %v)", sk)
	}

	// Four-eyes: the requester can't approve; someone else can.
	if _, _, err := repo.ApproveAcceptance(ctx, projectID, ra.ID, "alice", "", true); !errors.Is(err, finding.ErrAcceptanceSelfDecision) {
		t.Fatalf("self approval = %v, want ErrAcceptanceSelfDecision", err)
	}
	ra, moved, err := repo.ApproveAcceptance(ctx, projectID, ra.ID, "carol", "fine", true)
	if err != nil || len(moved) != 2 || ra.State != finding.AcceptanceApproved || ra.Approver != "carol" {
		t.Fatalf("approve = %+v moved %v err %v", ra, moved, err)
	}
	got, _ := repo.Get(ctx, fa.ID)
	if r, by, e := got.Exception(); got.Status != domain.FindingRiskAccepted || got.SLAStatus != domain.SLAPaused ||
		r != "virtual patch" || by != "carol" || e == nil {
		t.Fatalf("approved finding = %q %q (%q %q %v)", got.Status, got.SLAStatus, r, by, e)
	}
	if s := sla(fa.ID); s.pausedAt == nil {
		t.Fatal("approval didn't pause the SLA clock")
	}
	// Direct risk_accepted stays impossible.
	if _, err := repo.SetStatus(ctx, fb.ID, finding.Triage{Status: domain.FindingRiskAccepted}); !errors.Is(err, finding.ErrRiskAcceptanceRequired) {
		t.Errorf("SetStatus(risk_accepted) = %v", err)
	}

	// Removing b: it reopens, the ledger keeps the stay with its reason.
	if _, err := repo.RemoveAcceptanceFinding(ctx, projectID, ra.ID, fb.ID, "dave", "upgraded"); err != nil {
		t.Fatal(err)
	}
	if got, _ := repo.Get(ctx, fb.ID); got.Status != domain.FindingOpen || got.RiskAcceptance != nil {
		t.Errorf("removed finding = %q %+v", got.Status, got.RiskAcceptance)
	}
	ledger, _ := repo.FindingLedger(ctx, fb.ID)
	if len(ledger) != 1 || ledger[0].RemovedAt == nil || ledger[0].Reason != "upgraded" || ledger[0].RemovedBy != "dave" {
		t.Fatalf("ledger after removal = %+v", ledger)
	}

	// Expiry: pretend it was approved 72h ago and lapsed now.
	if _, err := pool.Exec(ctx, `UPDATE risk_acceptances SET expires_at = now() - interval '1 minute' WHERE id = $1;`, ra.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE findings SET sla_paused_at = sla_paused_at - interval '72 hours' WHERE id = $1`, fa.ID); err != nil {
		t.Fatal(err)
	}
	expired, err := repo.ExpireAcceptances(ctx)
	if err != nil || len(expired) != 1 || expired[0].State != finding.AcceptanceExpired || expired[0].FindingCount != 1 {
		t.Fatalf("expire = %+v err %v", expired, err)
	}
	got, _ = repo.Get(ctx, fa.ID)
	s := sla(fa.ID)
	if got.Status != domain.FindingOpen || s.pausedAt != nil || s.total < 72*time.Hour ||
		s.due.Sub(*before.due) < 72*time.Hour || s.due.Sub(*before.due) > 73*time.Hour {
		t.Fatalf("after expiry: status %q sla %+v (before %v)", got.Status, s, before.due)
	}
	ledger, _ = repo.FindingLedger(ctx, fa.ID)
	if len(ledger) != 1 || ledger[0].Reason != "acceptance expired" || ledger[0].AcceptanceState != finding.AcceptanceExpired {
		t.Fatalf("ledger after expiry = %+v", ledger)
	}
	if again, _ := repo.ExpireAcceptances(ctx); len(again) != 0 {
		t.Errorf("second sweep expired %d more", len(again))
	}
}

// A triage rule's matches join one acceptance per project, approved at once.
func TestAcceptBySystemJoinsOneAcceptance(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	a, b := sampleFinding(projectID), sampleFinding(projectID)
	b.Fingerprint = "fp-2"
	fa, _ := repo.Upsert(ctx, a)
	fb, _ := repo.Upsert(ctx, b)
	sys := finding.SystemAcceptance{ProjectID: projectID, SourceKey: "triage-rule:r1", Title: "Triage rule: r1",
		Justification: "noise", Actor: "triage-rule:r1", Approve: true}
	for _, id := range []string{fa.ID, fb.ID} {
		if moved, err := repo.AcceptBySystem(ctx, sys, []string{id}); err != nil || len(moved) != 1 {
			t.Fatalf("accept by system = %v %v", moved, err)
		}
	}
	list, _ := repo.ListAcceptances(ctx, finding.AcceptanceFilter{ProjectID: projectID})
	if len(list) != 1 || list[0].FindingCount != 2 || list[0].State != finding.AcceptanceApproved {
		t.Fatalf("system acceptances = %+v, want one approved with 2 findings", list)
	}
	// Warned once per expiry.
	if _, err := pool.Exec(ctx, `UPDATE risk_acceptances SET expires_at = now() + interval '2 days'`); err != nil {
		t.Fatal(err)
	}
	if w, _ := repo.WarnExpiringAcceptances(ctx, 7*24*time.Hour); len(w) != 1 {
		t.Errorf("first warning = %d, want 1", len(w))
	}
	if w, _ := repo.WarnExpiringAcceptances(ctx, 7*24*time.Hour); len(w) != 0 {
		t.Errorf("second warning = %d, want 0", len(w))
	}
}
