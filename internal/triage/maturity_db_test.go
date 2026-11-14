package triage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/triage"
)

type fixture struct {
	pool      *pgxpool.Pool
	frepo     *finding.Repository
	rrepo     *triage.Repository
	svc       *triage.Service
	projectID string
}

func newFixture(t *testing.T, slug string, crit domain.Criticality) fixture {
	t.Helper()
	pool := pgtest.Pool(t)
	var projectID string
	if err := pool.QueryRow(context.Background(), `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ($1,'o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name, business_criticality)
		SELECT id,'p','p',$2 FROM tm RETURNING id`, slug, crit).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	frepo := finding.NewRepository(pool)
	rrepo := triage.NewRepository(pool)
	return fixture{pool: pool, frepo: frepo, rrepo: rrepo, svc: triage.NewService(rrepo, frepo, frepo), projectID: projectID}
}

func (fx fixture) seed(t *testing.T, fp string, sev domain.Severity, epss *float64, kev bool) finding.Finding {
	t.Helper()
	ctx := context.Background()
	f, err := fx.frepo.Upsert(ctx, finding.Finding{
		ProjectID: fx.projectID, Fingerprint: fp, Scanner: "trivy", Category: domain.CategorySCA,
		RuleID: fp, Title: fp, Severity: sev,
	})
	if err != nil {
		t.Fatalf("seed %s: %v", fp, err)
	}
	if _, err := fx.pool.Exec(ctx, `UPDATE findings SET epss = $2, kev = $3 WHERE id = $1`, f.ID, epss, kev); err != nil {
		t.Fatalf("set epss/kev: %v", err)
	}
	return f
}

func (fx fixture) user(t *testing.T, email string) string {
	t.Helper()
	var id string
	if err := fx.pool.QueryRow(context.Background(),
		`INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id`, email).Scan(&id); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func (fx fixture) status(t *testing.T, id string) domain.FindingStatus {
	t.Helper()
	f, err := fx.frepo.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("get %s: %v", id, err)
	}
	return f.Status
}

// TestExploitConditionsHitsAndPreview: EPSS/KEV/criticality filter against
// real rows, preview lists exactly what apply then changes (and mutates
// nothing), and hit counts equal what changed.
func TestExploitConditionsHitsAndPreview(t *testing.T) {
	fx := newFixture(t, "o-mat", domain.CriticalityLow)
	ctx := context.Background()
	hi, lo := 0.9, 0.05
	hot := fx.seed(t, "hot", domain.SeverityHigh, &hi, true)
	quiet := fx.seed(t, "quiet", domain.SeverityHigh, &lo, false)
	unscored := fx.seed(t, "unscored", domain.SeverityHigh, nil, false)
	kevLow := fx.seed(t, "kevlow", domain.SeverityHigh, &lo, true)

	// Risk-accept anything with EPSS >= 0.5 in a low-criticality project.
	rule, err := fx.rrepo.Create(ctx, triage.Rule{
		Name: "epss", Enabled: true, MinEPSS: new(0.5),
		ProjectCriticality: []domain.Criticality{domain.CriticalityLow},
		Action:             triage.ActionRiskAccepted,
	}, "", false)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if rule.ApprovalStatus != triage.ApprovalApproved || rule.HitCount != 0 || rule.LastHitAt != nil {
		t.Fatalf("new rule = %+v, want approved with no hits", rule)
	}
	kevRule, err := fx.rrepo.Create(ctx, triage.Rule{
		Name: "kev", Enabled: true, SortOrder: 1, KEV: true,
		Action: triage.ActionSetSeverity, NewSeverity: domain.SeverityCritical,
	}, "", false)
	if err != nil {
		t.Fatalf("create kev: %v", err)
	}

	// Preview the stored EPSS rule: just "hot" (quiet below, unscored unknown,
	// kevLow below threshold).
	pv, err := fx.svc.Preview(ctx, rule, "")
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if pv.Total != 1 || len(pv.Findings) != 1 || pv.Findings[0].ID != hot.ID ||
		pv.Findings[0].NewStatus != domain.FindingRiskAccepted || pv.Findings[0].ProjectID != fx.projectID {
		t.Fatalf("preview = %+v, want only hot -> risk_accepted", pv)
	}
	// Preview of the kev rule: hot is claimed by the earlier epss rule.
	kpv, err := fx.svc.Preview(ctx, kevRule, fx.projectID)
	if err != nil {
		t.Fatalf("preview kev: %v", err)
	}
	if kpv.Total != 1 || kpv.Findings[0].ID != kevLow.ID || kpv.Findings[0].NewSeverity != domain.SeverityCritical {
		t.Fatalf("kev preview = %+v, want only kevlow -> critical", kpv)
	}
	// Nothing mutated: all still open/high, no hits.
	for _, f := range []finding.Finding{hot, quiet, unscored, kevLow} {
		got, _ := fx.frepo.Get(ctx, f.ID)
		if got.Status != domain.FindingOpen || got.Severity != domain.SeverityHigh {
			t.Errorf("preview mutated %s: %s/%s", f.Title, got.Status, got.Severity)
		}
	}
	if r, _ := fx.rrepo.Get(ctx, rule.ID); r.HitCount != 0 {
		t.Errorf("preview recorded hits: %d", r.HitCount)
	}

	changed, err := fx.svc.ApplyToProject(ctx, fx.projectID)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if changed != pv.Total+kpv.Total {
		t.Errorf("changed = %d, want %d (what preview predicted)", changed, pv.Total+kpv.Total)
	}
	if fx.status(t, hot.ID) != domain.FindingRiskAccepted || fx.status(t, quiet.ID) != domain.FindingOpen ||
		fx.status(t, unscored.ID) != domain.FindingOpen {
		t.Error("EPSS condition applied to the wrong findings")
	}
	if got, _ := fx.frepo.Get(ctx, kevLow.ID); got.Severity != domain.SeverityCritical {
		t.Errorf("kev finding severity = %s, want critical", got.Severity)
	}

	for id, want := range map[string]int64{rule.ID: 1, kevRule.ID: 1} {
		r, _ := fx.rrepo.Get(ctx, id)
		if r.HitCount != want || r.LastHitAt == nil {
			t.Errorf("rule %s hit_count=%d last_hit_at=%v, want %d + set", r.Name, r.HitCount, r.LastHitAt, want)
		}
	}
	// Idempotent re-run: no new hits.
	if _, err := fx.svc.ApplyToProject(ctx, fx.projectID); err != nil {
		t.Fatal(err)
	}
	if r, _ := fx.rrepo.Get(ctx, rule.ID); r.HitCount != 1 {
		t.Errorf("re-apply bumped hit_count to %d", r.HitCount)
	}

	// Criticality mismatch: the same rule on a high-criticality project does
	// nothing.
	if _, err := fx.pool.Exec(ctx, `UPDATE projects SET business_criticality='high' WHERE id=$1`, fx.projectID); err != nil {
		t.Fatal(err)
	}
	fresh := fx.seed(t, "fresh", domain.SeverityHigh, &hi, false)
	if _, err := fx.svc.ApplyToProject(ctx, fx.projectID); err != nil {
		t.Fatal(err)
	}
	if fx.status(t, fresh.ID) != domain.FindingOpen {
		t.Error("criticality condition should exclude a high-criticality project")
	}
}

// TestApprovalWorkflow: with approval on, rules start pending and never apply;
// the author can't approve (four-eyes); edits reset approval; reject keeps the row.
func TestApprovalWorkflow(t *testing.T) {
	fx := newFixture(t, "o-appr", domain.CriticalityMedium)
	ctx := context.Background()
	alice, bob := fx.user(t, "alice@x.co"), fx.user(t, "bob@x.co")
	low := fx.seed(t, "low", domain.SeverityLow, nil, false)

	rule, err := fx.rrepo.Create(ctx, triage.Rule{
		Name: "mute lows", Enabled: true, Severities: []domain.Severity{domain.SeverityLow},
		Action: triage.ActionFalsePositive,
	}, alice, true)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if rule.ApprovalStatus != triage.ApprovalPending || rule.ApprovedBy != nil || rule.ApprovedAt != nil ||
		rule.CreatedBy == nil || *rule.CreatedBy != alice || rule.UpdatedBy == nil || *rule.UpdatedBy != alice {
		t.Fatalf("created = %+v, want pending by alice", rule)
	}

	// Pending never applies — backlog or ingest path.
	if n, err := fx.svc.ApplyToProject(ctx, fx.projectID); err != nil || n != 0 {
		t.Fatalf("pending applied: n=%d err=%v", n, err)
	}
	if fx.status(t, low.ID) != domain.FindingOpen {
		t.Fatal("pending rule changed a finding")
	}

	// Four-eyes.
	if _, err := fx.rrepo.Approve(ctx, rule.ID, alice); !errors.Is(err, triage.ErrSelfApproval) {
		t.Fatalf("self-approve err = %v, want ErrSelfApproval", err)
	}
	approved, err := fx.rrepo.Approve(ctx, rule.ID, bob)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if approved.ApprovalStatus != triage.ApprovalApproved || approved.ApprovedBy == nil || *approved.ApprovedBy != bob || approved.ApprovedAt == nil {
		t.Fatalf("approved = %+v", approved)
	}
	if _, err := fx.rrepo.Approve(ctx, rule.ID, bob); !errors.Is(err, triage.ErrNotPending) {
		t.Errorf("re-approve err = %v, want ErrNotPending", err)
	}
	if n, _ := fx.svc.ApplyToProject(ctx, fx.projectID); n != 1 || fx.status(t, low.ID) != domain.FindingFalsePositive {
		t.Fatalf("approved rule should apply: n=%d", n)
	}

	// Bob edits it: back to pending, and now bob (last editor) can't approve
	// but alice can.
	approved.Reason = "noise"
	edited, err := fx.rrepo.Update(ctx, approved, bob, true)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if edited.ApprovalStatus != triage.ApprovalPending || edited.ApprovedBy != nil || edited.ApprovedAt != nil {
		t.Fatalf("edited = %+v, want pending, approval cleared", edited)
	}
	other := fx.seed(t, "low2", domain.SeverityLow, nil, false)
	if n, _ := fx.svc.ApplyToProject(ctx, fx.projectID); n != 0 || fx.status(t, other.ID) != domain.FindingOpen {
		t.Fatal("an edited (pending) rule must stop applying")
	}
	if _, err := fx.rrepo.Approve(ctx, rule.ID, bob); !errors.Is(err, triage.ErrSelfApproval) {
		t.Errorf("editor approve err = %v, want ErrSelfApproval", err)
	}

	// Reject: row kept, never applies.
	rejected, err := fx.rrepo.Reject(ctx, rule.ID, alice)
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if rejected.ApprovalStatus != triage.ApprovalRejected || rejected.RejectedBy == nil || *rejected.RejectedBy != alice {
		t.Fatalf("rejected = %+v", rejected)
	}
	if _, err := fx.rrepo.Approve(ctx, rule.ID, alice); !errors.Is(err, triage.ErrNotPending) {
		t.Errorf("approve rejected err = %v, want ErrNotPending", err)
	}
	if n, _ := fx.svc.ApplyToProject(ctx, fx.projectID); n != 0 {
		t.Error("rejected rule applied")
	}
	if _, err := fx.rrepo.Reject(ctx, "00000000-0000-0000-0000-000000000000", alice); !errors.Is(err, triage.ErrNotFound) {
		t.Errorf("reject missing err = %v, want ErrNotFound", err)
	}

	// Approval off: an edit lands approved again.
	back, err := fx.rrepo.Update(ctx, rejected, alice, false)
	if err != nil {
		t.Fatal(err)
	}
	if back.ApprovalStatus != triage.ApprovalApproved || back.RejectedBy != nil || back.ApprovedAt == nil {
		t.Errorf("approval-off edit = %+v, want approved", back)
	}
}
