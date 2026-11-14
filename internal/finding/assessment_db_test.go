package finding_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
)

func seedUser(t *testing.T, pool *pgxpool.Pool, email string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id`, email).Scan(&id); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

// A manual assessment under four-eyes: requesting changes nothing, approval
// applies it attributed to the requester (with the approval recorded too),
// rejection leaves the finding alone, and a finding has one pending request
// at a time.
func TestAssessmentApproval(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	alice := seedUser(t, pool, "alice@x.io")
	bob := seedUser(t, pool, "bob@x.io")

	f, err := repo.Upsert(ctx, sampleFinding(projectID))
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	a, err := repo.RequestAssessment(ctx, f.ID, finding.Change{
		Status: new(domain.FindingFalsePositive), Severity: new(domain.SeverityLow), Reason: "test fixture",
	}, alice)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if a.State != finding.AssessmentPending || a.Requester != "alice@x.io" || a.CurrentStatus != domain.FindingOpen {
		t.Fatalf("assessment = %+v", a)
	}
	if got, _ := repo.Get(ctx, f.ID); got.Status != domain.FindingOpen || got.Severity != domain.SeverityHigh {
		t.Fatalf("a pending request changed the finding: %s / %s", got.Status, got.Severity)
	}

	// One pending request per finding.
	if _, err := repo.RequestAssessment(ctx, f.ID, finding.Change{Status: new(domain.FindingConfirmed)}, bob); !errors.Is(err, finding.ErrAssessmentPending) {
		t.Fatalf("second request = %v, want ErrAssessmentPending", err)
	}
	created, busy, err := repo.RequestAssessments(ctx, []string{f.ID}, finding.Change{Severity: new(domain.SeverityInfo)}, bob)
	if err != nil || len(created) != 0 || len(busy) != 1 || busy[0] != f.ID {
		t.Fatalf("bulk request on a busy finding = %v / %v / %v", created, busy, err)
	}

	// Four-eyes: the requester can't approve their own.
	if _, _, err := repo.ApproveAssessment(ctx, a.ID, alice, ""); !errors.Is(err, finding.ErrSelfApproval) {
		t.Fatalf("self-approval = %v, want ErrSelfApproval", err)
	}

	approved, got, err := repo.ApproveAssessment(ctx, a.ID, bob, "agreed")
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if approved.State != finding.AssessmentApproved || approved.Decider != "bob@x.io" || approved.DecisionNote != "agreed" || approved.DecidedAt == nil {
		t.Errorf("approved = %+v", approved)
	}
	if got.Status != domain.FindingFalsePositive || got.Severity != domain.SeverityLow || got.ResolvedAt == nil ||
		got.ExceptionReason != "test fixture" || got.ExceptionBy != alice {
		t.Errorf("finding after approval = %s / %s resolved=%v reason=%q by=%q", got.Status, got.Severity, got.ResolvedAt, got.ExceptionReason, got.ExceptionBy)
	}
	if exc, err := repo.ListExceptions(ctx, f.ID); err != nil || len(exc) != 1 {
		t.Errorf("exception audit rows = %d (%v), want 1", len(exc), err)
	}
	if _, _, err := repo.ApproveAssessment(ctx, a.ID, bob, ""); !errors.Is(err, finding.ErrAssessmentDecided) {
		t.Errorf("approving twice = %v, want ErrAssessmentDecided", err)
	}

	// Rejection leaves the finding exactly as it is.
	r, err := repo.RequestAssessment(ctx, f.ID, finding.Change{Status: new(domain.FindingOpen), Reason: "actually real"}, alice)
	if err != nil {
		t.Fatalf("second request after approval: %v", err)
	}
	rejected, err := repo.RejectAssessment(ctx, r.ID, bob, "no")
	if err != nil || rejected.State != finding.AssessmentRejected {
		t.Fatalf("reject = %+v %v", rejected, err)
	}
	if after, _ := repo.Get(ctx, f.ID); after.Status != domain.FindingFalsePositive {
		t.Errorf("rejected request changed the finding to %s", after.Status)
	}

	events, err := repo.History(ctx, f.ID)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	type row struct{ kind, from, to, actor, note string }
	str := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	var hist []row
	for _, e := range events {
		hist = append(hist, row{e.Kind, str(e.From), str(e.To), e.ActorName, e.Note})
	}
	want := []row{
		{"created", "", "open", "system", ""},
		{"assessment", "status → false_positive, severity → low", "pending", "alice@x.io", "test fixture"},
		{"status", "open", "false_positive", "alice@x.io", "test fixture"},
		{"severity", "high", "low", "alice@x.io", "test fixture"},
		{"assessment", "status → false_positive, severity → low", "approved", "bob@x.io", "agreed"},
		{"assessment", "status → open", "pending", "alice@x.io", "actually real"},
		{"assessment", "status → open", "rejected", "bob@x.io", "no"},
	}
	if len(hist) != len(want) {
		t.Fatalf("history = %+v, want %d events", hist, len(want))
	}
	for i := range want {
		if hist[i] != want[i] {
			t.Errorf("event %d = %+v, want %+v", i, hist[i], want[i])
		}
	}

	pending, err := repo.ListAssessments(ctx, finding.AssessmentFilter{State: finding.AssessmentPending})
	if err != nil || len(pending) != 0 {
		t.Errorf("pending after decisions = %d (%v), want 0", len(pending), err)
	}
	all, err := repo.ListAssessments(ctx, finding.AssessmentFilter{FindingID: f.ID})
	if err != nil || len(all) != 2 {
		t.Errorf("assessments of the finding = %d (%v), want 2", len(all), err)
	}
	if none, _ := repo.ListAssessments(ctx, finding.AssessmentFilter{ProjectIDs: []string{}}); len(none) != 0 {
		t.Errorf("an empty visible scope listed %d assessments", len(none))
	}
}

// A stale request still lands on its target state: the reviewer approves the
// outcome shown, even if the finding moved meanwhile.
func TestStaleAssessmentAppliesTarget(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	alice := seedUser(t, pool, "alice@x.io")
	bob := seedUser(t, pool, "bob@x.io")
	f, err := repo.Upsert(ctx, sampleFinding(projectID))
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	a, err := repo.RequestAssessment(ctx, f.ID, finding.Change{Status: new(domain.FindingConfirmed)}, alice)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE findings SET status = 'remediated' WHERE id = $1`, f.ID); err != nil {
		t.Fatal(err)
	}
	if _, got, err := repo.ApproveAssessment(ctx, a.ID, bob, ""); err != nil || got.Status != domain.FindingConfirmed || got.ResolvedAt != nil {
		t.Fatalf("stale approve = %s resolved=%v (%v), want confirmed", got.Status, got.ResolvedAt, err)
	}
}
