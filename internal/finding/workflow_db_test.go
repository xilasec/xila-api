package finding_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// The history must capture every change, whoever makes it: a person through
// the API (attributed, with their reason), and the automatic paths that know
// nothing about history (auto-close, reopen-on-reappearance) as "system".
func TestHistoryRecordsEveryWriter(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	var alice string
	if err := pool.QueryRow(ctx, `INSERT INTO users (email, password_hash) VALUES ('alice@x.io', 'x') RETURNING id`).Scan(&alice); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	f, err := repo.Upsert(ctx, sampleFinding(projectID))
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if _, err := repo.SetStatus(ctx, f.ID, finding.Triage{Status: domain.FindingWontFix, Reason: "behind WAF", Actor: alice}); err != nil {
		t.Fatalf("accept: %v", err)
	}
	if _, err := repo.Apply(ctx, []string{f.ID}, finding.Change{
		Severity: new(domain.SeverityLow), SetAssignee: true, AssigneeID: &alice, Reason: "triaged in standup",
	}, alice); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Automatic writers: reopened by an analyst, then auto-closed by a scan.
	if _, err := pool.Exec(ctx, `UPDATE findings SET status = 'remediated' WHERE id = $1`, f.ID); err != nil {
		t.Fatalf("system close: %v", err)
	}
	if _, err := repo.AddComment(ctx, f.ID, alice, "fixed in #42"); err != nil {
		t.Fatalf("comment: %v", err)
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
	var got []row
	for _, e := range events {
		got = append(got, row{e.Kind, str(e.From), str(e.To), e.ActorName, e.Note})
	}
	want := []row{
		{"created", "", "open", "system", ""},
		{"status", "open", "wont_fix", "alice@x.io", "behind WAF"},
		{"severity", "high", "low", "alice@x.io", "triaged in standup"},
		{"assignee", "", "alice@x.io", "alice@x.io", "triaged in standup"},
		{"status", "wont_fix", "remediated", "system", ""},
		{"comment", "", "", "alice@x.io", ""},
	}
	if len(got) != len(want) {
		t.Fatalf("history = %+v, want %d events", got, len(want))
	}
	for i := range want {
		w := want[i]
		if i == 5 { // a comment event's to_value is the comment id
			got[i].to = ""
		}
		if got[i] != w {
			t.Errorf("event %d = %+v, want %+v", i, got[i], w)
		}
	}
}

// A bulk status change behaves exactly like one-by-one triage: resolved_at,
// the active exception, and one audit row per finding.
func TestApplyMatchesSingleTriage(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	var ids []string
	for _, fp := range []string{"a", "b", "c"} {
		f := sampleFinding(projectID)
		f.Fingerprint = fp
		created, err := repo.Upsert(ctx, f)
		if err != nil {
			t.Fatalf("upsert: %v", err)
		}
		ids = append(ids, created.ID)
	}
	out, err := repo.Apply(ctx, ids[:2], finding.Change{Status: new(domain.FindingFalsePositive), Reason: "test fixture"}, "")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("updated %d, want 2", len(out))
	}
	for _, f := range out {
		if f.Status != domain.FindingFalsePositive || f.ResolvedAt == nil || f.ExceptionReason != "test fixture" {
			t.Errorf("bulk-triaged finding = %+v", f)
		}
		if ex, _ := repo.ListExceptions(ctx, f.ID); len(ex) != 1 || ex[0].Reason != "test fixture" {
			t.Errorf("exception audit = %+v, want one row", ex)
		}
	}
	if untouched, _ := repo.Get(ctx, ids[2]); untouched.Status != domain.FindingOpen {
		t.Errorf("finding outside the selection = %q, want open", untouched.Status)
	}
	// Unassigning, and a no-op change of status, write nothing new.
	before, _ := repo.History(ctx, ids[0])
	if _, err := repo.Apply(ctx, ids[:1], finding.Change{Status: new(domain.FindingFalsePositive)}, ""); err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if after, _ := repo.History(ctx, ids[0]); len(after) != len(before) {
		t.Errorf("re-applying the same status added %d history events", len(after)-len(before))
	}
}

func TestCommentsAndAttachments(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	f, _ := repo.Upsert(ctx, sampleFinding(projectID))

	if _, err := repo.AddComment(ctx, "00000000-0000-0000-0000-000000000000", "", "x"); !errors.Is(err, finding.ErrNotFound) {
		t.Errorf("comment on a missing finding = %v, want ErrNotFound", err)
	}
	c, err := repo.AddComment(ctx, f.ID, "", "first")
	if err != nil {
		t.Fatalf("comment: %v", err)
	}
	if list, _ := repo.Comments(ctx, f.ID); len(list) != 1 || list[0].Body != "first" {
		t.Errorf("comments = %+v", list)
	}
	if err := repo.DeleteComment(ctx, f.ID, c.ID); err != nil {
		t.Fatalf("delete comment: %v", err)
	}

	a, err := repo.AddAttachment(ctx, f.ID, "", "proof.txt", "text/plain; charset=utf-8", []byte("poc output"))
	if err != nil {
		t.Fatalf("attach: %v", err)
	}
	sum := sha256.Sum256([]byte("poc output"))
	if a.Size != 10 || a.SHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("attachment metadata = %+v", a)
	}
	got, err := repo.Attachment(ctx, f.ID, a.ID)
	if err != nil || string(got.Data) != "poc output" {
		t.Fatalf("download = %q (%v)", got.Data, err)
	}
	if list, _ := repo.Attachments(ctx, f.ID); len(list) != 1 || list[0].Data != nil {
		t.Errorf("listing must not carry file bytes: %+v", list)
	}
}
