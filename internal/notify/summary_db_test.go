package notify_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// A channel's minimum severity keeps it out of lower-severity events; events
// without a severity still reach it.
func TestChannelMinSeverity(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := notify.NewRepository(pool)
	if _, err := repo.Create(ctx, notify.Channel{Name: "pager", Type: "webhook", URL: "https://p", Enabled: true, MinSeverity: "high"}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Create(ctx, notify.Channel{Name: "all", Type: "webhook", URL: "https://a", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for sev, want := range map[string]int{"critical": 2, "HIGH": 2, "medium": 1, "low": 1, "": 2} {
		chs, err := repo.ListForEvent(ctx, notify.EventCriticalFinding, "", sev)
		if err != nil || len(chs) != want {
			t.Errorf("severity %q: %d channels (%v), want %d", sev, len(chs), err, want)
		}
	}
}

// A scheduled summary goes out once per slot — even with two dispatchers
// racing (a leader handover) — with the scope's real figures; and editing the
// schedule restarts it rather than firing for a slot already past.
func TestScheduledSummaries(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := notify.NewRepository(pool)
	findings := finding.NewRepository(pool)

	var projectID, other string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-sum','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'web','web' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO projects (team_id, slug, name) SELECT team_id,'api','api' FROM projects WHERE id = $1 RETURNING id`,
		projectID).Scan(&other); err != nil {
		t.Fatal(err)
	}
	seed := func(project, fp, sev, status string, firstSeen time.Duration, kev bool) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO findings (project_id, fingerprint, scanner, category, title, severity, status, first_seen_at, last_seen_at, kev, priority,
				resolved_at)
			VALUES ($1,$2,'trivy','sca',$2,$3,$4, now() - $5::interval, now(), $6, CASE $3 WHEN 'critical' THEN 15 ELSE 3 END,
				CASE WHEN $4 = 'remediated' THEN now() - interval '1 hour' END)`,
			project, fp, sev, status, firstSeen.String(), kev); err != nil {
			t.Fatal(err)
		}
	}
	seed(projectID, "Log4Shell", "critical", "open", time.Hour, true)       // new, open, KEV
	seed(projectID, "old-medium", "medium", "open", 40*24*time.Hour, false) // old, open
	seed(projectID, "fixed-high", "high", "remediated", 10*24*time.Hour, false)
	seed(other, "elsewhere", "critical", "open", time.Hour, false) // another project: out of scope

	ch, err := repo.Create(ctx, notify.Channel{Name: "team", Type: "webhook", URL: "https://t", Enabled: true,
		ProjectID: &projectID, Summary: notify.SummaryDaily, SummaryHour: 8})
	if err != nil {
		t.Fatal(err)
	}
	// Created now: the first summary waits for the next slot.
	now := time.Now().UTC()
	slot, _, _ := notify.SummarySlot(ch, now)
	svc := notify.NewService(repo, notify.SMTPConfig{})
	if n, _ := svc.SendDueSummaries(ctx, findings, now); n != 0 {
		t.Fatalf("a new schedule sent %d summaries for a slot already past", n)
	}

	// Pretend the last one went out the day before: today's slot is due.
	if _, err := pool.Exec(ctx, `UPDATE notification_channels SET last_summary_at = $2 WHERE id = $1`, ch.ID, slot.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	other1 := notify.NewService(repo, notify.SMTPConfig{}) // a second leader during handover
	done := make(chan int, 2)
	for _, s := range []*notify.Service{svc, other1} {
		go func() { n, _ := s.SendDueSummaries(ctx, findings, now); done <- n }()
	}
	if total := <-done + <-done; total != 1 {
		t.Fatalf("two dispatchers queued %d summaries for one slot, want exactly 1", total)
	}

	var raw []byte
	if err := pool.QueryRow(ctx, `SELECT event FROM notification_outbox WHERE channel_id = $1`, ch.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var e notify.Event
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"new": "1", "new_critical": "1", "fixed": "1", "open": "2", "open_critical": "1", "kev": "1"}
	for k, v := range want {
		if e.Fields[k] != v {
			t.Errorf("summary field %s = %q, want %s (fields %v)", k, e.Fields[k], v, e.Fields)
		}
	}
	if e.Type != notify.EventSummary || e.ProjectID != projectID || !strings.Contains(e.Text, "Log4Shell") || strings.Contains(e.Text, "elsewhere") {
		t.Errorf("summary event = %+v", e)
	}
	if n, _ := svc.SendDueSummaries(ctx, findings, now); n != 0 {
		t.Errorf("the same slot was sent again (%d)", n)
	}

	// Switching to weekly restarts the schedule from now: nothing fires today.
	ch.Summary, ch.SummaryWeekday = notify.SummaryWeekly, int(now.Weekday())
	if _, err := repo.Update(ctx, ch); err != nil {
		t.Fatal(err)
	}
	if n, _ := svc.SendDueSummaries(ctx, findings, now.Add(time.Minute)); n != 0 {
		t.Errorf("an edited schedule fired immediately (%d)", n)
	}
}
