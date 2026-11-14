package notify_test

import (
	"context"
	"testing"

	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// A channel filter narrows what the channel receives, reading the project and
// finding the event names; an expression that can't be evaluated (a null
// fact) doesn't deliver and doesn't affect any other channel.
func TestChannelFilters(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := notify.NewRepository(pool)
	svc := notify.NewService(repo, notify.SMTPConfig{})

	var projectID, findingID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug, name) VALUES ('o', 'o') RETURNING id),
		t AS (INSERT INTO teams (org_id, slug, name) SELECT id, 't', 't' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name, tags) SELECT id, 'shop', 'Shop', '{pci,internet-facing}' FROM t
		RETURNING id`).Scan(&projectID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO findings (project_id, fingerprint, scanner, category, rule_id, title,
			severity, cve, kev, kev_sources)
		VALUES ($1, 'fp', 'trivy', 'sca', 'CVE-2021-44228', 'log4shell', 'critical', '{CVE-2021-44228}', true, '{cisa,enisa}')
		RETURNING id`, projectID).Scan(&findingID); err != nil {
		t.Fatal(err)
	}

	mk := func(name, filter string) string {
		t.Helper()
		ch, err := repo.Create(ctx, notify.Channel{Name: name, Type: "webhook", URL: "https://hooks.example.test/" + name,
			Events: []string{"*"}, Enabled: true, Filter: filter})
		if err != nil {
			t.Fatal(err)
		}
		return ch.ID
	}
	plain := mk("plain", "")
	enisa := mk("enisa", `"enisa" in event.finding.kev_sources`)
	pci := mk("pci", `"pci" in event.project.tags && event.severity == "critical"`)
	noCVSS := mk("cvss", `event.finding.cvss >= 9.0`) // the finding has no CVSS: null never matches
	other := mk("other", `event.project.slug == "intranet"`)

	svc.Notify(ctx, notify.Event{Type: notify.EventCriticalFinding, Severity: "critical", ProjectID: projectID,
		FindingID: findingID, Title: "Log4Shell"})
	// An event naming no finding: finding facts are null.
	svc.Notify(ctx, notify.Event{Type: notify.EventPolicyViolation, Severity: "critical", ProjectID: projectID})

	got := map[string]int{}
	rows, err := pool.Query(ctx, `SELECT channel_id::text, count(*) FROM notification_outbox GROUP BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			t.Fatal(err)
		}
		got[id] = n
	}
	want := map[string]int{plain: 2, enisa: 1, pci: 2}
	for id, n := range want {
		if got[id] != n {
			t.Errorf("channel %s got %d events, want %d", id, got[id], n)
		}
	}
	for _, id := range []string{noCVSS, other} {
		if got[id] != 0 {
			t.Errorf("channel %s got %d events, want none", id, got[id])
		}
	}

	// A stored filter that no longer compiles skips its channel only.
	if _, err := pool.Exec(ctx, `UPDATE notification_channels SET filter = 'event.nonexistent ==' WHERE id = $1`, other); err != nil {
		t.Fatal(err)
	}
	svc.Notify(ctx, notify.Event{Type: notify.EventPolicyViolation, ProjectID: projectID})
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM notification_outbox WHERE channel_id = $1`, plain).Scan(&n); err != nil || n != 3 {
		t.Fatalf("plain channel after a broken filter elsewhere: %d, %v", n, err)
	}
}

// Filters are validated when saved: syntax errors and unknown fields are
// rejected with the compiler's explanation.
func TestCompileFilter(t *testing.T) {
	for _, ok := range []string{"", `event.finding.kev`, `event.type.startsWith("cra.")`, `event.fields.count == "1"`} {
		if err := notify.CompileFilter(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{`event.finding.kev ==`, `event.finding.nope`, `event.title`, `1 + 1`} {
		if err := notify.CompileFilter(bad); err == nil {
			t.Errorf("%q compiled", bad)
		}
	}
}
