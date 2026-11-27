package inbox

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// q runs sql returning one value (an id), failing the test on error.
func q(t *testing.T, pool *pgxpool.Pool, sql string, args ...any) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), sql, args...).Scan(&id); err != nil {
		t.Fatalf("query %q: %v", sql, err)
	}
	return id
}

// TestFillRecipients covers every routing rule Fill implements: the
// assignee for finding.assigned, explicit UserIDs for mention, a project's
// watchers for its other events, and instance admins for events naming no
// project — each still gated by project visibility and muted_events.
func TestFillRecipients(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := NewRepository(pool)

	user := func(email string) string {
		return q(t, pool, `INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id`, email)
	}
	admin := func(email string) string {
		return q(t, pool, `INSERT INTO users (email, password_hash, is_admin) VALUES ($1, 'x', true) RETURNING id`, email)
	}
	project := q(t, pool, `WITH o AS (INSERT INTO organizations (slug, name) VALUES ('o', 'o') RETURNING id),
		tm AS (INSERT INTO teams (org_id, slug, name) SELECT id, 't', 't' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id, 'web', 'Web' FROM tm RETURNING id`)

	assignee := user("assignee@xila.io")
	watcher := user("watcher@xila.io")
	mentioned := user("mentioned@xila.io")
	bystander := user("bystander@xila.io") // can see the project, but not assigned/watching/mentioned
	outsider := user("outsider@xila.io")   // cannot see the project at all
	adm := admin("admin@xila.io")

	for _, u := range []string{assignee, watcher, mentioned, bystander} {
		if _, err := pool.Exec(ctx, `INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, 'viewer')`, project, u); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO project_watches (project_id, user_id) VALUES ($1, $2)`, project, watcher); err != nil {
		t.Fatal(err)
	}
	finding := q(t, pool, `INSERT INTO findings (project_id, fingerprint, scanner, category, title, severity, assignee_id)
		VALUES ($1, 'fp', 'trivy', 'sca', 'log4shell', 'critical', $2) RETURNING id`, project, assignee)

	// finding.assigned: only the assignee.
	if err := repo.Fill(ctx, notify.Event{Type: notify.EventFindingAssigned, ProjectID: project, FindingID: finding, Title: "Assigned"}); err != nil {
		t.Fatal(err)
	}
	assertType(t, ctx, pool, assignee, notify.EventFindingAssigned, 1)
	for _, u := range []string{watcher, mentioned, bystander, outsider, adm} {
		assertType(t, ctx, pool, u, notify.EventFindingAssigned, 0)
	}

	// mention: exactly the UserIDs given, even though mentioned isn't a watcher.
	if err := repo.Fill(ctx, notify.Event{Type: notify.EventMention, ProjectID: project, FindingID: finding, UserIDs: []string{mentioned}, Title: "Mentioned"}); err != nil {
		t.Fatal(err)
	}
	assertType(t, ctx, pool, mentioned, notify.EventMention, 1)
	assertType(t, ctx, pool, bystander, notify.EventMention, 0)
	assertType(t, ctx, pool, outsider, notify.EventMention, 0)

	// a mentioned user who can no longer see the project is skipped, even
	// though they're named explicitly.
	if err := repo.Fill(ctx, notify.Event{Type: notify.EventMention, ProjectID: project, UserIDs: []string{outsider}, Title: "Mentioned outsider"}); err != nil {
		t.Fatal(err)
	}
	assertType(t, ctx, pool, outsider, notify.EventMention, 0)

	// a generic project event: the project's watchers, not the assignee or
	// the bystander.
	if err := repo.Fill(ctx, notify.Event{Type: notify.EventCriticalFinding, ProjectID: project, FindingID: finding, Title: "Critical"}); err != nil {
		t.Fatal(err)
	}
	assertType(t, ctx, pool, watcher, notify.EventCriticalFinding, 1)
	assertType(t, ctx, pool, bystander, notify.EventCriticalFinding, 0)

	// an event naming no project: instance admins only.
	if err := repo.Fill(ctx, notify.Event{Type: notify.EventIngestionAnomaly, Title: "Global anomaly"}); err != nil {
		t.Fatal(err)
	}
	assertType(t, ctx, pool, adm, notify.EventIngestionAnomaly, 1)
	assertType(t, ctx, pool, watcher, notify.EventIngestionAnomaly, 0) // not admin, no project on the event

	// muting the event type stops delivery of that type only.
	if _, err := pool.Exec(ctx, `INSERT INTO user_notification_prefs (user_id, muted_events) VALUES ($1, ARRAY['finding.sla_breach'])
		ON CONFLICT (user_id) DO UPDATE SET muted_events = EXCLUDED.muted_events`, watcher); err != nil {
		t.Fatal(err)
	}
	if err := repo.Fill(ctx, notify.Event{Type: "finding.sla_breach", ProjectID: project, FindingID: finding, Title: "SLA breach"}); err != nil {
		t.Fatal(err)
	}
	assertType(t, ctx, pool, watcher, "finding.sla_breach", 0)
	if err := repo.Fill(ctx, notify.Event{Type: notify.EventExploitable, ProjectID: project, FindingID: finding, Title: "Exploitable"}); err != nil {
		t.Fatal(err)
	}
	assertType(t, ctx, pool, watcher, notify.EventExploitable, 1) // unmuted type still delivered
}

// assertType checks how many rows of eventType exist for userID (bypassing
// the RBAC recheck List/UnreadCount apply, since this test is about Fill's
// write-time routing).
func assertType(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID, eventType string, want int) {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM inbox_items WHERE user_id = $1 AND event_type = $2`, userID, eventType).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != want {
		t.Errorf("inbox rows of %s for %s = %d, want %d", eventType, userID, n, want)
	}
}

// TestListCountMarkRead covers the read-side API: filters, the RBAC recheck
// (a user who lost access stops seeing an item, without the row being
// deleted), and marking read by id or all.
func TestListCountMarkRead(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := NewRepository(pool)

	user := func(email string) string {
		return q(t, pool, `INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id`, email)
	}
	project := q(t, pool, `WITH o AS (INSERT INTO organizations (slug, name) VALUES ('o', 'o') RETURNING id),
		tm AS (INSERT INTO teams (org_id, slug, name) SELECT id, 't', 't' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id, 'web', 'Web' FROM tm RETURNING id`)
	alice := user("alice@xila.io")
	if _, err := pool.Exec(ctx, `INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, 'viewer')`, project, alice); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO project_watches (project_id, user_id) VALUES ($1, $2)`, project, alice); err != nil {
		t.Fatal(err)
	}
	finding := q(t, pool, `INSERT INTO findings (project_id, fingerprint, scanner, category, title, severity, assignee_id)
		VALUES ($1, 'fp', 'trivy', 'sca', 'log4shell', 'critical', $2) RETURNING id`, project, alice)

	if err := repo.Fill(ctx, notify.Event{Type: notify.EventFindingAssigned, ProjectID: project, FindingID: finding, Title: "Assigned to you"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Fill(ctx, notify.Event{Type: notify.EventMention, ProjectID: project, FindingID: finding, UserIDs: []string{alice}, Title: "Mentioned"}); err != nil {
		t.Fatal(err)
	}
	if err := repo.Fill(ctx, notify.Event{Type: notify.EventCriticalFinding, ProjectID: project, FindingID: finding, Title: "Critical"}); err != nil {
		t.Fatal(err)
	}

	items, err := repo.List(ctx, alice, Filter{Limit: 50})
	if err != nil || len(items) != 3 {
		t.Fatalf("List = %d items, %v; want 3", len(items), err)
	}
	if items[0].Link != "/findings/"+finding {
		t.Errorf("link = %q, want a finding link", items[0].Link)
	}

	mentions, err := repo.List(ctx, alice, Filter{Mode: "mentions", Limit: 50})
	if err != nil || len(mentions) != 1 || mentions[0].EventType != "mention" {
		t.Fatalf("mentions filter = %+v, %v", mentions, err)
	}
	assigned, err := repo.List(ctx, alice, Filter{Mode: "assigned", Limit: 50})
	if err != nil || len(assigned) != 1 || assigned[0].EventType != notify.EventFindingAssigned {
		t.Fatalf("assigned filter = %+v, %v", assigned, err)
	}

	n, err := repo.UnreadCount(ctx, alice)
	if err != nil || n != 3 {
		t.Fatalf("UnreadCount = %d, %v; want 3", n, err)
	}

	// Mark one read by id, then the rest with all.
	one := items[0].ID
	marked, err := repo.MarkRead(ctx, alice, []string{one}, false)
	if err != nil || marked != 1 {
		t.Fatalf("MarkRead one = %d, %v; want 1", marked, err)
	}
	if n, _ := repo.UnreadCount(ctx, alice); n != 2 {
		t.Errorf("UnreadCount after marking one = %d, want 2", n)
	}
	unreadFiltered, err := repo.List(ctx, alice, Filter{Mode: "unread", Limit: 50})
	if err != nil || len(unreadFiltered) != 2 {
		t.Fatalf("unread filter = %d items, %v; want 2", len(unreadFiltered), err)
	}
	marked, err = repo.MarkRead(ctx, alice, nil, true)
	if err != nil || marked != 2 {
		t.Fatalf("MarkRead all = %d, %v; want 2", marked, err)
	}
	if n, _ := repo.UnreadCount(ctx, alice); n != 0 {
		t.Errorf("UnreadCount after marking all = %d, want 0", n)
	}

	// RBAC recheck: losing project access hides the items without deleting
	// them (they reappear if access is restored).
	if _, err := pool.Exec(ctx, `DELETE FROM project_members WHERE user_id = $1`, alice); err != nil {
		t.Fatal(err)
	}
	if items, err := repo.List(ctx, alice, Filter{Limit: 50}); err != nil || len(items) != 0 {
		t.Fatalf("List after losing access = %d items, %v; want 0", len(items), err)
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM inbox_items WHERE user_id = $1`, alice).Scan(&rows); err != nil || rows != 3 {
		t.Fatalf("underlying rows after losing access = %d, %v; want 3 (not deleted)", rows, err)
	}
}

// TestListAdminGlobalItem covers the other half of the RBAC recheck: a
// project-less (admin) item stops being visible once the recipient is no
// longer an admin.
func TestListAdminGlobalItem(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := NewRepository(pool)

	adminID := q(t, pool, `INSERT INTO users (email, password_hash, is_admin) VALUES ('admin2@xila.io', 'x', true) RETURNING id`)
	if err := repo.Fill(ctx, notify.Event{Type: notify.EventIngestionAnomaly, Title: "Global"}); err != nil {
		t.Fatal(err)
	}
	if items, err := repo.List(ctx, adminID, Filter{Limit: 50}); err != nil || len(items) != 1 {
		t.Fatalf("List = %d items, %v; want 1", len(items), err)
	}
	if _, err := pool.Exec(ctx, `UPDATE users SET is_admin = false WHERE id = $1`, adminID); err != nil {
		t.Fatal(err)
	}
	if items, err := repo.List(ctx, adminID, Filter{Limit: 50}); err != nil || len(items) != 0 {
		t.Fatalf("List after losing admin = %d items, %v; want 0", len(items), err)
	}
}
