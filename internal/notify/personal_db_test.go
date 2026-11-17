package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/secretbox"
)

// Personal subscriptions: the assignee hears about their finding, watchers
// about their project — only while they can see it (re-checked when sending),
// never someone without access, and a personal webhook URL is never returned.
func TestPersonalNotifications(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := NewRepository(pool)
	cipher, err := secretbox.NewKeyring([]byte("0123456789abcdef0123456789abcdef"), nil) // gitleaks:allow -- test key
	if err != nil {
		t.Fatal(err)
	}
	svc := NewService(repo, SMTPConfig{})
	svc.SetSecretCipher(cipher)
	svc.SetDeliveryPolicy(DeliveryPolicy{MaxAttempts: 2, RetryBase: 10 * time.Millisecond, RetryMax: time.Second, Retention: time.Hour})

	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[strings.TrimPrefix(r.URL.Path, "/")]++
		mu.Unlock()
	}))
	defer srv.Close()

	q := func(sql string, args ...any) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, sql, args...).Scan(&id); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return id
	}
	user := func(name string) string {
		return q(`INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id`, name+"@xila.io")
	}
	project := q(`WITH o AS (INSERT INTO organizations (slug, name) VALUES ('o', 'o') RETURNING id),
		tm AS (INSERT INTO teams (org_id, slug, name) SELECT id, 't', 't' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id, 'web', 'Web' FROM tm RETURNING id`)
	alice, bob, carol, dave, erin := user("alice"), user("bob"), user("carol"), user("dave"), user("erin")
	for _, u := range []string{alice, bob, dave, erin} { // carol has no access
		q(`INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, 'viewer') RETURNING user_id`, project, u)
	}
	finding := q(`INSERT INTO findings (project_id, fingerprint, scanner, category, title, severity, assignee_id)
		VALUES ($1, 'fp', 'trivy', 'sca', 'log4shell', 'critical', $2) RETURNING id`, project, alice)

	enabled, assigned := true, false
	subscribe := func(u, name string, onAssigned *bool) {
		t.Helper()
		url := srv.URL + "/" + name
		seal := func(id, url string) ([]byte, error) { return cipher.Seal(url, id) }
		if err := repo.savePersonal(ctx, u, onAssigned, nil, map[string]personalUpdate{
			"slack": {Enabled: &enabled, URL: &url}}, seal); err != nil {
			t.Fatal(err)
		}
	}
	subscribe(alice, "alice", nil)
	subscribe(bob, "bob", nil)
	subscribe(carol, "carol", nil)
	subscribe(dave, "dave", nil)
	subscribe(erin, "erin", &assigned) // erin: assigned-to-me off, watching nothing
	for _, u := range []string{bob, carol, dave} {
		if err := repo.Watch(ctx, u, project, true); err != nil {
			t.Fatal(err)
		}
	}

	svc.Notify(ctx, Event{Type: EventFindingAssigned, ProjectID: project, FindingID: finding, Severity: "critical", Title: "Assigned: log4shell"})
	// Dave loses access between queueing and sending.
	if _, err := pool.Exec(ctx, `DELETE FROM project_members WHERE user_id = $1`, dave); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DispatchDue(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := map[string]int{}
	for k, v := range hits {
		got[k] = v
	}
	mu.Unlock()
	if got["alice"] != 1 || got["bob"] != 1 || got["carol"] != 0 || got["dave"] != 0 || got["erin"] != 0 {
		t.Errorf("deliveries = %v; want alice (assignee) and bob (watcher) once, nobody else", got)
	}
	// Dave's attempt is in his own delivery log, refused, not retried.
	log, err := repo.PersonalDeliveries(ctx, dave, 10)
	if err != nil || len(log) != 1 || log[0].Delivered || !strings.Contains(log[0].Error, "can no longer see") {
		t.Errorf("dave's log = %+v, %v", log, err)
	}

	// The admin channel list never shows personal channels; prefs never the URL.
	if list, _ := repo.List(ctx); len(list) != 0 {
		t.Errorf("admin list shows %d personal channels", len(list))
	}
	prefs, err := repo.PersonalPrefsOf(ctx, bob)
	if err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(prefs)
	if !prefs.Methods["slack"].HasURL || strings.Contains(string(out), srv.URL) || len(prefs.Watching) != 1 {
		t.Errorf("bob's prefs = %s", out)
	}
}
