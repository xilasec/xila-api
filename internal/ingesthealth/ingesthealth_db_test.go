package ingesthealth_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/ingesthealth"
	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/pgtest"
)

type recorder struct {
	mu     sync.Mutex
	events []notify.Event
}

func (r *recorder) Notify(_ context.Context, e notify.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

// The live view finds a silent scanner, a collapsed upload and a failing
// connector — scoped to what the caller may see — and the sweep alerts each
// once, forgetting it when it clears.
func TestCheckAndSweep(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	id := func(sql string, args ...any) string {
		t.Helper()
		var v string
		if err := pool.QueryRow(ctx, sql, args...).Scan(&v); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return v
	}
	web := id(`WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-ih','o') RETURNING id),
		tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'web','web' FROM tm RETURNING id`)
	api := id(`INSERT INTO projects (team_id, slug, name) SELECT team_id,'api','api' FROM projects WHERE id = $1 RETURNING id`, web)
	scan := func(project, scanner string, daysAgo, total int) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO scans (project_id, version_id, scanner, category, status, summary, created_at)
			VALUES ($1, project_version($1, '', 'branch'), $2, 'sca', 'completed', jsonb_build_object('high', $3::int), now() - make_interval(days => $4))`,
			project, scanner, total, daysAgo); err != nil {
			t.Fatal(err)
		}
	}
	// web/trivy: daily, last one 5 days ago → stale. web/semgrep: today's upload collapsed to 0.
	for d := 5; d <= 8; d++ {
		scan(web, "trivy", d, 20)
	}
	scan(web, "semgrep", 0, 0)
	for d := 1; d <= 4; d++ {
		scan(web, "semgrep", d, 25)
	}
	// Synthetic producers are never watched.
	scan(web, "osv", 30, 50)
	for d := 31; d <= 33; d++ {
		scan(web, "osv", d, 50)
	}
	// api: a healthy daily stream, and a failing connector.
	for d := range 4 {
		scan(api, "grype", d, 30)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO connectors (project_id, kind, name, base_url, remote_project, token_enc, enabled, last_pulled_at, last_error)
		VALUES ($1, 'defectdojo', 'dojo', 'https://dd', '1', '\x00', true, now() - interval '1 hour', 'GET /api/v2/findings/: HTTP 401')`, api); err != nil {
		t.Fatal(err)
	}

	repo := ingesthealth.NewRepository(pool)
	now := time.Now()
	all, err := repo.Check(ctx, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, a := range all {
		got[a.ProjectName+"/"+a.Scanner] = a.Kind
	}
	want := map[string]string{"web/trivy": ingesthealth.KindStale, "web/semgrep": ingesthealth.KindVolumeDrop, "api/dojo": ingesthealth.KindConnectorFailing}
	if len(got) != len(want) {
		t.Errorf("anomalies = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	if scoped, _ := repo.Check(ctx, []string{api}, now); len(scoped) != 1 || scoped[0].ProjectID != api {
		t.Errorf("scoped to api: %+v", scoped)
	}
	if none, _ := repo.Check(ctx, []string{}, now); len(none) != 0 {
		t.Errorf("an empty scope saw %+v", none)
	}

	// The sweep alerts each new anomaly once…
	rec := &recorder{}
	if n, err := repo.Sweep(ctx, rec, now); err != nil || n != 3 {
		t.Fatalf("first sweep = %d, %v", n, err)
	}
	if n, _ := repo.Sweep(ctx, rec, now); n != 0 || len(rec.events) != 3 {
		t.Errorf("second sweep re-alerted: %d new, %d events", n, len(rec.events))
	}
	for _, e := range rec.events {
		if e.Type != notify.EventIngestionAnomaly || e.ProjectID == "" || e.Text == "" {
			t.Errorf("event = %+v", e)
		}
	}
	// …and once trivy uploads again, its anomaly clears; if it goes silent again
	// later, that's a new alert.
	scan(web, "trivy", 0, 20)
	if n, _ := repo.Sweep(ctx, rec, now); n != 0 {
		t.Errorf("recovery alerted %d", n)
	}
	var open int
	pool.QueryRow(ctx, `SELECT count(*) FROM ingestion_anomalies`).Scan(&open)
	if open != 2 {
		t.Errorf("open anomalies after trivy recovered = %d, want 2", open)
	}
}
