package retention_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/retention"
)

// Retention deletes what is past its lifetime and nothing the live views and
// lifecycle depend on: the current SBOM of every artifact, the scan each
// finding was last seen in, the latest scan of each target, the default
// version.
func TestRetentionKeepsWhatMatters(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	q := func(sql string, args ...any) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, sql, args...).Scan(&id); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return id
	}
	n := func(sql string, args ...any) int {
		t.Helper()
		var c int
		if err := pool.QueryRow(ctx, sql, args...).Scan(&c); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return c
	}
	projectID := q(`WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-ret','o') RETURNING id),
		tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'web','web' FROM tm RETURNING id`)
	mainV := q(`SELECT project_version($1, '', 'branch')`, projectID)
	oldRelease := q(`INSERT INTO project_versions (project_id, name, kind, created_at) VALUES ($1, 'v1.0', 'release', now() - interval '400 days') RETURNING id`, projectID)

	// Five snapshots of "web" on main, a year apart down to today; one of "cli".
	var webSnaps []string
	for i := range 5 {
		webSnaps = append(webSnaps, q(`INSERT INTO sboms (project_id, version_id, artifact, version, created_at)
			VALUES ($1, $2, 'web', $3, now() - make_interval(days => $4)) RETURNING id`, projectID, mainV, fmt.Sprint(i), (4-i)*100))
	}
	cliSnap := q(`INSERT INTO sboms (project_id, version_id, artifact, version, created_at)
		VALUES ($1, $2, 'cli', '1', now() - interval '500 days') RETURNING id`, projectID, mainV)

	// Scans: an old one a finding still points at, an old one nothing needs, and
	// the latest of the same target.
	scan := func(ago string) string {
		return q(`INSERT INTO scans (project_id, version_id, scanner, category, status, created_at)
			VALUES ($1, $2, 'trivy', 'sca', 'completed', now() - $3::interval) RETURNING id`, projectID, mainV, ago)
	}
	pinned, stale, latest := scan("300 days"), scan("200 days"), scan("1 day")
	q(`INSERT INTO findings (project_id, version_id, fingerprint, scanner, category, title, severity, first_scan_id, last_scan_id)
		VALUES ($1, $2, 'f1', 'trivy', 'sca', 'old but still reported', 'high', $3, $3) RETURNING id`, projectID, mainV, pinned)
	q(`INSERT INTO findings (project_id, version_id, fingerprint, scanner, category, title, severity, first_scan_id, last_scan_id)
		VALUES ($1, $2, 'f2', 'trivy', 'sca', 'seen today', 'high', $3, $4) RETURNING id`, projectID, mainV, stale, latest)

	// Logs.
	q(`INSERT INTO notification_deliveries (channel_name, event_type, delivered, attempts, created_at)
		VALUES ('x', 'test', true, 1, now() - interval '200 days') RETURNING id`)
	q(`INSERT INTO notification_deliveries (channel_name, event_type, delivered, attempts) VALUES ('x', 'test', true, 1) RETURNING id`)

	// Ingest jobs: an old failed one (a log), an old one still pending (work
	// that must never be dropped), and a recently failed one.
	job := func(status, ago string) string {
		return q(`INSERT INTO scan_jobs (scan_id, payload, status, created_at)
			VALUES ($1, '\x00', $2, now() - $3::interval) RETURNING id`, latest, status, ago)
	}
	oldFailed, oldPending, newFailed := job("failed", "200 days"), job("pending", "200 days"), job("failed", "1 day")

	projects := project.NewRepository(pool)

	// Nothing configured: nothing deleted.
	if res, err := retention.NewService(pool, projects, retention.Policy{}).Run(ctx); err != nil || res != (retention.Result{}) {
		t.Fatalf("empty policy deleted %+v (%v)", res, err)
	}

	res, err := retention.NewService(pool, projects, retention.Policy{
		ReleaseAge: 365 * 24 * time.Hour,
		SBOMKeep:   2, SBOMAge: 150 * 24 * time.Hour, // keep 2 newest; older go once 150+ days old
		ScanAge: 90 * 24 * time.Hour,
		LogAge:  90 * 24 * time.Hour,
	}).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// web: newest two kept (0, 100 days); 200/300/400-day ones go. cli: its only snapshot stays (current).
	want := retention.Result{Releases: 1, SBOMSnapshots: 3, Scans: 1, Deliveries: 1, FailedJobs: 1}
	if res != want {
		t.Errorf("deleted %+v, want %+v", res, want)
	}
	for _, id := range []string{webSnaps[3], webSnaps[4], cliSnap} {
		if n(`SELECT count(*) FROM sboms WHERE id = $1`, id) != 1 {
			t.Errorf("a snapshot that must stay (%s) was deleted", id)
		}
	}
	if n(`SELECT count(*) FROM scans WHERE id = ANY($1)`, []string{pinned, latest}) != 2 || n(`SELECT count(*) FROM scans WHERE id = $1`, stale) != 0 {
		t.Error("scan retention removed a scan a finding or the target depends on (or kept the stale one)")
	}
	if n(`SELECT count(*) FROM scan_jobs WHERE id = $1`, oldFailed) != 0 ||
		n(`SELECT count(*) FROM scan_jobs WHERE id = ANY($1)`, []string{oldPending, newFailed}) != 2 {
		t.Error("log retention must drop only failed ingest jobs past LOG_RETENTION, never pending work")
	}
	if n(`SELECT count(*) FROM findings WHERE project_id = $1`, projectID) != 2 {
		t.Error("retention deleted findings")
	}
	if n(`SELECT count(*) FROM findings WHERE fingerprint = 'f2' AND first_scan_id IS NULL AND last_scan_id = $1`, latest) != 1 {
		t.Error("the finding first seen in the deleted scan should keep its last scan and lose only first_scan_id")
	}
	if n(`SELECT count(*) FROM project_versions WHERE id = $1`, oldRelease) != 0 || n(`SELECT count(*) FROM project_versions WHERE id = $1`, mainV) != 1 {
		t.Error("release pruning got the wrong version")
	}
}
