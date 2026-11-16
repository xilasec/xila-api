package scan_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/scan"
)

// seedOrgWithProjects creates one org, one team, and n projects under it,
// returning the org id and each project id.
func seedOrgWithProjects(t *testing.T, pool *pgxpool.Pool, slug string, n int) (string, []string) {
	t.Helper()
	ctx := context.Background()
	var orgID, teamID string
	if err := pool.QueryRow(ctx, `INSERT INTO organizations (slug, name) VALUES ($1, $1) RETURNING id`, slug).Scan(&orgID); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO teams (org_id, slug, name) VALUES ($1, $2, $2) RETURNING id`, orgID, slug+"-t").Scan(&teamID); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	ids := make([]string, n)
	for i := range ids {
		if err := pool.QueryRow(ctx, `INSERT INTO projects (team_id, slug, name) VALUES ($1, $2, $2) RETURNING id`,
			teamID, fmt.Sprintf("%s-p%d", slug, i)).Scan(&ids[i]); err != nil {
			t.Fatalf("seed project: %v", err)
		}
	}
	return orgID, ids
}

// enqueueJob creates a scan and enqueues one job against it, exercising the
// real EnqueueJob path (so project_id/org_id are denormalized exactly as a
// live upload would do it).
func enqueueJob(t *testing.T, repo *scan.Repository, projectID string) {
	t.Helper()
	ctx := context.Background()
	sc, err := repo.Create(ctx, scan.Scan{ProjectID: projectID, Scanner: "trivy", Category: domain.CategorySCA})
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := repo.EnqueueJob(ctx, sc.ID, []byte(trivyReport), "", true, false); err != nil {
		t.Fatalf("enqueue job: %v", err)
	}
}

// TestClaimPrefersLeastLoadedOrg is M11 11.6's headline guarantee: org A's
// burst (many pending jobs, spread across several of its own projects so the
// per-project cap alone can't explain the result) must not starve org B's
// single upload. Org B's job is claimed within the first two claims: the
// first claim takes whichever job is globally oldest (a tie at zero
// processing each), which bumps that org's processing count to one and makes
// the other org — now strictly less loaded — win the second claim.
func TestClaimPrefersLeastLoadedOrg(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := scan.NewRepository(pool)

	orgA, aProjects := seedOrgWithProjects(t, pool, "o-fairA", 5)
	for _, pid := range aProjects {
		for i := 0; i < 10; i++ {
			enqueueJob(t, repo, pid)
		}
	}
	orgB, bProjects := seedOrgWithProjects(t, pool, "o-fairB", 1)
	enqueueJob(t, repo, bProjects[0])

	seenB := false
	for i := 0; i < 2; i++ {
		job, err := repo.ClaimJob(ctx, 5*time.Minute)
		if err != nil || job == nil {
			t.Fatalf("claim %d: job=%v err=%v", i, job, err)
		}
		var orgID string
		if err := pool.QueryRow(ctx, `SELECT org_id FROM scan_jobs WHERE id = $1`, job.ID).Scan(&orgID); err != nil {
			t.Fatalf("lookup claimed job's org: %v", err)
		}
		switch orgID {
		case orgB:
			seenB = true
		case orgA:
			// expected for whichever claim org B doesn't win
		default:
			t.Fatalf("claimed job belongs to neither seeded org: %s", orgID)
		}
	}
	if !seenB {
		t.Error("org B's single job was not claimed within the first two claims — one tenant's burst starved another's upload")
	}
}

// TestClaimEnforcesOneProcessingPerProject: many workers racing the same
// project's pending backlog must never put two of its jobs "processing" at
// once, even though the NOT EXISTS check in the claim query can race between
// concurrent transactions (ClaimJob must retry past the resulting unique
// violation rather than erroring).
func TestClaimEnforcesOneProcessingPerProject(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := scan.NewRepository(pool)

	_, projects := seedOrgWithProjects(t, pool, "o-oneproc", 1)
	projectID := projects[0]
	const jobs = 30
	for range jobs {
		enqueueJob(t, repo, projectID)
	}

	const concurrency = 10
	var wg sync.WaitGroup
	claimed := make(chan *scan.Job, concurrency)
	errs := make(chan error, concurrency)
	for range concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			job, err := repo.ClaimJob(ctx, 5*time.Minute)
			if err != nil {
				errs <- err
				return
			}
			claimed <- job
		}()
	}
	wg.Wait()
	close(claimed)
	close(errs)

	for err := range errs {
		t.Errorf("claim error: %v", err)
	}
	got := 0
	for job := range claimed {
		if job != nil {
			got++
		}
	}
	// Only one of project's jobs can ever be "processing" at a time, so of
	// `concurrency` simultaneous claimers all racing the same single project,
	// exactly one succeeds — the rest correctly find nothing claimable.
	if got != 1 {
		t.Errorf("concurrent claimers on one project claimed %d jobs, want exactly 1 (single-flight cap)", got)
	}
	var processing int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM scan_jobs WHERE project_id = $1 AND status = 'processing'`, projectID).Scan(&processing); err != nil {
		t.Fatalf("count processing: %v", err)
	}
	if processing != 1 {
		t.Errorf("processing rows for project = %d, want 1", processing)
	}
}

// TestClaimReclaimsStaleProcessingJob covers the crashed-worker path: a job
// left "processing" with an old lock is still claimable (same row, one more
// attempt), not stuck forever.
func TestClaimReclaimsStaleProcessingJob(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := scan.NewRepository(pool)

	_, projects := seedOrgWithProjects(t, pool, "o-stale", 1)
	enqueueJob(t, repo, projects[0])

	job, err := repo.ClaimJob(ctx, time.Minute)
	if err != nil || job == nil {
		t.Fatalf("initial claim: job=%v err=%v", job, err)
	}
	if job.Attempts != 1 {
		t.Fatalf("attempts = %d, want 1", job.Attempts)
	}
	// A second claim finds nothing: the lock isn't stale yet.
	if again, _ := repo.ClaimJob(ctx, time.Minute); again != nil {
		t.Fatalf("second claim = %v, want nil (lock not stale)", again)
	}

	// Simulate a crashed worker: the row is still "processing" but its lock
	// is old.
	if _, err := pool.Exec(ctx, `UPDATE scan_jobs SET locked_at = now() - interval '10 minutes' WHERE id = $1`, job.ID); err != nil {
		t.Fatalf("backdate lock: %v", err)
	}

	reclaimed, err := repo.ClaimJob(ctx, time.Minute)
	if err != nil || reclaimed == nil {
		t.Fatalf("reclaim: job=%v err=%v", reclaimed, err)
	}
	if reclaimed.ID != job.ID || reclaimed.Attempts != 2 {
		t.Errorf("reclaimed = %+v, want the same job with attempts 2", reclaimed)
	}
}

// A deep backlog doesn't hide a small tenant: org A has 2,000 jobs queued
// before org B's single upload (far more than any fixed look-ahead window over
// the global queue would reach), and B is still claimed second.
func TestClaimFairUnderDeepBacklog(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := scan.NewRepository(pool)
	_, aProjects := seedOrgWithProjects(t, pool, "deep-a", 3)
	_, bProjects := seedOrgWithProjects(t, pool, "deep-b", 1)

	// 2,000 jobs for A, all older than B's.
	if _, err := pool.Exec(ctx, `
		WITH s AS (
			INSERT INTO scans (project_id, scanner, category)
			SELECT ($1::uuid[])[1 + g % 3], 'trivy', 'sca' FROM generate_series(1, 2000) g
			RETURNING id, project_id
		)
		INSERT INTO scan_jobs (scan_id, payload, project_id, org_id, created_at)
		SELECT s.id, '{}'::bytea, s.project_id, t.org_id, now() - interval '1 hour' + (row_number() OVER ())::int * interval '1 ms'
		FROM s JOIN projects p ON p.id = s.project_id JOIN teams t ON t.id = p.team_id`, aProjects); err != nil {
		t.Fatalf("seed backlog: %v", err)
	}
	enqueueJob(t, repo, bProjects[0])

	first, err := repo.ClaimJob(ctx, time.Hour)
	if err != nil || first == nil {
		t.Fatalf("first claim = %v, %v", first, err)
	}
	second, err := repo.ClaimJob(ctx, time.Hour)
	if err != nil || second == nil {
		t.Fatalf("second claim = %v, %v", second, err)
	}
	var secondProject string
	if err := pool.QueryRow(ctx, `SELECT project_id FROM scan_jobs WHERE id = $1`, second.ID).Scan(&secondProject); err != nil {
		t.Fatal(err)
	}
	if secondProject != bProjects[0] {
		t.Errorf("second claim went to project %s, want org B's %s", secondProject, bProjects[0])
	}
}
