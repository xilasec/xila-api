package scan_test

import (
	"context"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/scan"
	"github.com/xilasec/xila-api/internal/scanner"
)

const trivyReport = `{"Results":[{"Target":"go.mod","Vulnerabilities":[
	{"VulnerabilityID":"CVE-2021-44228","PkgName":"log4j","Severity":"CRITICAL"}]}]}`

func TestAsyncIngestQueue(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	scanRepo := scan.NewRepository(pool)
	findingRepo := finding.NewRepository(pool)
	projectRepo := project.NewRepository(pool)
	parsers := scanner.NewRegistry(scanner.NewTrivy())
	svc := scan.NewService(scanRepo, findingRepo, projectRepo, parsers, nil, nil, scanRepo)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-q','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	// Enqueue returns immediately with a processing scan and a queued job.
	sc, err := svc.Enqueue(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy"}, []byte(trivyReport))
	if err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if sc.Status != domain.ScanProcessing {
		t.Errorf("enqueued scan status = %q, want processing", sc.Status)
	}

	// A worker claims the job (SKIP LOCKED).
	job, err := scanRepo.ClaimJob(ctx, 5*time.Minute)
	if err != nil || job == nil {
		t.Fatalf("claim: job=%v err=%v", job, err)
	}
	if job.ScanID != sc.ID || job.Attempts != 1 {
		t.Errorf("claimed job = scan %s attempts %d, want scan %s attempts 1", job.ScanID, job.Attempts, sc.ID)
	}
	// A second claim finds nothing — the job is processing (not stale).
	if j2, _ := scanRepo.ClaimJob(ctx, 5*time.Minute); j2 != nil {
		t.Errorf("second claim returned %v, want nil (job in flight)", j2)
	}

	// Process it → findings land, scan completes.
	if err := svc.ProcessJob(ctx, *job); err != nil {
		t.Fatalf("process: %v", err)
	}
	if err := scanRepo.CompleteJob(ctx, job.ID); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if got, _ := scanRepo.Get(ctx, sc.ID); got.Status != domain.ScanCompleted {
		t.Errorf("scan status = %q, want completed", got.Status)
	}
	if list, _ := findingRepo.List(ctx, finding.Filter{ProjectID: projectID}); len(list) != 1 {
		t.Errorf("findings = %d, want 1 (the log4j critical)", len(list))
	}
	// Queue drained.
	if j3, _ := scanRepo.ClaimJob(ctx, 5*time.Minute); j3 != nil {
		t.Errorf("queue not empty after completion: %v", j3)
	}
}

func TestJobRetryAndPark(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	scanRepo := scan.NewRepository(pool)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-r','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	sc, err := scanRepo.Create(ctx, scan.Scan{ProjectID: projectID, Scanner: "trivy", Category: domain.CategorySCA})
	if err != nil {
		t.Fatalf("create scan: %v", err)
	}
	if err := scanRepo.EnqueueJob(ctx, sc.ID, []byte(trivyReport), "", true, false); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Claim, then fail with maxAttempts=2 → re-queued (pending) for retry.
	job, _ := scanRepo.ClaimJob(ctx, 5*time.Minute)
	retry, err := scanRepo.FailJob(ctx, job.ID, "boom", 2)
	if err != nil || !retry {
		t.Fatalf("first fail should retry: retry=%v err=%v", retry, err)
	}
	// It's claimable again (attempts now 2).
	job2, _ := scanRepo.ClaimJob(ctx, 5*time.Minute)
	if job2 == nil || job2.Attempts != 2 {
		t.Fatalf("re-claim = %v, want attempts 2", job2)
	}
	// Failing at the attempt limit parks it as failed (no more retries).
	retry2, _ := scanRepo.FailJob(ctx, job2.ID, "boom again", 2)
	if retry2 {
		t.Error("should not retry past maxAttempts")
	}
	if j3, _ := scanRepo.ClaimJob(ctx, 5*time.Minute); j3 != nil {
		t.Errorf("parked-failed job should not be claimable, got %v", j3)
	}
}

// TestQueueStatsTracksBacklog covers what operators page on: not just how many
// jobs are queued, but how long the oldest one has been waiting. Depth alone is
// ambiguous — a steady 500 that workers are draining is healthy, a steady 5 that
// nobody has touched for an hour is not.
func TestQueueStatsTracksBacklog(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := scan.NewRepository(pool)
	svc := scan.NewService(repo, finding.NewRepository(pool), project.NewRepository(pool),
		scanner.NewRegistry(scanner.NewTrivy()), nil, nil, repo)

	var projectID string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-qs','o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t','t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,'p','p' FROM tm RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	if s, err := repo.QueueStats(ctx); err != nil || s.Pending != 0 || s.OldestWaitSeconds != 0 {
		t.Fatalf("empty queue stats = %+v, err %v", s, err)
	}

	for i := 0; i < 3; i++ {
		if _, err := svc.Enqueue(ctx, scan.IngestRequest{ProjectID: projectID, Scanner: "trivy"}, []byte(trivyReport)); err != nil {
			t.Fatalf("enqueue: %v", err)
		}
	}
	// Backdate the oldest job so the wait is measurable without sleeping.
	if _, err := pool.Exec(ctx,
		`UPDATE scan_jobs SET created_at = now() - interval '2 minutes'
		 WHERE id = (SELECT id FROM scan_jobs ORDER BY created_at LIMIT 1)`); err != nil {
		t.Fatalf("backdate: %v", err)
	}

	s, err := repo.QueueStats(ctx)
	if err != nil {
		t.Fatalf("queue stats: %v", err)
	}
	if s.Pending != 3 || s.Processing != 0 {
		t.Errorf("stats = %+v, want 3 pending / 0 processing", s)
	}
	if s.OldestWaitSeconds < 110 {
		t.Errorf("oldest wait = %.0fs, want ~120s (the backdated job)", s.OldestWaitSeconds)
	}

	// A claimed job moves from pending to processing, and the wait now reflects
	// the next job in line rather than the one being worked.
	job, err := repo.ClaimJob(ctx, time.Minute)
	if err != nil || job == nil {
		t.Fatalf("claim: %v (job %v)", err, job)
	}
	s, err = repo.QueueStats(ctx)
	if err != nil {
		t.Fatalf("queue stats: %v", err)
	}
	if s.Pending != 2 || s.Processing != 1 {
		t.Errorf("stats = %+v, want 2 pending / 1 processing", s)
	}
	if s.OldestWaitSeconds > 60 {
		t.Errorf("oldest wait = %.0fs; the backdated job is being worked, so the wait should drop", s.OldestWaitSeconds)
	}

	// Completing removes it from the queue entirely — the table only holds work
	// that still has to happen, which is what keeps this aggregate cheap.
	if err := repo.CompleteJob(ctx, job.ID); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if s, _ := repo.QueueStats(ctx); s.Processing != 0 || s.Pending != 2 {
		t.Errorf("after complete stats = %+v, want 2 pending / 0 processing", s)
	}
}
