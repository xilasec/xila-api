package sbom_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/sbom"
)

func TestProcessingRollsUpSteps(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := sbom.NewRepository(pool)
	ctx := context.Background()
	s, err := repo.Ingest(ctx, sbom.Sbom{ProjectID: seedProject(t, pool, "roll"), Artifact: "a", Format: "CycloneDX"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	p, err := repo.CreateProcessing(ctx, s.ID, []string{sbom.StepVulnMatch, sbom.StepPkgMeta})
	if err != nil || p.Status != sbom.StepPending || p.CompletedAt != nil {
		t.Fatalf("create = %+v, %v; want pending", p, err)
	}
	if p, _ = repo.MarkStep(ctx, s.ID, sbom.StepVulnMatch, sbom.StepRunning, ""); p.Status != sbom.StepRunning {
		t.Errorf("one step running = %s, want running", p.Status)
	}
	if p, _ = repo.MarkStep(ctx, s.ID, sbom.StepVulnMatch, sbom.StepCompleted, ""); p.Status != sbom.StepRunning {
		t.Errorf("one of two done = %s, want running", p.Status)
	}
	p, err = repo.MarkStep(ctx, s.ID, sbom.StepPkgMeta, sbom.StepCompleted, "")
	if err != nil || p.Status != sbom.StepCompleted || p.CompletedAt == nil {
		t.Errorf("all done = %+v, %v; want completed with completed_at", p, err)
	}

	// No steps: nothing to wait for.
	empty, err := repo.Ingest(ctx, sbom.Sbom{ProjectID: s.ProjectID, Artifact: "b", Format: "CycloneDX"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p, err := repo.CreateProcessing(ctx, empty.ID, nil); err != nil || p.Status != sbom.StepCompleted {
		t.Errorf("no steps = %+v, %v; want completed", p, err)
	}

	// A failed step fails the upload and keeps its message.
	failed, err := repo.Ingest(ctx, sbom.Sbom{ProjectID: s.ProjectID, Artifact: "c", Format: "CycloneDX"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateProcessing(ctx, failed.ID, []string{sbom.StepVulnMatch, sbom.StepPkgMeta}); err != nil {
		t.Fatal(err)
	}
	if p, _ := repo.MarkStep(ctx, failed.ID, sbom.StepPkgMeta, sbom.StepFailed, "registry unavailable"); p.Status != sbom.StepFailed || p.Error != "registry unavailable" {
		t.Errorf("failed step = %+v, want failed with its message", p)
	}
}

// Two steps finishing at the same moment must both be recorded. This forces
// the interleaving: one MarkStep is made to wait on the row lock while another
// writer commits, then must apply its change on top of that commit rather
// than over it.
func TestMarkStepDoesNotLoseAConcurrentUpdate(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := sbom.NewRepository(pool)
	ctx := context.Background()
	s, err := repo.Ingest(ctx, sbom.Sbom{ProjectID: seedProject(t, pool, "race"), Artifact: "a", Format: "CycloneDX"}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateProcessing(ctx, s.ID, []string{sbom.StepVulnMatch, sbom.StepPkgMeta}); err != nil {
		t.Fatal(err)
	}

	holder, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Rollback(ctx) //nolint:errcheck // no-op after commit
	if _, err := holder.Exec(ctx, `SELECT 1 FROM sbom_processing WHERE sbom_id = $1 FOR UPDATE`, s.ID); err != nil {
		t.Fatal(err)
	}

	type result struct {
		p   sbom.ProcessingStatus
		err error
	}
	done := make(chan result, 1)
	go func() {
		p, err := repo.MarkStep(ctx, s.ID, sbom.StepVulnMatch, sbom.StepCompleted, "")
		done <- result{p, err}
	}()
	waitForLockWaiter(t, ctx, pool)

	// The concurrent writer: the other step completes and commits first.
	if _, err := holder.Exec(ctx,
		`UPDATE sbom_processing SET steps = jsonb_set(steps, '{pkgmeta}', '"completed"') WHERE sbom_id = $1`, s.ID); err != nil {
		t.Fatal(err)
	}
	if err := holder.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	r := <-done
	if r.err != nil {
		t.Fatal(r.err)
	}
	if r.p.Steps[sbom.StepPkgMeta] != sbom.StepCompleted || r.p.Steps[sbom.StepVulnMatch] != sbom.StepCompleted {
		t.Fatalf("steps = %v, want both completed (the concurrent pkgmeta update was lost)", r.p.Steps)
	}
	if r.p.Status != sbom.StepCompleted {
		t.Errorf("status = %s, want completed", r.p.Status)
	}
}

// waitForLockWaiter blocks until a session of this database is waiting for a
// lock (the MarkStep under test, queued behind the holder's row lock).
func waitForLockWaiter(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var waiting bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS (
			SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
			WHERE NOT l.granted AND a.datname = current_database())`).Scan(&waiting); err != nil {
			t.Fatal(err)
		}
		if waiting {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("MarkStep never waited on the row lock")
}
