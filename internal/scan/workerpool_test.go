package scan

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// fakeIdleClaimer reports an empty queue — workers settle into their idle poll
// immediately, so Resize's effect is observable without a database.
type fakeIdleClaimer struct{}

func (fakeIdleClaimer) ClaimJob(context.Context, time.Duration) (*Job, error)      { return nil, nil }
func (fakeIdleClaimer) CompleteJob(context.Context, string) error                  { return nil }
func (fakeIdleClaimer) FailJob(context.Context, string, string, int) (bool, error) { return false, nil }

type fakeRunner struct{}

func (fakeRunner) ProcessJob(context.Context, Job) error { return nil }

// waitForActive polls until the pool's running-goroutine count matches want,
// or fails after a generous timeout.
func waitForActive(t *testing.T, p *WorkerPool, want int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p.Active() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("active workers = %d, want %d", p.Active(), want)
}

// TestWorkerPoolResize covers M11 11.7: the pool grows and shrinks to the
// target count, including down to zero (INGEST_WORKERS=0 must stay possible).
func TestWorkerPoolResize(t *testing.T) {
	p := NewWorkerPool(fakeIdleClaimer{}, fakeRunner{}, 20*time.Millisecond, 3)
	ctx := context.Background()

	p.Resize(ctx, 4)
	if got := p.Count(); got != 4 {
		t.Fatalf("Count() = %d, want 4", got)
	}
	waitForActive(t, p, 4)

	p.Resize(ctx, 1)
	if got := p.Count(); got != 1 {
		t.Fatalf("Count() = %d, want 1", got)
	}
	waitForActive(t, p, 1)

	p.Resize(ctx, 0)
	if got := p.Count(); got != 0 {
		t.Fatalf("Count() = %d, want 0", got)
	}
	waitForActive(t, p, 0)

	// Negative is treated as zero, not an error.
	p.Resize(ctx, -5)
	if got := p.Count(); got != 0 {
		t.Fatalf("Count() after negative resize = %d, want 0", got)
	}

	p.Stop()
}

// onceClaimer hands out exactly one job, then reports an empty queue forever.
type onceClaimer struct {
	done atomic.Bool
}

func (c *onceClaimer) ClaimJob(context.Context, time.Duration) (*Job, error) {
	if c.done.CompareAndSwap(false, true) {
		return &Job{ID: "job-1"}, nil
	}
	return nil, nil
}
func (c *onceClaimer) CompleteJob(context.Context, string) error                  { return nil }
func (c *onceClaimer) FailJob(context.Context, string, string, int) (bool, error) { return false, nil }

// blockingRunner holds ProcessJob open until told to finish, to simulate a job
// still in flight.
type blockingRunner struct {
	started chan struct{}
	release chan struct{}
}

func (r *blockingRunner) ProcessJob(context.Context, Job) error {
	close(r.started)
	<-r.release
	return nil
}

// TestWorkerPoolStopsOnlyBetweenJobs is the M11 11.7 contract that matters
// most: shrinking never abandons a job mid-flight. The worker must stay
// active until the blocked job returns, even though Resize asked for 0.
func TestWorkerPoolStopsOnlyBetweenJobs(t *testing.T) {
	runner := &blockingRunner{started: make(chan struct{}), release: make(chan struct{})}
	claimer := &onceClaimer{}
	p := NewWorkerPool(claimer, runner, 10*time.Millisecond, 3)
	ctx := t.Context()

	p.Resize(ctx, 1)
	select {
	case <-runner.started:
	case <-time.After(time.Second):
		t.Fatal("worker never started processing the job")
	}

	// Shrink to 0 while the job is still "in flight": the worker must not
	// exit yet — stopping is only allowed between jobs.
	p.Resize(ctx, 0)
	time.Sleep(50 * time.Millisecond)
	if got := p.Active(); got != 1 {
		t.Fatalf("active = %d while a job is in flight, want 1 (must not abandon a running job)", got)
	}

	close(runner.release) // let the job finish
	waitForActive(t, p, 0)
}
