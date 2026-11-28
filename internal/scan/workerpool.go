package scan

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// jobClaimer claims and resolves queued jobs; *Repository satisfies it. A
// narrow interface so WorkerPool is unit-testable with a fake, no database.
type jobClaimer interface {
	ClaimJob(ctx context.Context, staleAfter time.Duration) (*Job, error)
	CompleteJob(ctx context.Context, jobID string) error
	FailJob(ctx context.Context, jobID, errMsg string, maxAttempts int) (bool, error)
}

// jobRunner processes one claimed job; *Service satisfies it.
type jobRunner interface {
	ProcessJob(ctx context.Context, job Job) error
}

// WorkerPool runs a resizable set of goroutines draining the ingest queue.
// The count can change at runtime (M11 11.7 live tuning): Resize starts new
// workers immediately and stops surplus ones the next time they are idle
// between jobs — never mid-job, so a shrink never abandons work in flight.
type WorkerPool struct {
	jobs        jobClaimer
	ingest      jobRunner
	poll        time.Duration
	maxAttempts int
	staleAfter  time.Duration

	mu      sync.Mutex
	workers []context.CancelFunc
	wg      sync.WaitGroup
	active  atomic.Int64 // workers actually running right now, for observability/tests
}

// NewWorkerPool builds an idle pool (0 workers); call Resize to start some.
func NewWorkerPool(jobs jobClaimer, ingest jobRunner, poll time.Duration, maxAttempts int) *WorkerPool {
	return &WorkerPool{jobs: jobs, ingest: ingest, poll: poll, maxAttempts: maxAttempts, staleAfter: 5 * time.Minute}
}

// Count returns the number of workers the pool is currently targeting (set
// synchronously by Resize; the goroutines themselves may still be starting up
// or finishing a last job).
func (p *WorkerPool) Count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.workers)
}

// Active returns the number of worker goroutines actually running right now.
func (p *WorkerPool) Active() int {
	return int(p.active.Load())
}

// Resize grows or shrinks the pool to exactly n workers (n < 0 is treated as
// 0 — INGEST_WORKERS=0 stays possible, a web-only node). Growing starts new
// goroutines immediately; shrinking cancels the surplus workers' context,
// which they observe between jobs — never mid-job — and exit. Safe to call
// concurrently and repeatedly (the queue monitor calls it once per sample).
func (p *WorkerPool) Resize(ctx context.Context, n int) {
	if n < 0 {
		n = 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.workers) < n {
		wctx, cancel := context.WithCancel(ctx)
		p.workers = append(p.workers, cancel)
		p.wg.Go(func() {
			p.run(wctx)
		})
	}
	for len(p.workers) > n {
		last := len(p.workers) - 1
		p.workers[last]()
		p.workers = p.workers[:last]
	}
}

// Stop cancels every worker and waits for them to finish their current job.
func (p *WorkerPool) Stop() {
	p.mu.Lock()
	for _, cancel := range p.workers {
		cancel()
	}
	p.workers = nil
	p.mu.Unlock()
	p.wg.Wait()
}

// run drains queued ingest jobs until ctx is cancelled. Each iteration claims
// one job (SKIP LOCKED), processes it off the request path, and either
// deletes it or re-queues/parks it on failure. Idle workers poll on an
// interval; cancellation is observed between jobs (the inner loop's ctx.Err()
// check, and the outer select), never while a job is being processed.
func (p *WorkerPool) run(ctx context.Context) {
	p.active.Add(1)
	defer p.active.Add(-1)

	ticker := time.NewTicker(p.poll)
	defer ticker.Stop()
	for {
		// Drain everything available before sleeping, so bursts don't wait a tick.
		for {
			if ctx.Err() != nil {
				return
			}
			job, err := p.jobs.ClaimJob(ctx, p.staleAfter)
			if err != nil {
				slog.WarnContext(ctx, "claim scan job failed", "error", err)
				break
			}
			if job == nil {
				break // queue (or claim window) empty
			}
			if err := p.ingest.ProcessJob(ctx, *job); err != nil {
				retry, ferr := p.jobs.FailJob(ctx, job.ID, err.Error(), p.maxAttempts)
				slog.WarnContext(ctx, "scan job failed", "job_id", job.ID, "scan_id", job.ScanID,
					"attempts", job.Attempts, "will_retry", retry, "error", err, "fail_err", ferr)
			} else if err := p.jobs.CompleteJob(ctx, job.ID); err != nil {
				slog.WarnContext(ctx, "complete scan job failed", "job_id", job.ID, "error", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
