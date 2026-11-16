package scan

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Job is a queued ingest: the raw payload plus the options needed to process
// it. The owning scan row (project, scanner, …) is referenced by ScanID.
// Exactly one of Payload/PayloadRef is set: Payload when
// INGEST_PAYLOAD_STORE=postgres (the default), PayloadRef — the object store
// key a worker fetches with scan.PayloadStore.Get — when it's s3.
type Job struct {
	ID           string
	ScanID       string
	Payload      []byte
	PayloadRef   string
	Format       string
	CloseMissing bool
	// Force skips the skip-unchanged check: always run the full pipeline (the
	// upload's force=true query parameter, carried through to the worker since
	// the content hash is only known after this payload is parsed).
	Force    bool
	Attempts int
}

// EnqueueJob stores a job for later processing by a worker. Exactly one of
// payload/payloadRef is non-empty (see Job).
func (r *Repository) EnqueueJob(ctx context.Context, scanID string, payload []byte, payloadRef, format string, closeMissing, force bool) error {
	const q = `INSERT INTO scan_jobs (scan_id, payload, payload_ref, format, close_missing, force) VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6)`
	if _, err := r.db.Exec(ctx, q, scanID, payload, payloadRef, format, closeMissing, force); err != nil {
		return fmt.Errorf("enqueue job: %w", err)
	}
	return nil
}

// ClaimJob atomically grabs one claimable job — pending, or a processing job
// whose lock has gone stale (a crashed worker) — marks it processing, and
// returns it. SKIP LOCKED lets many workers/instances claim concurrently without
// contention. Returns (nil, nil) when the queue is empty.
func (r *Repository) ClaimJob(ctx context.Context, staleAfter time.Duration) (*Job, error) {
	const q = `
		UPDATE scan_jobs SET status = 'processing', locked_at = now(), attempts = attempts + 1
		WHERE id = (
			SELECT id FROM scan_jobs
			WHERE status = 'pending'
			   OR (status = 'processing' AND locked_at < now() - make_interval(secs => $1))
			ORDER BY created_at
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		RETURNING id, scan_id, payload, COALESCE(payload_ref, ''), format, close_missing, force, attempts`
	var j Job
	err := r.db.QueryRow(ctx, q, staleAfter.Seconds()).
		Scan(&j.ID, &j.ScanID, &j.Payload, &j.PayloadRef, &j.Format, &j.CloseMissing, &j.Force, &j.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("claim job: %w", err)
	}
	return &j, nil
}

// CompleteJob removes a finished job from the queue.
func (r *Repository) CompleteJob(ctx context.Context, jobID string) error {
	if _, err := r.db.Exec(ctx, `DELETE FROM scan_jobs WHERE id = $1`, jobID); err != nil {
		return fmt.Errorf("complete job: %w", err)
	}
	return nil
}

// FailJob records a processing failure: it re-queues the job (pending) for retry
// until maxAttempts, then parks it as failed. Returns whether it will retry.
func (r *Repository) FailJob(ctx context.Context, jobID, errMsg string, maxAttempts int) (bool, error) {
	const q = `
		UPDATE scan_jobs
		SET status = CASE WHEN attempts >= $3 THEN 'failed' ELSE 'pending' END,
		    locked_at = NULL, last_error = $2
		WHERE id = $1
		RETURNING status`
	var status string
	if err := r.db.QueryRow(ctx, q, jobID, errMsg, maxAttempts).Scan(&status); err != nil {
		return false, fmt.Errorf("fail job: %w", err)
	}
	return status == "pending", nil
}

// QueueStats is the health of the ingest queue at a moment in time.
type QueueStats struct {
	Pending    int           `json:"pending"`    // waiting for a worker
	Processing int           `json:"processing"` // claimed by a worker right now
	Failed     int           `json:"failed"`     // parked after exhausting retries
	OldestWait time.Duration `json:"-"`          // age of the oldest pending job
	// OldestWaitSeconds is OldestWait in the JSON payload — the number ops cares
	// about: how far behind the workers are.
	OldestWaitSeconds float64 `json:"oldest_wait_seconds"`
}

// QueueStats summarizes the queue. It is a single aggregate over scan_jobs, which
// only ever holds *unfinished* work (completed jobs are deleted), so it stays
// small and this stays cheap.
func (r *Repository) QueueStats(ctx context.Context) (QueueStats, error) {
	const q = `
		SELECT
			count(*) FILTER (WHERE status = 'pending'),
			count(*) FILTER (WHERE status = 'processing'),
			count(*) FILTER (WHERE status = 'failed'),
			COALESCE(EXTRACT(EPOCH FROM (now() - min(created_at) FILTER (WHERE status = 'pending'))), 0)
		FROM scan_jobs`
	var s QueueStats
	var oldest float64
	if err := r.db.QueryRow(ctx, q).Scan(&s.Pending, &s.Processing, &s.Failed, &oldest); err != nil {
		return QueueStats{}, fmt.Errorf("queue stats: %w", err)
	}
	s.OldestWait = time.Duration(oldest * float64(time.Second))
	s.OldestWaitSeconds = oldest
	return s, nil
}
