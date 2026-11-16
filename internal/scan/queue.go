package scan

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
// payload/payloadRef is non-empty (see Job). project_id/org_id are
// denormalized from the scan's project/team at insert time (M11 11.6): the
// claim query reads them without joining through scans -> projects -> teams
// on every claim.
func (r *Repository) EnqueueJob(ctx context.Context, scanID string, payload []byte, payloadRef, format string, closeMissing, force bool) error {
	const q = `
		INSERT INTO scan_jobs (scan_id, payload, payload_ref, format, close_missing, force, project_id, org_id)
		SELECT $1, $2, NULLIF($3, ''), $4, $5, $6, p.id, t.org_id
		FROM scans s
		JOIN projects p ON p.id = s.project_id
		JOIN teams t ON t.id = p.team_id
		WHERE s.id = $1`
	tag, err := r.db.Exec(ctx, q, scanID, payload, payloadRef, format, closeMissing, force)
	if err != nil {
		return fmt.Errorf("enqueue job: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("enqueue job: scan %s not found", scanID)
	}
	return nil
}

// orgLookahead bounds how deep the claim looks into each org's pending jobs
// for one whose project has nothing processing. An org whose oldest
// orgLookahead jobs all belong to busy projects is passed over for this claim
// (its projects are being worked on anyway) instead of the query walking a
// 100,000-job backlog of one project.
const orgLookahead = 64

// maxClaimRetries bounds the retries after losing a race to another claimer:
// both picked the same job, or two jobs of one project and collided on
// idx_scan_jobs_one_processing_per_project. The loser re-picks from a fresh
// snapshot rather than reporting an empty queue.
const maxClaimRetries = 5

// staleClaimSQL reclaims the job of a crashed worker: a processing job whose
// lock is older than $1 seconds. It stays processing (so its project's slot
// stays taken) and is handed to this worker.
const staleClaimSQL = `
	UPDATE scan_jobs SET locked_at = now(), attempts = attempts + 1
	WHERE id = (
		SELECT id FROM scan_jobs
		WHERE status = 'processing' AND locked_at < now() - make_interval(secs => $1)
		ORDER BY locked_at
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	)
	RETURNING id, scan_id, payload, COALESCE(payload_ref, ''), format, close_missing, force, attempts`

// fairClaimSQL implements fair queueing (M11 11.6) in one statement:
//
//  1. pending_orgs lists every org with pending jobs by a loose index scan of
//     idx_scan_jobs_pending_org (one probe per org, independent of depth).
//  2. org_load counts each org's processing jobs (bounded by the number of
//     workers cluster-wide).
//  3. For each org, its oldest pending job (among its orgLookahead oldest)
//     whose project has nothing processing; then the org with the fewest jobs
//     processing wins, oldest job first on a tie.
//
// So a tenant with 100,000 queued jobs can't starve another tenant's single
// upload: that upload's org has nothing processing and is picked next. The
// UPDATE re-checks status = 'pending', and the outer SELECT always returns the
// job it picked, so a claimer that lost the race (picked IS NOT NULL, nothing
// updated) can tell it apart from an empty queue (picked IS NULL).
const fairClaimSQL = `
	WITH RECURSIVE pending_orgs AS (
		(SELECT org_id FROM scan_jobs WHERE status = 'pending' ORDER BY org_id LIMIT 1)
		UNION ALL
		SELECT (SELECT s.org_id FROM scan_jobs s
		        WHERE s.status = 'pending' AND s.org_id > o.org_id ORDER BY s.org_id LIMIT 1)
		FROM pending_orgs o WHERE o.org_id IS NOT NULL
	),
	org_load AS (
		SELECT org_id, count(*) AS n FROM scan_jobs WHERE status = 'processing' GROUP BY org_id
	),
	candidate AS (
		SELECT c.id
		FROM pending_orgs o
		LEFT JOIN org_load ol ON ol.org_id = o.org_id
		CROSS JOIN LATERAL (
			SELECT w.id, w.created_at
			FROM (
				SELECT s.id, s.project_id, s.created_at FROM scan_jobs s
				WHERE s.org_id = o.org_id AND s.status = 'pending'
				ORDER BY s.created_at LIMIT $1
			) w
			WHERE NOT EXISTS (
				SELECT 1 FROM scan_jobs b WHERE b.project_id = w.project_id AND b.status = 'processing'
			)
			ORDER BY w.created_at
			LIMIT 1
		) c
		WHERE o.org_id IS NOT NULL
		ORDER BY COALESCE(ol.n, 0), c.created_at
		LIMIT 1
	),
	claimed AS (
		UPDATE scan_jobs SET status = 'processing', locked_at = now(), attempts = attempts + 1
		WHERE id = (SELECT id FROM candidate) AND status = 'pending'
		RETURNING id, scan_id, payload, COALESCE(payload_ref, '') AS payload_ref, format, close_missing, force, attempts
	)
	SELECT (SELECT id FROM candidate), c.id, c.scan_id, c.payload, c.payload_ref, c.format, c.close_missing, c.force, c.attempts
	FROM (SELECT 1) one LEFT JOIN claimed c ON true`

// ClaimJob atomically grabs one claimable job, marks it processing, and
// returns it: first a stale job of a crashed worker, else the fairest pending
// one (fairClaimSQL): the org with the fewest jobs processing, then its oldest
// job whose project has nothing processing. So one tenant's burst can't
// starve another's single upload and at most one job per project runs at a
// time. Returns (nil, nil) when nothing is claimable.
func (r *Repository) ClaimJob(ctx context.Context, staleAfter time.Duration) (*Job, error) {
	if j, err := scanJob(r.db.QueryRow(ctx, staleClaimSQL, staleAfter.Seconds())); err != nil || j != nil {
		return j, err
	}
	for attempt := 0; ; attempt++ {
		// Every job column is NULL when nothing was claimed.
		var picked, id, scanID, ref, format *string
		var j Job
		var closeMissing, force *bool
		var attempts *int
		err := r.db.QueryRow(ctx, fairClaimSQL, orgLookahead).
			Scan(&picked, &id, &scanID, &j.Payload, &ref, &format, &closeMissing, &force, &attempts)
		lost := err == nil && picked != nil && id == nil
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
			lost, err = true, nil // two jobs of one project; the other claimer won
		}
		switch {
		case err != nil:
			return nil, fmt.Errorf("claim job: %w", err)
		case lost && attempt < maxClaimRetries:
			continue
		case id == nil:
			return nil, nil // empty, or still losing races: the next poll retries
		}
		j.ID, j.ScanID, j.PayloadRef, j.Format, j.CloseMissing, j.Force, j.Attempts = *id, *scanID, *ref, *format, *closeMissing, *force, *attempts
		return &j, nil
	}
}

// scanJob reads one claimed job row; (nil, nil) when there was none.
func scanJob(row pgx.Row) (*Job, error) {
	var j Job
	err := row.Scan(&j.ID, &j.ScanID, &j.Payload, &j.PayloadRef, &j.Format, &j.CloseMissing, &j.Force, &j.Attempts)
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
