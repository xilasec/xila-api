package issuetracker

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/xilasec/xila-api/internal/finding"
)

// SetWebhookSecret stores the tracker's sealed webhook secret (empty turns
// the receiver off).
func (r *Repository) SetWebhookSecret(ctx context.Context, trackerID string, sealed []byte) error {
	if sealed == nil {
		sealed = []byte{}
	}
	tag, err := r.db.Exec(ctx, `UPDATE issue_trackers SET webhook_secret_enc = $2, updated_at = now() WHERE id = $1`, trackerID, sealed)
	if err != nil {
		return fmt.Errorf("set webhook secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// LinksByExternal returns the tracker's links to one issue (normally one).
func (r *Repository) LinksByExternal(ctx context.Context, trackerID, externalID string) ([]Link, error) {
	rows, err := r.db.Query(ctx, `SELECT `+linkColumns+linkFrom+`
		WHERE fi.tracker_id = $1 AND fi.external_id = $2 ORDER BY fi.created_at`, trackerID, externalID)
	if err != nil {
		return nil, fmt.Errorf("find finding issue: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Link, error) {
		var l Link
		return l, row.Scan(scanLinkInto(&l)...)
	})
}

// WithLinkLock runs fn holding link's sync lock, so the periodic sync and a
// webhook never reconcile one link at once. ran=false: someone else holds it
// (they will reach the same result).
func (r *Repository) WithLinkLock(ctx context.Context, linkID string, fn func(context.Context) error) (ran bool, err error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtext('finding_issue_sync:' || $1::text))`, linkID).Scan(&ran); err != nil {
		return false, fmt.Errorf("lock finding issue: %w", err)
	}
	if !ran {
		return false, nil
	}
	if err := fn(ctx); err != nil {
		return true, err
	}
	return true, tx.Commit(ctx)
}

// GetSyncItem re-reads one link with its finding's status (under the link
// lock, so a decision never acts on a state another reconcile just changed).
func (r *Repository) GetSyncItem(ctx context.Context, linkID string) (SyncItem, error) {
	var it SyncItem
	err := r.db.QueryRow(ctx, `SELECT `+linkColumns+`, f.status`+linkFrom+`
		JOIN findings f ON f.id = fi.finding_id WHERE fi.id = $1`, linkID).Scan(scanLinkInto(&it.Link, &it.Status)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return SyncItem{}, ErrNoLink
	}
	if err != nil {
		return SyncItem{}, fmt.Errorf("get finding issue: %w", err)
	}
	return it, nil
}

// PendingComments returns up to limit comments on the link's finding, posted
// since the issue was linked, that have crossed to the issue in neither
// direction, oldest first.
func (r *Repository) PendingComments(ctx context.Context, link Link, limit int) ([]finding.Comment, error) {
	rows, err := r.db.Query(ctx, `SELECT c.id, c.finding_id, c.author_id, c.author, c.body, c.created_at
		FROM finding_comments c
		WHERE c.finding_id = $1 AND c.created_at >= $2
		  AND NOT EXISTS (SELECT 1 FROM finding_issue_comments x WHERE x.link_id = $3 AND x.comment_id = c.id)
		ORDER BY c.created_at, c.id LIMIT $4`, link.FindingID, link.CreatedAt, link.ID, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending comments: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (finding.Comment, error) {
		var c finding.Comment
		return c, row.Scan(&c.ID, &c.FindingID, &c.AuthorID, &c.Author, &c.Body, &c.CreatedAt)
	})
}

// RecordOutbound notes that comment was posted to the link's issue as remoteID.
func (r *Repository) RecordOutbound(ctx context.Context, linkID, commentID, remoteID string) error {
	if _, err := r.db.Exec(ctx, `INSERT INTO finding_issue_comments (link_id, comment_id, remote_id, direction)
		VALUES ($1, $2, $3, 'outbound') ON CONFLICT DO NOTHING`, linkID, commentID, remoteID); err != nil {
		return fmt.Errorf("record pushed comment: %w", err)
	}
	return nil
}

// AddInbound stores a tracker comment on the link's finding once: a remote id
// already taken in (or posted by Xila) is skipped, created=false.
func (r *Repository) AddInbound(ctx context.Context, link Link, remoteID, author, body string) (created bool, err error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	// Serializes concurrent redeliveries of one comment.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('finding_issue_comment:' || $1::text || ':' || $2))`, link.ID, remoteID); err != nil {
		return false, fmt.Errorf("lock comment: %w", err)
	}
	var seen bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM finding_issue_comments WHERE link_id = $1 AND remote_id = $2)`,
		link.ID, remoteID).Scan(&seen); err != nil {
		return false, fmt.Errorf("check comment: %w", err)
	}
	if seen {
		return false, nil
	}
	c, err := finding.AddExternalCommentTx(ctx, tx, link.FindingID, author, body, SyncActor)
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO finding_issue_comments (link_id, comment_id, remote_id, direction)
		VALUES ($1, $2, $3, 'inbound')`, link.ID, c.ID, remoteID); err != nil {
		return false, fmt.Errorf("record comment: %w", err)
	}
	return true, tx.Commit(ctx)
}
