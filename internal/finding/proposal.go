package finding

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/xilasec/xila-api/internal/domain"
)

// Proposed is a change proposed outside the finding package (an AI
// proposal, internal/aitriage) that a person has accepted.
type Proposed struct {
	Status   *domain.FindingStatus // never risk_accepted: that is a request (RequestAcceptances)
	Severity *domain.Severity
	// Comment, when set, is added as the actor's comment.
	Comment string
	// Note is the history note of the change (and an exception's reason).
	Note string
}

// ApplyProposed applies p to finding id exactly like a direct edit by actor
// (setStatusTx / applyChange under withActor, so the history names actor
// with p.Note), and runs also inside the same transaction — the caller
// records its own decision atomically with the change. commentID is the
// comment p.Comment added (nil without one). Priority is recomputed and the
// project regrouped when the severity or status moved.
func (r *Repository) ApplyProposed(ctx context.Context, id string, p Proposed, actor string,
	also func(ctx context.Context, tx pgx.Tx, commentID *string) error,
) (Finding, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Finding{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if err := withActor(ctx, tx, actor, p.Note); err != nil {
		return Finding{}, err
	}
	var projectID string
	if err := tx.QueryRow(ctx, `SELECT project_id FROM findings WHERE id = $1 FOR UPDATE`, id).Scan(&projectID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Finding{}, ErrNotFound
		}
		return Finding{}, fmt.Errorf("lock finding: %w", err)
	}
	if p.Status != nil {
		if _, err := setStatusTx(ctx, tx, id, Triage{Status: *p.Status, Reason: p.Note, Actor: actor}); err != nil {
			return Finding{}, err
		}
	}
	if p.Severity != nil {
		if err := applyChange(ctx, tx, []string{id}, Change{Severity: p.Severity}, actor); err != nil {
			return Finding{}, err
		}
	}
	var commentID *string
	if p.Comment != "" {
		c, err := addCommentTx(ctx, tx, id, actor, p.Comment)
		if err != nil {
			return Finding{}, err
		}
		commentID = &c.ID
	}
	if also != nil {
		if err := also(ctx, tx, commentID); err != nil {
			return Finding{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Finding{}, fmt.Errorf("commit: %w", err)
	}
	if p.Severity != nil {
		if _, _, err := r.Reprioritize(ctx, PriorityScope{FindingIDs: []string{id}}); err != nil {
			return Finding{}, err
		}
	}
	if p.Severity != nil || p.Status != nil {
		// Severity (and status) elect a cross-tool group's primary.
		if _, err := r.Deduplicate(ctx, projectID); err != nil {
			return Finding{}, err
		}
	}
	return r.Get(ctx, id)
}
