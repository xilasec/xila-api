package finding

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Duplicate-marking errors (M13 13.15, half): a human overrides automatic
// cross-tool dedup for one pair of findings.
var (
	// ErrSelfDuplicate is returned when a finding is marked a duplicate of
	// itself.
	ErrSelfDuplicate = errors.New("a finding cannot be marked a duplicate of itself")
	// ErrDuplicateScope is returned when the two findings aren't the same
	// project and version.
	ErrDuplicateScope = errors.New("duplicate-of requires the same project and version")
	// ErrDuplicateChain is returned when the requested primary is itself
	// marked a duplicate of something else.
	ErrDuplicateChain = errors.New("the primary is itself marked a duplicate")
	// ErrNotManualDuplicate is returned by UnmarkDuplicateManual when the
	// finding isn't currently a hand-made duplicate.
	ErrNotManualDuplicate = errors.New("finding is not manually marked a duplicate")
)

// MarkDuplicateManual marks finding id as a duplicate of primaryID — a
// person's override of automatic cross-tool dedup, for a pair Deduplicate's
// correlation key can't see (different rule ids, different wording of the
// same real issue). Both findings must be the same project and version, and
// primaryID must not itself be a duplicate (no two-level chains). The flag it
// sets (duplicate_manual) makes every dedup statement skip this row, so a
// later automatic run never rewrites the decision; the finding is otherwise
// excluded from counts, lists and metrics exactly like an automatic
// duplicate.
func (r *Repository) MarkDuplicateManual(ctx context.Context, id, primaryID, actor string) (Finding, error) {
	if id == primaryID {
		return Finding{}, ErrSelfDuplicate
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Finding{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	var projectID, versionID string
	if err := tx.QueryRow(ctx, `SELECT project_id, version_id FROM findings WHERE id = $1 FOR UPDATE`, id).
		Scan(&projectID, &versionID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Finding{}, ErrNotFound
		}
		return Finding{}, fmt.Errorf("lock finding: %w", err)
	}
	var pProjectID, pVersionID string
	var pDuplicateOf *string
	if err := tx.QueryRow(ctx, `SELECT project_id, version_id, duplicate_of FROM findings WHERE id = $1`, primaryID).
		Scan(&pProjectID, &pVersionID, &pDuplicateOf); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Finding{}, ErrNotFound
		}
		return Finding{}, fmt.Errorf("lookup primary: %w", err)
	}
	if pProjectID != projectID || pVersionID != versionID {
		return Finding{}, ErrDuplicateScope
	}
	if pDuplicateOf != nil {
		return Finding{}, ErrDuplicateChain
	}

	if err := withActor(ctx, tx, actor, "marked a duplicate of "+primaryID); err != nil {
		return Finding{}, err
	}
	const q = `UPDATE findings SET duplicate_of = $2, duplicate_manual = true, updated_at = now()
		WHERE id = $1 RETURNING ` + findingColumns
	f, err := scanFinding(tx.QueryRow(ctx, q, id, primaryID))
	if err != nil {
		return Finding{}, fmt.Errorf("mark duplicate: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Finding{}, fmt.Errorf("commit: %w", err)
	}
	return f, nil
}

// UnmarkDuplicateManual clears a hand-made duplicate mark, handing the
// finding back to automatic dedup (its next run groups it like any other
// finding).
func (r *Repository) UnmarkDuplicateManual(ctx context.Context, id, actor string) (Finding, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Finding{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if err := withActor(ctx, tx, actor, "duplicate mark removed"); err != nil {
		return Finding{}, err
	}
	const q = `UPDATE findings SET duplicate_of = NULL, duplicate_manual = false, updated_at = now()
		WHERE id = $1 AND duplicate_manual RETURNING ` + findingColumns
	f, err := scanFinding(tx.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM findings WHERE id = $1)`, id).Scan(&exists); err != nil {
			return Finding{}, fmt.Errorf("check finding: %w", err)
		}
		if !exists {
			return Finding{}, ErrNotFound
		}
		return Finding{}, ErrNotManualDuplicate
	}
	if err != nil {
		return Finding{}, fmt.Errorf("unmark duplicate: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Finding{}, fmt.Errorf("commit: %w", err)
	}
	return f, nil
}
