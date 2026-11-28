package finding

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ExtensionState is where an extension request is: pending until an owner
// decides it; withdrawn when its acceptance ended first.
type ExtensionState string

// Extension states.
const (
	ExtensionPending   ExtensionState = "pending"
	ExtensionApproved  ExtensionState = "approved"
	ExtensionRejected  ExtensionState = "rejected"
	ExtensionWithdrawn ExtensionState = "withdrawn"
)

// ErrExtensionNotFound: no such extension on that acceptance.
var ErrExtensionNotFound = errors.New("risk acceptance extension not found")

// Extension is a request to push an approved risk acceptance's expiry out.
type Extension struct {
	ID            string         `json:"id"`
	AcceptanceID  string         `json:"acceptance_id"`
	Reason        string         `json:"reason"`
	FromExpiresAt time.Time      `json:"from_expires_at"`
	ToExpiresAt   time.Time      `json:"to_expires_at"`
	State         ExtensionState `json:"state"`
	RequestedBy   *string        `json:"requested_by"`
	Requester     string         `json:"requester"`
	RequestedAt   time.Time      `json:"requested_at"`
	DecidedBy     *string        `json:"decided_by"`
	Decider       string         `json:"decider"`
	DecidedAt     *time.Time     `json:"decided_at"`
	DecisionNote  string         `json:"decision_note"`
}

// requestedBy reports whether actor asked for the extension.
func (e Extension) requestedBy(actor string) bool {
	return e.RequestedBy != nil && *e.RequestedBy == actor
}

const extensionColumns = `id, acceptance_id, reason, from_expires_at, to_expires_at, state,
	requested_by, requester, requested_at, decided_by, decider, decided_at, decision_note`

// pendingExtensionSQL is an acceptance's pending extension as JSON (NULL
// when none), with the keys of Extension.
const pendingExtensionSQL = `(SELECT jsonb_build_object('id', x.id, 'acceptance_id', x.acceptance_id,
	'reason', x.reason, 'from_expires_at', x.from_expires_at, 'to_expires_at', x.to_expires_at, 'state', x.state,
	'requested_by', x.requested_by, 'requester', x.requester, 'requested_at', x.requested_at,
	'decided_by', x.decided_by, 'decider', x.decider, 'decided_at', x.decided_at, 'decision_note', x.decision_note)
	FROM risk_acceptance_extensions x WHERE x.acceptance_id = ra.id AND x.state = 'pending')`

func scanExtension(row pgx.Row) (Extension, error) {
	var e Extension
	err := row.Scan(&e.ID, &e.AcceptanceID, &e.Reason, &e.FromExpiresAt, &e.ToExpiresAt, &e.State,
		&e.RequestedBy, &e.Requester, &e.RequestedAt, &e.DecidedBy, &e.Decider, &e.DecidedAt, &e.DecisionNote)
	return e, err
}

// checkExtension is the rule an extension must meet, both when requested and
// when approved: the acceptance is approved and has an expiry, which hasn't
// passed, and the new one is later than it.
func checkExtension(a RiskAcceptance, to, now time.Time) error {
	switch {
	case a.State != AcceptanceApproved:
		return fmt.Errorf("%w: only an approved acceptance can be extended (it is %s)", ErrAcceptanceState, a.State)
	case a.ExpiresAt == nil:
		return fmt.Errorf("%w: the acceptance never expires", ErrAcceptanceState)
	case !a.ExpiresAt.After(now):
		return ErrAcceptanceLapsed
	case !to.After(*a.ExpiresAt):
		return fmt.Errorf("%w: the new expiry must be later than the current one (%s)", ErrAcceptanceState, a.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

// RequestExtension asks to extend an approved acceptance to `to`, for reason.
// With apply (the caller may decide it, see Handler.mayDecideExtension) it
// takes effect at once and is recorded as approved by the caller; otherwise
// it waits for an owner while the acceptance keeps its current expiry.
func (r *Repository) RequestExtension(ctx context.Context, projectID, id, actor, reason string, to time.Time, apply bool) (RiskAcceptance, Extension, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return RiskAcceptance{}, Extension{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	a, err := readAcceptance(ctx, tx, projectID, id, true)
	if err != nil {
		return RiskAcceptance{}, Extension{}, err
	}
	if err := checkExtension(a, to, time.Now()); err != nil {
		return RiskAcceptance{}, Extension{}, err
	}
	if a.PendingExtension != nil {
		return RiskAcceptance{}, Extension{}, fmt.Errorf("%w: an extension is already waiting for a decision", ErrAcceptanceState)
	}
	state := ExtensionPending
	if apply {
		state = ExtensionApproved
	}
	e, err := scanExtension(tx.QueryRow(ctx, `
		INSERT INTO risk_acceptance_extensions (acceptance_id, reason, from_expires_at, to_expires_at, state,
		    requested_by, requester, decided_by, decider, decided_at)
		VALUES ($1, $2, $3, $4, $5, `+userOf(6)+`, `+labelOf(6)+`,
		    CASE WHEN $7 THEN `+userOf(6)+` END, CASE WHEN $7 THEN `+labelOf(6)+` ELSE '' END,
		    CASE WHEN $7 THEN now() END)
		RETURNING `+extensionColumns, id, reason, *a.ExpiresAt, to, string(state), actor, apply))
	if err != nil {
		return RiskAcceptance{}, Extension{}, fmt.Errorf("request extension: %w", err)
	}
	if apply {
		if err := setExpiryTx(ctx, tx, id, to); err != nil {
			return RiskAcceptance{}, Extension{}, err
		}
	}
	if a, err = readAcceptance(ctx, tx, "", id, false); err != nil {
		return RiskAcceptance{}, Extension{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RiskAcceptance{}, Extension{}, fmt.Errorf("commit: %w", err)
	}
	return a, e, nil
}

// DecideExtension approves or rejects a pending extension. With fourEyes the
// person who asked for it can't decide it. Approving re-checks the rule: an
// acceptance that lapsed or ended meanwhile is not revived.
func (r *Repository) DecideExtension(ctx context.Context, projectID, id, extensionID, actor, note string, approve, fourEyes bool) (RiskAcceptance, Extension, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return RiskAcceptance{}, Extension{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	a, err := readAcceptance(ctx, tx, projectID, id, true)
	if err != nil {
		return RiskAcceptance{}, Extension{}, err
	}
	e, err := scanExtension(tx.QueryRow(ctx, `SELECT `+extensionColumns+`
		FROM risk_acceptance_extensions WHERE id = $1 AND acceptance_id = $2 FOR UPDATE`, extensionID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return RiskAcceptance{}, Extension{}, ErrExtensionNotFound
	}
	if err != nil {
		return RiskAcceptance{}, Extension{}, fmt.Errorf("get extension: %w", err)
	}
	if e.State != ExtensionPending {
		return RiskAcceptance{}, Extension{}, fmt.Errorf("%w: the extension was already decided (%s)", ErrAcceptanceState, e.State)
	}
	if fourEyes && e.requestedBy(actor) {
		return RiskAcceptance{}, Extension{}, ErrAcceptanceSelfDecision
	}
	state := ExtensionRejected
	if approve {
		if err := checkExtension(a, e.ToExpiresAt, time.Now()); err != nil {
			return RiskAcceptance{}, Extension{}, err
		}
		state = ExtensionApproved
		if err := setExpiryTx(ctx, tx, id, e.ToExpiresAt); err != nil {
			return RiskAcceptance{}, Extension{}, err
		}
	}
	if e, err = scanExtension(tx.QueryRow(ctx, `
		UPDATE risk_acceptance_extensions
		SET state = $2, decided_by = `+userOf(3)+`, decider = `+labelOf(3)+`, decided_at = now(), decision_note = $4
		WHERE id = $1 RETURNING `+extensionColumns, extensionID, string(state), actor, note)); err != nil {
		return RiskAcceptance{}, Extension{}, fmt.Errorf("decide extension: %w", err)
	}
	if a, err = readAcceptance(ctx, tx, "", id, false); err != nil {
		return RiskAcceptance{}, Extension{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RiskAcceptance{}, Extension{}, fmt.Errorf("commit: %w", err)
	}
	return a, e, nil
}

// setExpiryTx moves an acceptance's expiry. The expiring warning re-arms by
// itself (WarnExpiringAcceptances compares expiry_warned_at with expires_at).
func setExpiryTx(ctx context.Context, tx pgx.Tx, id string, to time.Time) error {
	if _, err := tx.Exec(ctx, `UPDATE risk_acceptances SET expires_at = $2, updated_at = now() WHERE id = $1`, id, to); err != nil {
		return fmt.Errorf("extend risk acceptance: %w", err)
	}
	return nil
}

// withdrawExtensionsTx withdraws an acceptance's pending extension when the
// acceptance ends (tx holds its row lock).
func withdrawExtensionsTx(ctx context.Context, tx pgx.Tx, id, actor string, state AcceptanceState) error {
	if _, err := tx.Exec(ctx, `
		UPDATE risk_acceptance_extensions
		SET state = 'withdrawn', decided_by = `+userOf(2)+`, decider = `+labelOf(2)+`, decided_at = now(),
		    decision_note = $3
		WHERE acceptance_id = $1 AND state = 'pending'`, id, actor, "acceptance "+string(state)); err != nil {
		return fmt.Errorf("withdraw extensions: %w", err)
	}
	return nil
}

// Extensions lists an acceptance's extensions, oldest first.
func (r *Repository) Extensions(ctx context.Context, acceptanceID string) ([]Extension, error) {
	rows, err := r.db.Query(ctx, `SELECT `+extensionColumns+`
		FROM risk_acceptance_extensions WHERE acceptance_id = $1 ORDER BY requested_at, id`, acceptanceID)
	if err != nil {
		return nil, fmt.Errorf("list extensions: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (Extension, error) { return scanExtension(row) })
}
