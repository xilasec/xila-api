package finding

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xilasec/xila-api/internal/domain"
)

// Risk acceptance errors.
var (
	ErrAcceptanceNotFound = errors.New("risk acceptance not found")
	// ErrRiskAcceptanceRequired: risk_accepted is never set directly — only an
	// approved risk acceptance puts a finding there.
	ErrRiskAcceptanceRequired = errors.New("risk_accepted is set by approving a risk acceptance, not directly")
	// ErrAcceptanceState: the acceptance's state doesn't allow the operation
	// (e.g. approving one that isn't requested).
	ErrAcceptanceState = errors.New("not allowed in the risk acceptance's current state")
	// ErrAcceptanceSelfDecision: four-eyes — the requester can't approve or
	// reject their own request.
	ErrAcceptanceSelfDecision = errors.New("a risk acceptance must be decided by someone other than its requester")
	// ErrAcceptanceLapsed: approving an acceptance whose expiry has passed.
	ErrAcceptanceLapsed = errors.New("the risk acceptance's expiry has already passed")
	// ErrNotMember: the finding isn't (any more) in the acceptance.
	ErrNotMember = errors.New("the finding is not in this risk acceptance")
)

// AcceptanceState is where a risk acceptance is in its lifecycle:
// requested → approved → expired / revoked, or requested → rejected / revoked.
type AcceptanceState string

const (
	AcceptanceRequested AcceptanceState = "requested"
	AcceptanceApproved  AcceptanceState = "approved"
	AcceptanceExpired   AcceptanceState = "expired"
	AcceptanceRevoked   AcceptanceState = "revoked"
	AcceptanceRejected  AcceptanceState = "rejected"
)

// Valid reports whether s is a known state.
func (s AcceptanceState) Valid() bool {
	switch s {
	case AcceptanceRequested, AcceptanceApproved, AcceptanceExpired, AcceptanceRevoked, AcceptanceRejected:
		return true
	}
	return false
}

// Live reports whether the acceptance still holds findings (requested or approved).
func (s AcceptanceState) Live() bool { return s == AcceptanceRequested || s == AcceptanceApproved }

// AcceptanceRef is the live risk acceptance covering a finding, as carried on
// the finding itself.
type AcceptanceRef struct {
	ID            string          `json:"id"`
	Title         string          `json:"title"`
	State         AcceptanceState `json:"state"`
	Justification string          `json:"justification"`
	Approver      string          `json:"approver"`
	ExpiresAt     *time.Time      `json:"expires_at"`
}

// acceptanceRefSQL reads a finding's live acceptance (alias-free over findings).
const acceptanceRefSQL = `(SELECT jsonb_build_object('id', ra.id, 'title', ra.title, 'state', ra.state,
		'justification', ra.justification, 'approver', ra.approver, 'expires_at', ra.expires_at)
	FROM risk_acceptance_findings ram JOIN risk_acceptances ra ON ra.id = ram.acceptance_id
	WHERE ram.finding_id = findings.id AND ram.removed_at IS NULL)`

// Exception returns the reason, decider and expiry behind a finding's triage
// state: the approved covering acceptance's for risk_accepted, the finding's
// own exception fields for false_positive / wont_fix.
func (f Finding) Exception() (reason, by string, expires *time.Time) {
	if f.Status == domain.FindingRiskAccepted {
		if a := f.RiskAcceptance; a != nil && a.State == AcceptanceApproved {
			return a.Justification, a.Approver, a.ExpiresAt
		}
		return "", "", nil
	}
	return f.ExceptionReason, f.ExceptionBy, f.ExceptionExpiresAt
}

// RiskAcceptance is a decision to live with a set of a project's findings for
// a while: who asked, who approved, why, and until when.
type RiskAcceptance struct {
	ID            string          `json:"id"`
	ProjectID     string          `json:"project_id"`
	ProjectName   string          `json:"project_name"`
	Title         string          `json:"title"`
	Justification string          `json:"justification"`
	OwnerID       *string         `json:"owner_id"`
	OwnerEmail    *string         `json:"owner_email"`
	ExpiresAt     *time.Time      `json:"expires_at"`
	State         AcceptanceState `json:"state"`
	// SourceKey marks an acceptance the platform keeps for a triage rule or an
	// import; nil for requested-by-a-person.
	SourceKey    *string    `json:"source_key"`
	RequestedBy  *string    `json:"requested_by"`
	Requester    string     `json:"requester"`
	RequestedAt  time.Time  `json:"requested_at"`
	ApprovedBy   *string    `json:"approved_by"`
	Approver     string     `json:"approver"`
	ApprovedAt   *time.Time `json:"approved_at"`
	ApprovalNote string     `json:"approval_note"`
	ClosedBy     *string    `json:"closed_by"`
	Closer       string     `json:"closer"`
	ClosedAt     *time.Time `json:"closed_at"`
	CloseNote    string     `json:"close_note"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	// FindingCount is how many findings it covers — or covered when it ended.
	FindingCount int `json:"finding_count"`
	// CanApprove / CanRevoke are whether the caller may (set by the handler).
	CanApprove bool `json:"can_approve"`
	CanRevoke  bool `json:"can_revoke"`
}

const acceptanceColumns = `ra.id, ra.project_id, p.name, ra.title, ra.justification, ra.owner_id,
	(SELECT email FROM users WHERE users.id = ra.owner_id), ra.expires_at, ra.state, ra.source_key,
	ra.requested_by, ra.requester, ra.requested_at, ra.approved_by, ra.approver, ra.approved_at, ra.approval_note,
	ra.closed_by, ra.closer, ra.closed_at, ra.close_note, ra.created_at, ra.updated_at,
	(SELECT count(*)::int FROM risk_acceptance_findings m
	 WHERE m.acceptance_id = ra.id AND (m.removed_at IS NULL OR m.removed_at = ra.closed_at))`

const acceptanceFrom = ` FROM risk_acceptances ra JOIN projects p ON p.id = ra.project_id`

func scanAcceptance(row pgx.Row) (RiskAcceptance, error) {
	var a RiskAcceptance
	err := row.Scan(&a.ID, &a.ProjectID, &a.ProjectName, &a.Title, &a.Justification, &a.OwnerID,
		&a.OwnerEmail, &a.ExpiresAt, &a.State, &a.SourceKey,
		&a.RequestedBy, &a.Requester, &a.RequestedAt, &a.ApprovedBy, &a.Approver, &a.ApprovedAt, &a.ApprovalNote,
		&a.ClosedBy, &a.Closer, &a.ClosedAt, &a.CloseNote, &a.CreatedAt, &a.UpdatedAt, &a.FindingCount)
	return a, err
}

func collectAcceptances(rows pgx.Rows) ([]RiskAcceptance, error) {
	defer rows.Close()
	out := []RiskAcceptance{}
	for rows.Next() {
		a, err := scanAcceptance(rows)
		if err != nil {
			return nil, fmt.Errorf("scan risk acceptance: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// An actor is a user id or a system label (a triage rule, a scanner, system).
// userOf resolves it to the user (NULL for a system actor); labelOf to what the
// record shows: the user's email at the time, else the label itself.
func userOf(n int) string { return fmt.Sprintf(`(SELECT id FROM users WHERE id::text = $%d)`, n) }
func labelOf(n int) string {
	return fmt.Sprintf(`COALESCE((SELECT email FROM users WHERE id::text = $%d), $%d)`, n, n)
}

// AcceptanceInput is a new risk acceptance request.
type AcceptanceInput struct {
	ProjectID     string
	Title         string
	Justification string
	OwnerID       *string // nil = the requester (when a user)
	ExpiresAt     *time.Time
	FindingIDs    []string
}

// CreateAcceptance records a requested acceptance of in.FindingIDs. Findings
// that aren't live (open / confirmed) findings of the project, or that are
// already in a live acceptance, are skipped and returned. Nothing about the
// findings changes until the acceptance is approved.
func (r *Repository) CreateAcceptance(ctx context.Context, in AcceptanceInput, requester string) (RiskAcceptance, []string, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return RiskAcceptance{}, nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	a, skipped, err := createAcceptanceTx(ctx, tx, in, requester)
	if err != nil {
		return RiskAcceptance{}, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RiskAcceptance{}, nil, fmt.Errorf("commit: %w", err)
	}
	return a, skipped, nil
}

func createAcceptanceTx(ctx context.Context, tx pgx.Tx, in AcceptanceInput, requester string) (RiskAcceptance, []string, error) {
	var id string
	if err := tx.QueryRow(ctx, `
		INSERT INTO risk_acceptances (project_id, title, justification, owner_id, expires_at,
		                              requested_by, requester)
		VALUES ($1, $2, $3, COALESCE($4::uuid, `+userOf(5)+`), $6, `+userOf(5)+`, `+labelOf(5)+`)
		RETURNING id`,
		in.ProjectID, in.Title, in.Justification, in.OwnerID, requester, in.ExpiresAt).Scan(&id); err != nil {
		return RiskAcceptance{}, nil, fmt.Errorf("create risk acceptance: %w", err)
	}
	added, err := addMembersTx(ctx, tx, id, in.ProjectID, in.FindingIDs, requester)
	if err != nil {
		return RiskAcceptance{}, nil, err
	}
	a, err := readAcceptance(ctx, tx, "", id, false)
	if err != nil {
		return RiskAcceptance{}, nil, err
	}
	return a, missing(in.FindingIDs, added), nil
}

// missing returns the ids in want that aren't in got, in want's order.
func missing(want, got []string) []string {
	have := make(map[string]bool, len(got))
	for _, id := range got {
		have[id] = true
	}
	out := []string{}
	for _, id := range want {
		if !have[id] {
			out = append(out, id)
			have[id] = true
		}
	}
	return out
}

// addMembersTx adds the live (open / confirmed) findings of projectID among
// ids that aren't in a live acceptance yet; returns those added.
func addMembersTx(ctx context.Context, tx pgx.Tx, acceptanceID, projectID string, ids []string, actor string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `
		INSERT INTO risk_acceptance_findings (acceptance_id, finding_id, added_by)
		SELECT $1, f.id, `+labelOf(4)+` FROM findings f
		WHERE f.id = ANY($2) AND f.project_id = $3 AND f.status IN ('open', 'confirmed')
		ON CONFLICT (finding_id) WHERE removed_at IS NULL DO NOTHING
		RETURNING finding_id`, acceptanceID, ids, projectID, actor)
	if err != nil {
		return nil, fmt.Errorf("add acceptance findings: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// leaveAcceptances takes the findings in ids out of whatever live acceptance
// holds them (a status set by hand overrides the acceptance). The ledger rows
// are stamped, not deleted.
func leaveAcceptances(ctx context.Context, tx pgx.Tx, ids []string, actor, reason string) error {
	if _, err := tx.Exec(ctx, `
		UPDATE risk_acceptance_findings SET removed_at = now(), removed_by = `+labelOf(2)+`, reason = $3
		WHERE finding_id = ANY($1) AND removed_at IS NULL`, ids, actor, reason); err != nil {
		return fmt.Errorf("leave risk acceptances: %w", err)
	}
	return nil
}

// acceptMembersTx puts an approved acceptance's live members (all, or only
// those in ids) that are still open / confirmed into risk_accepted. The SLA
// trigger pauses their clocks. tx's actor must already be set.
func acceptMembersTx(ctx context.Context, tx pgx.Tx, acceptanceID string, ids []string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		UPDATE findings
		SET status = 'risk_accepted', resolved_at = now(),
		    exception_reason = '', exception_by = '', exception_expires_at = NULL, updated_at = now()
		WHERE id IN (SELECT finding_id FROM risk_acceptance_findings
		             WHERE acceptance_id = $1 AND removed_at IS NULL
		               AND ($2::uuid[] IS NULL OR finding_id = ANY($2)))
		  AND status IN ('open', 'confirmed')
		RETURNING id`, acceptanceID, ids)
	if err != nil {
		return nil, fmt.Errorf("accept findings: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// reopenTx reopens the risk_accepted findings among ids: their acceptance no
// longer covers them. The SLA trigger resumes their clocks. tx's actor must
// already be set.
func reopenTx(ctx context.Context, tx pgx.Tx, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		UPDATE findings SET status = 'open', resolved_at = NULL, updated_at = now()
		WHERE id = ANY($1) AND status = 'risk_accepted'`, ids); err != nil {
		return fmt.Errorf("reopen findings: %w", err)
	}
	return nil
}

// readAcceptance reads one acceptance (of projectID, when given), optionally
// locking its row until tx ends.
func readAcceptance(ctx context.Context, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, projectID, id string, lock bool) (RiskAcceptance, error) {
	sql := `SELECT ` + acceptanceColumns + acceptanceFrom + ` WHERE ra.id = $1 AND ($2 = '' OR ra.project_id::text = $2)`
	if lock {
		sql += ` FOR UPDATE OF ra`
	}
	a, err := scanAcceptance(q.QueryRow(ctx, sql, id, projectID))
	if errors.Is(err, pgx.ErrNoRows) {
		return RiskAcceptance{}, ErrAcceptanceNotFound
	}
	if err != nil {
		return RiskAcceptance{}, fmt.Errorf("get risk acceptance: %w", err)
	}
	return a, nil
}

// Acceptance returns one acceptance of a project ("" = any project).
func (r *Repository) Acceptance(ctx context.Context, projectID, id string) (RiskAcceptance, error) {
	return readAcceptance(ctx, r.db, projectID, id, false)
}

// AcceptanceFilter narrows ListAcceptances.
type AcceptanceFilter struct {
	ProjectID string
	// ProjectIDs, when non-nil, restricts to these projects (the caller's
	// visible scope); an empty non-nil slice matches nothing.
	ProjectIDs []string
	State      AcceptanceState // "" = any
	Limit      int             // 0 = no limit
	Offset     int
}

// ListAcceptances returns acceptances, newest first.
func (r *Repository) ListAcceptances(ctx context.Context, f AcceptanceFilter) ([]RiskAcceptance, error) {
	var where []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.ProjectID != "" {
		add("ra.project_id = $%d", f.ProjectID)
	}
	if f.ProjectIDs != nil {
		add("ra.project_id = ANY($%d)", f.ProjectIDs)
	}
	if f.State != "" {
		add("ra.state = $%d", string(f.State))
	}
	q := `SELECT ` + acceptanceColumns + acceptanceFrom
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY ra.created_at DESC, ra.id"
	if f.Limit > 0 {
		args = append(args, f.Limit, f.Offset)
		q += fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	}
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list risk acceptances: %w", err)
	}
	return collectAcceptances(rows)
}

// AcceptancePatch edits a requested acceptance; nil fields stay.
type AcceptancePatch struct {
	Title         *string
	Justification *string
	OwnerID       *string
	// SetExpiry applies ExpiresAt (nil = never expires).
	SetExpiry bool
	ExpiresAt *time.Time
}

// UpdateAcceptance edits a requested acceptance. Once approved, what was
// approved is fixed: revoke it and request a new one instead.
func (r *Repository) UpdateAcceptance(ctx context.Context, projectID, id string, p AcceptancePatch) (RiskAcceptance, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return RiskAcceptance{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	a, err := readAcceptance(ctx, tx, projectID, id, true)
	if err != nil {
		return RiskAcceptance{}, err
	}
	if a.State != AcceptanceRequested {
		return RiskAcceptance{}, fmt.Errorf("%w: only a requested acceptance can be edited (it is %s)", ErrAcceptanceState, a.State)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE risk_acceptances
		SET title = COALESCE($2, title), justification = COALESCE($3, justification),
		    owner_id = COALESCE($4::uuid, owner_id),
		    expires_at = CASE WHEN $5 THEN $6 ELSE expires_at END, updated_at = now()
		WHERE id = $1`, id, p.Title, p.Justification, p.OwnerID, p.SetExpiry, p.ExpiresAt); err != nil {
		return RiskAcceptance{}, fmt.Errorf("update risk acceptance: %w", err)
	}
	if a, err = readAcceptance(ctx, tx, "", id, false); err != nil {
		return RiskAcceptance{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RiskAcceptance{}, fmt.Errorf("commit: %w", err)
	}
	return a, nil
}

// DeleteAcceptance withdraws a request that never took effect (requested or
// rejected). Anything that was ever approved stays, for the record.
func (r *Repository) DeleteAcceptance(ctx context.Context, projectID, id string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	a, err := readAcceptance(ctx, tx, projectID, id, true)
	if err != nil {
		return err
	}
	if a.State != AcceptanceRequested && a.State != AcceptanceRejected {
		return fmt.Errorf("%w: only a requested or rejected acceptance can be deleted (it is %s); revoke it instead", ErrAcceptanceState, a.State)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM risk_acceptances WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete risk acceptance: %w", err)
	}
	return tx.Commit(ctx)
}

// ApproveAcceptance approves a requested acceptance: its open / confirmed
// findings become risk_accepted (pausing their SLA clocks), attributed to the
// approver. With fourEyes, the requester can't approve their own request.
// Returns the approved acceptance and the findings it moved.
func (r *Repository) ApproveAcceptance(ctx context.Context, projectID, id, approver, note string, fourEyes bool) (RiskAcceptance, []string, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return RiskAcceptance{}, nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	a, err := readAcceptance(ctx, tx, projectID, id, true)
	if err != nil {
		return RiskAcceptance{}, nil, err
	}
	if a.State != AcceptanceRequested {
		return RiskAcceptance{}, nil, fmt.Errorf("%w: only a requested acceptance can be approved (it is %s)", ErrAcceptanceState, a.State)
	}
	if fourEyes && a.requestedBy(approver) {
		return RiskAcceptance{}, nil, ErrAcceptanceSelfDecision
	}
	if a.ExpiresAt != nil && !a.ExpiresAt.After(time.Now()) {
		return RiskAcceptance{}, nil, ErrAcceptanceLapsed
	}
	if _, err := tx.Exec(ctx, `
		UPDATE risk_acceptances
		SET state = 'approved', approved_by = `+userOf(2)+`, approver = `+labelOf(2)+`,
		    approved_at = now(), approval_note = $3, updated_at = now()
		WHERE id = $1`, id, approver, note); err != nil {
		return RiskAcceptance{}, nil, fmt.Errorf("approve risk acceptance: %w", err)
	}
	if err := withActor(ctx, tx, approver, "risk acceptance approved: "+a.Title); err != nil {
		return RiskAcceptance{}, nil, err
	}
	moved, err := acceptMembersTx(ctx, tx, id, nil)
	if err != nil {
		return RiskAcceptance{}, nil, err
	}
	if a, err = readAcceptance(ctx, tx, "", id, false); err != nil {
		return RiskAcceptance{}, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RiskAcceptance{}, nil, fmt.Errorf("commit: %w", err)
	}
	return a, moved, nil
}

// closeTx ends a live acceptance in state: every live member leaves (the
// ledger records why) and, if it was approved, its risk_accepted findings
// reopen. tx's row lock on a must be held.
func closeTx(ctx context.Context, tx pgx.Tx, a RiskAcceptance, state AcceptanceState, actor, note string) error {
	if _, err := tx.Exec(ctx, `
		UPDATE risk_acceptances
		SET state = $2, closed_by = `+userOf(3)+`, closer = `+labelOf(3)+`, closed_at = now(),
		    close_note = $4, updated_at = now()
		WHERE id = $1`, a.ID, string(state), actor, note); err != nil {
		return fmt.Errorf("close risk acceptance: %w", err)
	}
	rows, err := tx.Query(ctx, `
		UPDATE risk_acceptance_findings SET removed_at = now(), removed_by = `+labelOf(2)+`, reason = $3
		WHERE acceptance_id = $1 AND removed_at IS NULL
		RETURNING finding_id`, a.ID, actor, "acceptance "+string(state))
	if err != nil {
		return fmt.Errorf("close acceptance findings: %w", err)
	}
	left, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return fmt.Errorf("close acceptance findings: %w", err)
	}
	if a.State != AcceptanceApproved {
		return nil
	}
	if err := withActor(ctx, tx, actor, "risk acceptance "+string(state)+": "+a.Title); err != nil {
		return err
	}
	return reopenTx(ctx, tx, left)
}

// requestedBy reports whether actor (a user id, or a system actor such as an
// importing scanner) made the request. requested_by is set only for a user;
// any other requester is identified by its label.
func (a RiskAcceptance) requestedBy(actor string) bool {
	if a.RequestedBy != nil {
		return *a.RequestedBy == actor
	}
	return a.Requester != "" && a.Requester == actor
}

// RejectAcceptance turns a request down; its findings never changed. With
// fourEyes, the requester can't reject their own request (they delete it).
func (r *Repository) RejectAcceptance(ctx context.Context, projectID, id, actor, note string, fourEyes bool) (RiskAcceptance, error) {
	return r.end(ctx, projectID, id, actor, note, AcceptanceRejected, func(a RiskAcceptance) error {
		if a.State != AcceptanceRequested {
			return fmt.Errorf("%w: only a requested acceptance can be rejected (it is %s)", ErrAcceptanceState, a.State)
		}
		if fourEyes && a.requestedBy(actor) {
			return ErrAcceptanceSelfDecision
		}
		return nil
	})
}

// RevokeAcceptance ends a live acceptance early: its findings reopen.
func (r *Repository) RevokeAcceptance(ctx context.Context, projectID, id, actor, note string) (RiskAcceptance, error) {
	return r.end(ctx, projectID, id, actor, note, AcceptanceRevoked, func(a RiskAcceptance) error {
		if !a.State.Live() {
			return fmt.Errorf("%w: it already ended (%s)", ErrAcceptanceState, a.State)
		}
		return nil
	})
}

func (r *Repository) end(ctx context.Context, projectID, id, actor, note string, state AcceptanceState, check func(RiskAcceptance) error) (RiskAcceptance, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return RiskAcceptance{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	a, err := readAcceptance(ctx, tx, projectID, id, true)
	if err != nil {
		return RiskAcceptance{}, err
	}
	if err := check(a); err != nil {
		return RiskAcceptance{}, err
	}
	if err := closeTx(ctx, tx, a, state, actor, note); err != nil {
		return RiskAcceptance{}, err
	}
	if a, err = readAcceptance(ctx, tx, "", id, false); err != nil {
		return RiskAcceptance{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RiskAcceptance{}, fmt.Errorf("commit: %w", err)
	}
	return a, nil
}

// AddAcceptanceFindings adds findings to a live acceptance (skipped: not live
// findings of the project, or already in a live acceptance). Added to an
// approved one, they become risk_accepted at once — the caller checks the
// actor may approve.
func (r *Repository) AddAcceptanceFindings(ctx context.Context, projectID, id string, ids []string, actor string) (RiskAcceptance, []string, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return RiskAcceptance{}, nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	a, err := readAcceptance(ctx, tx, projectID, id, true)
	if err != nil {
		return RiskAcceptance{}, nil, err
	}
	if !a.State.Live() {
		return RiskAcceptance{}, nil, fmt.Errorf("%w: it ended (%s)", ErrAcceptanceState, a.State)
	}
	added, err := addMembersTx(ctx, tx, id, a.ProjectID, ids, actor)
	if err != nil {
		return RiskAcceptance{}, nil, err
	}
	if a.State == AcceptanceApproved && len(added) > 0 {
		if err := withActor(ctx, tx, actor, "added to risk acceptance: "+a.Title); err != nil {
			return RiskAcceptance{}, nil, err
		}
		if _, err := acceptMembersTx(ctx, tx, id, added); err != nil {
			return RiskAcceptance{}, nil, err
		}
	}
	if a, err = readAcceptance(ctx, tx, "", id, false); err != nil {
		return RiskAcceptance{}, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RiskAcceptance{}, nil, fmt.Errorf("commit: %w", err)
	}
	return a, missing(ids, added), nil
}

// RemoveAcceptanceFinding takes one finding out of a live acceptance; the
// ledger keeps the row with reason. If the acceptance was approved, the
// finding reopens.
func (r *Repository) RemoveAcceptanceFinding(ctx context.Context, projectID, id, findingID, actor, reason string) (RiskAcceptance, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return RiskAcceptance{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	a, err := readAcceptance(ctx, tx, projectID, id, true)
	if err != nil {
		return RiskAcceptance{}, err
	}
	if !a.State.Live() {
		return RiskAcceptance{}, fmt.Errorf("%w: it ended (%s)", ErrAcceptanceState, a.State)
	}
	if reason == "" {
		reason = "removed from the acceptance"
	}
	tag, err := tx.Exec(ctx, `
		UPDATE risk_acceptance_findings SET removed_at = now(), removed_by = `+labelOf(3)+`, reason = $4
		WHERE acceptance_id = $1 AND finding_id = $2 AND removed_at IS NULL`, id, findingID, actor, reason)
	if err != nil {
		return RiskAcceptance{}, fmt.Errorf("remove acceptance finding: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return RiskAcceptance{}, ErrNotMember
	}
	if a.State == AcceptanceApproved {
		if err := withActor(ctx, tx, actor, "removed from risk acceptance: "+a.Title); err != nil {
			return RiskAcceptance{}, err
		}
		if err := reopenTx(ctx, tx, []string{findingID}); err != nil {
			return RiskAcceptance{}, err
		}
	}
	if a, err = readAcceptance(ctx, tx, "", id, false); err != nil {
		return RiskAcceptance{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return RiskAcceptance{}, fmt.Errorf("commit: %w", err)
	}
	return a, nil
}

// LedgerEntry is one stay of a finding in a risk acceptance: when it joined,
// when and why it left (nil while it's still in).
type LedgerEntry struct {
	ID              string               `json:"id"`
	AcceptanceID    string               `json:"acceptance_id"`
	AcceptanceTitle string               `json:"acceptance_title"`
	AcceptanceState AcceptanceState      `json:"acceptance_state"`
	FindingID       string               `json:"finding_id"`
	FindingTitle    string               `json:"finding_title"`
	FindingSeverity domain.Severity      `json:"finding_severity"`
	FindingStatus   domain.FindingStatus `json:"finding_status"`
	AddedAt         time.Time            `json:"added_at"`
	AddedBy         string               `json:"added_by"`
	RemovedAt       *time.Time           `json:"removed_at"`
	RemovedBy       string               `json:"removed_by"`
	Reason          string               `json:"reason"`
}

func (r *Repository) ledger(ctx context.Context, where string, arg string) ([]LedgerEntry, error) {
	rows, err := r.db.Query(ctx, `
		SELECT m.id, m.acceptance_id, ra.title, ra.state, m.finding_id, f.title, f.severity, f.status,
		       m.added_at, m.added_by, m.removed_at, m.removed_by, m.reason
		FROM risk_acceptance_findings m
		JOIN risk_acceptances ra ON ra.id = m.acceptance_id
		JOIN findings f ON f.id = m.finding_id
		WHERE `+where+`
		ORDER BY m.added_at DESC, m.id`, arg)
	if err != nil {
		return nil, fmt.Errorf("risk acceptance ledger: %w", err)
	}
	defer rows.Close()
	out := []LedgerEntry{}
	for rows.Next() {
		var e LedgerEntry
		if err := rows.Scan(&e.ID, &e.AcceptanceID, &e.AcceptanceTitle, &e.AcceptanceState, &e.FindingID,
			&e.FindingTitle, &e.FindingSeverity, &e.FindingStatus,
			&e.AddedAt, &e.AddedBy, &e.RemovedAt, &e.RemovedBy, &e.Reason); err != nil {
			return nil, fmt.Errorf("scan ledger entry: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// AcceptanceMembers returns every finding that was ever in an acceptance,
// latest first — live members have no RemovedAt.
func (r *Repository) AcceptanceMembers(ctx context.Context, acceptanceID string) ([]LedgerEntry, error) {
	return r.ledger(ctx, `m.acceptance_id = $1`, acceptanceID)
}

// FindingLedger returns a finding's risk-acceptance history, latest first.
func (r *Repository) FindingLedger(ctx context.Context, findingID string) ([]LedgerEntry, error) {
	return r.ledger(ctx, `m.finding_id = $1`, findingID)
}

// RequestAcceptances creates one requested acceptance per project for the
// live findings among ids (the "Accept risk" triage action). Findings already
// in a live acceptance, or not open / confirmed, are returned in busy. An
// empty title is derived from the findings.
func (r *Repository) RequestAcceptances(ctx context.Context, ids []string, in AcceptanceInput, requester string) (created []RiskAcceptance, busy []string, err error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	rows, err := tx.Query(ctx, `SELECT id, project_id, title FROM findings WHERE id = ANY($1) ORDER BY project_id, priority DESC, id`, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("findings to accept: %w", err)
	}
	type row struct{ id, project, title string }
	found, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
		var x row
		return x, r.Scan(&x.id, &x.project, &x.title)
	})
	if err != nil {
		return nil, nil, fmt.Errorf("findings to accept: %w", err)
	}
	var order []string
	byProject := map[string][]row{}
	for _, f := range found {
		if _, ok := byProject[f.project]; !ok {
			order = append(order, f.project)
		}
		byProject[f.project] = append(byProject[f.project], f)
	}
	for _, pid := range order {
		group := byProject[pid]
		req := in
		req.ProjectID = pid
		req.FindingIDs = make([]string, len(group))
		for i, f := range group {
			req.FindingIDs[i] = f.id
		}
		if req.Title == "" {
			req.Title = "Accept risk: " + group[0].title
			if len(group) > 1 {
				req.Title = fmt.Sprintf("Accept risk: %d findings", len(group))
			}
		}
		a, skipped, err := createAcceptanceTx(ctx, tx, req, requester)
		if err != nil {
			return nil, nil, err
		}
		busy = append(busy, skipped...)
		if a.FindingCount == 0 {
			// Nothing could join: don't leave an empty request behind.
			if _, err := tx.Exec(ctx, `DELETE FROM risk_acceptances WHERE id = $1`, a.ID); err != nil {
				return nil, nil, fmt.Errorf("drop empty request: %w", err)
			}
			continue
		}
		created = append(created, a)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit: %w", err)
	}
	if created == nil {
		created = []RiskAcceptance{}
	}
	return created, busy, nil
}

// SystemAcceptance is an acceptance the platform keeps on behalf of a
// recurring source: a triage rule, or the verdicts an import carries.
type SystemAcceptance struct {
	ProjectID string
	// SourceKey finds the source's live acceptance in the project; new matches
	// join it rather than opening another.
	SourceKey     string
	Title         string
	Justification string
	Actor         string // recorded as requester (and approver)
	ExpiresAt     *time.Time
	// Approve approves a newly created acceptance at once (a triage rule was
	// already approved as policy); otherwise it waits as a request.
	Approve bool
}

// AcceptBySystem adds findings to the source's live acceptance, creating it
// if needed. When that acceptance is approved, the findings become
// risk_accepted at once. Returns the ids that changed status.
func (r *Repository) AcceptBySystem(ctx context.Context, s SystemAcceptance, ids []string) ([]string, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	state := AcceptanceRequested
	if s.Approve {
		state = AcceptanceApproved
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO risk_acceptances (project_id, source_key, title, justification, expires_at, state,
		                              requester, approver, approved_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, CASE WHEN $6 = 'approved' THEN $7 ELSE '' END,
		        CASE WHEN $6 = 'approved' THEN now() END)
		ON CONFLICT (project_id, source_key) WHERE source_key IS NOT NULL AND state IN ('requested', 'approved')
		DO NOTHING`,
		s.ProjectID, s.SourceKey, s.Title, s.Justification, s.ExpiresAt, string(state), s.Actor); err != nil {
		return nil, fmt.Errorf("system risk acceptance: %w", err)
	}
	var id string
	if err := tx.QueryRow(ctx, `
		SELECT id FROM risk_acceptances
		WHERE project_id = $1 AND source_key = $2 AND state IN ('requested', 'approved')
		FOR UPDATE`, s.ProjectID, s.SourceKey).Scan(&id); err != nil {
		return nil, fmt.Errorf("system risk acceptance: %w", err)
	}
	a, err := readAcceptance(ctx, tx, "", id, false)
	if err != nil {
		return nil, err
	}
	added, err := addMembersTx(ctx, tx, id, s.ProjectID, ids, s.Actor)
	if err != nil {
		return nil, err
	}
	var moved []string
	if a.State == AcceptanceApproved && len(added) > 0 {
		if err := withActor(ctx, tx, s.Actor, a.Justification); err != nil {
			return nil, err
		}
		if moved, err = acceptMembersTx(ctx, tx, id, added); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return moved, nil
}

// SystemActor attributes what the expiry sweep does.
const SystemActor = "system"

// ExpireAcceptances ends every live acceptance whose expiry has passed: an
// approved one's findings reopen and their SLA clocks resume (the findings_sla
// trigger adds the paused time to the deadline); a request that was never
// approved just lapses. Returns the acceptances it expired.
func (r *Repository) ExpireAcceptances(ctx context.Context) ([]RiskAcceptance, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id FROM risk_acceptances
		WHERE state IN ('requested', 'approved') AND expires_at <= now()
		ORDER BY expires_at, id`)
	if err != nil {
		return nil, fmt.Errorf("lapsed risk acceptances: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("lapsed risk acceptances: %w", err)
	}
	out := []RiskAcceptance{}
	for _, id := range ids {
		a, err := r.end(ctx, "", id, SystemActor, "expired", AcceptanceExpired, func(a RiskAcceptance) error {
			if !a.State.Live() || a.ExpiresAt == nil || a.ExpiresAt.After(time.Now()) {
				return ErrAcceptanceState // changed since the scan: someone else got there
			}
			return nil
		})
		if errors.Is(err, ErrAcceptanceState) || errors.Is(err, ErrAcceptanceNotFound) {
			continue
		}
		if err != nil {
			return out, err
		}
		out = append(out, a)
	}
	return out, nil
}

// WarnExpiringAcceptances returns the approved acceptances lapsing within
// `within` that haven't been warned about for their current expiry yet, and
// marks them warned — each expiry is announced once.
func (r *Repository) WarnExpiringAcceptances(ctx context.Context, within time.Duration) ([]RiskAcceptance, error) {
	rows, err := r.db.Query(ctx, `
		UPDATE risk_acceptances SET expiry_warned_at = expires_at
		WHERE state = 'approved' AND expires_at > now()
		  AND expires_at <= now() + make_interval(secs => $1)
		  AND expiry_warned_at IS DISTINCT FROM expires_at
		RETURNING id`, within.Seconds())
	if err != nil {
		return nil, fmt.Errorf("expiring risk acceptances: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("expiring risk acceptances: %w", err)
	}
	rows, err = r.db.Query(ctx, `SELECT `+acceptanceColumns+acceptanceFrom+` WHERE ra.id = ANY($1) ORDER BY ra.expires_at, ra.id`, ids)
	if err != nil {
		return nil, fmt.Errorf("expiring risk acceptances: %w", err)
	}
	return collectAcceptances(rows)
}
