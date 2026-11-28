package finding

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/domain"
)

// Assessment errors.
var (
	ErrAssessmentNotFound = errors.New("assessment not found")
	// ErrAssessmentPending: the finding already has a request awaiting review.
	ErrAssessmentPending = errors.New("an assessment of this finding is already pending approval")
	// ErrAssessmentDecided: the request was already approved or rejected.
	ErrAssessmentDecided = errors.New("assessment already decided")
	// ErrSelfApproval: four-eyes — the requester can't decide their own request.
	ErrSelfApproval = errors.New("an assessment must be decided by someone other than its requester")
)

// AssessmentState is where a manual assessment is in its review.
type AssessmentState string

const (
	AssessmentPending  AssessmentState = "pending"
	AssessmentApproved AssessmentState = "approved"
	AssessmentRejected AssessmentState = "rejected"
)

// Valid reports whether s is a known state.
func (s AssessmentState) Valid() bool {
	return s == AssessmentPending || s == AssessmentApproved || s == AssessmentRejected
}

// Assessment is an analyst's status and/or severity change on a finding,
// held for a second person's approval (ASSESSMENT_REQUIRES_APPROVAL).
type Assessment struct {
	ID          string                `json:"id"`
	FindingID   string                `json:"finding_id"`
	ProjectID   string                `json:"project_id"`
	RequestedBy *string               `json:"requested_by"`
	Requester   string                `json:"requester"`
	Status      *domain.FindingStatus `json:"status"`
	Severity    *domain.Severity      `json:"severity"`
	Reason      string                `json:"reason"`
	ExpiresAt   *time.Time            `json:"expires_at"`
	// VexJustification / VexResponse: the structured analysis requested
	// alongside a status of false_positive or wont_fix (M13 13.2), applied
	// verbatim on approval.
	VexJustification domain.VexJustification `json:"vex_justification"`
	VexResponse      []domain.VexResponse    `json:"vex_response"`
	State            AssessmentState         `json:"state"`
	DecidedBy        *string                 `json:"decided_by"`
	Decider          string                  `json:"decider"`
	DecidedAt        *time.Time              `json:"decided_at"`
	DecisionNote     string                  `json:"decision_note"`
	CreatedAt        time.Time               `json:"created_at"`

	// Context for a reviewer: what the finding is and looks like now.
	FindingTitle    string               `json:"finding_title"`
	CurrentStatus   domain.FindingStatus `json:"current_status"`
	CurrentSeverity domain.Severity      `json:"current_severity"`
	ProjectName     string               `json:"project_name"`

	// CanDecide is whether the caller may approve or reject it (set by the handler).
	CanDecide bool `json:"can_decide"`
}

// summary describes the requested change for the finding history.
func (a Assessment) summary() string {
	var parts []string
	if a.Status != nil {
		parts = append(parts, "status → "+string(*a.Status))
	}
	if a.Severity != nil {
		parts = append(parts, "severity → "+string(*a.Severity))
	}
	return strings.Join(parts, ", ")
}

const assessmentColumns = `a.id, a.finding_id, a.project_id, a.requested_by, a.requester, a.status, a.severity,
	a.reason, a.expires_at, a.vex_justification, a.vex_response, a.state, a.decided_by, a.decider, a.decided_at, a.decision_note, a.created_at,
	f.title, f.status, f.severity, p.name`

const assessmentFrom = ` FROM finding_assessments a
	JOIN findings f ON f.id = a.finding_id
	JOIN projects p ON p.id = a.project_id`

func scanAssessment(row pgx.Row) (Assessment, error) {
	var a Assessment
	err := row.Scan(&a.ID, &a.FindingID, &a.ProjectID, &a.RequestedBy, &a.Requester, &a.Status, &a.Severity,
		&a.Reason, &a.ExpiresAt, &a.VexJustification, &a.VexResponse, &a.State, &a.DecidedBy, &a.Decider, &a.DecidedAt, &a.DecisionNote, &a.CreatedAt,
		&a.FindingTitle, &a.CurrentStatus, &a.CurrentSeverity, &a.ProjectName)
	return a, err
}

func collectAssessments(rows pgx.Rows) ([]Assessment, error) {
	defer rows.Close()
	out := []Assessment{}
	for rows.Next() {
		a, err := scanAssessment(rows)
		if err != nil {
			return nil, fmt.Errorf("scan assessment: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// recordAssessment writes an assessment's step into the finding history:
// what was asked (from), where it stands (to), who did it and why.
func recordAssessment(ctx context.Context, tx pgx.Tx, a Assessment, actor, note string) error {
	if _, err := tx.Exec(ctx, `
		INSERT INTO finding_events (finding_id, project_id, kind, from_value, to_value, actor, note)
		VALUES ($1, $2, 'assessment', $3, $4, $5, $6)`,
		a.FindingID, a.ProjectID, a.summary(), string(a.State), actor, note); err != nil {
		return fmt.Errorf("record assessment: %w", err)
	}
	return nil
}

// RequestAssessments records c's status / severity part as a pending
// assessment of every finding in ids, requested by requester. Findings that
// already have one pending are skipped and returned in busy (unknown ids are
// silently absent — the caller resolved them). Assignee changes are never
// part of an assessment.
func (r *Repository) RequestAssessments(ctx context.Context, ids []string, c Change, requester string) (created []Assessment, busy []string, err error) {
	if c.Status == nil && c.Severity == nil {
		return nil, nil, errors.New("an assessment needs a status or severity")
	}
	if c.Status != nil && *c.Status == domain.FindingRiskAccepted {
		return nil, nil, ErrRiskAcceptanceRequired
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	justification := domain.VexJustification("")
	var response []domain.VexResponse
	if c.Status != nil && isExceptionStatus(*c.Status) {
		justification, response = c.VexJustification, c.VexResponse
	}
	rows, err := tx.Query(ctx, `
		INSERT INTO finding_assessments (finding_id, project_id, requested_by, requester, status, severity, reason, expires_at, vex_justification, vex_response)
		SELECT f.id, f.project_id, NULLIF($2, '')::uuid,
		       COALESCE((SELECT email FROM users WHERE id::text = $2), ''), $3, $4, $5, $6, $7, $8
		FROM findings f WHERE f.id = ANY($1)
		ON CONFLICT (finding_id) WHERE state = 'pending' DO NOTHING
		RETURNING id`, ids, requester, c.Status, c.Severity, c.Reason, c.ExpiresAt, justification, vexResponseStrings(response))
	if err != nil {
		return nil, nil, fmt.Errorf("request assessments: %w", err)
	}
	var newIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("scan: %w", err)
		}
		newIDs = append(newIDs, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, fmt.Errorf("request assessments: %w", err)
	}

	rows, err = tx.Query(ctx, `SELECT `+assessmentColumns+assessmentFrom+` WHERE a.id = ANY($1) ORDER BY f.priority DESC, f.id`, newIDs)
	if err != nil {
		return nil, nil, fmt.Errorf("read assessments: %w", err)
	}
	if created, err = collectAssessments(rows); err != nil {
		return nil, nil, err
	}
	got := make(map[string]bool, len(created))
	for _, a := range created {
		got[a.FindingID] = true
		if err := recordAssessment(ctx, tx, a, requester, a.Reason); err != nil {
			return nil, nil, err
		}
	}
	// Whatever existed but wasn't inserted collided with a pending request.
	rows, err = tx.Query(ctx, `SELECT id FROM findings WHERE id = ANY($1) ORDER BY id`, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("existing findings: %w", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, nil, fmt.Errorf("scan: %w", err)
		}
		if !got[id] {
			busy = append(busy, id)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit: %w", err)
	}
	return created, busy, nil
}

// RequestAssessment is RequestAssessments for one finding: ErrNotFound when it
// doesn't exist, ErrAssessmentPending when it already has a pending request.
func (r *Repository) RequestAssessment(ctx context.Context, findingID string, c Change, requester string) (Assessment, error) {
	created, busy, err := r.RequestAssessments(ctx, []string{findingID}, c, requester)
	switch {
	case err != nil:
		return Assessment{}, err
	case len(created) == 1:
		return created[0], nil
	case len(busy) == 1:
		return Assessment{}, ErrAssessmentPending
	}
	return Assessment{}, ErrNotFound
}

// Assessment returns one assessment.
func (r *Repository) Assessment(ctx context.Context, id string) (Assessment, error) {
	a, err := scanAssessment(r.db.QueryRow(ctx, `SELECT `+assessmentColumns+assessmentFrom+` WHERE a.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Assessment{}, ErrAssessmentNotFound
	}
	if err != nil {
		return Assessment{}, fmt.Errorf("get assessment: %w", err)
	}
	return a, nil
}

// AssessmentFilter narrows ListAssessments.
type AssessmentFilter struct {
	State     AssessmentState // empty = any
	FindingID string
	ProjectID string
	// ProjectIDs, when non-nil, restricts to these projects (the caller's
	// visible scope); an empty non-nil slice matches nothing.
	ProjectIDs []string
	// ExcludeRequester drops assessments this user requested (four-eyes).
	ExcludeRequester string
	Limit            int // 0 = no limit
	Offset           int
}

// ListAssessments returns assessments, newest first.
func (r *Repository) ListAssessments(ctx context.Context, f AssessmentFilter) ([]Assessment, error) {
	var where []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, fmt.Sprintf(cond, len(args)))
	}
	if f.State != "" {
		add("a.state = $%d", string(f.State))
	}
	if f.FindingID != "" {
		add("a.finding_id = $%d", f.FindingID)
	} else {
		// The review queue: an archived finding has nothing left to decide.
		where = append(where, strings.TrimSpace(archive.Finding("f")))
	}
	if f.ProjectID != "" {
		add("a.project_id = $%d", f.ProjectID)
	}
	if f.ProjectIDs != nil {
		add("a.project_id = ANY($%d)", f.ProjectIDs)
	}
	if f.ExcludeRequester != "" {
		add("a.requested_by IS DISTINCT FROM $%d", f.ExcludeRequester)
	}
	q := `SELECT ` + assessmentColumns + assessmentFrom
	if len(where) > 0 {
		q += " WHERE " + strings.Join(where, " AND ")
	}
	q += " ORDER BY a.created_at DESC, a.id"
	if f.Limit > 0 {
		args = append(args, f.Limit, f.Offset)
		q += fmt.Sprintf(" LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	}
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list assessments: %w", err)
	}
	return collectAssessments(rows)
}

// lockPending loads assessment id for a decision, holding its row until the
// transaction ends so two reviewers can't both decide it.
func lockPending(ctx context.Context, tx pgx.Tx, id, decider string) (Assessment, error) {
	if _, err := tx.Exec(ctx, `SELECT 1 FROM finding_assessments WHERE id = $1 FOR UPDATE`, id); err != nil {
		return Assessment{}, fmt.Errorf("lock assessment: %w", err)
	}
	a, err := scanAssessment(tx.QueryRow(ctx, `SELECT `+assessmentColumns+assessmentFrom+` WHERE a.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Assessment{}, ErrAssessmentNotFound
	}
	if err != nil {
		return Assessment{}, fmt.Errorf("get assessment: %w", err)
	}
	if a.State != AssessmentPending {
		return Assessment{}, ErrAssessmentDecided
	}
	if a.RequestedBy != nil && *a.RequestedBy == decider {
		return Assessment{}, ErrSelfApproval
	}
	return a, nil
}

// decide marks a locked pending assessment approved / rejected by decider and
// records the decision in the finding history.
func decide(ctx context.Context, tx pgx.Tx, a *Assessment, state AssessmentState, decider, note string) error {
	err := tx.QueryRow(ctx, `
		UPDATE finding_assessments
		SET state = $2, decided_by = NULLIF($3, '')::uuid,
		    decider = COALESCE((SELECT email FROM users WHERE id::text = $3), ''),
		    decided_at = now(), decision_note = $4
		WHERE id = $1
		RETURNING state, decided_by, decider, decided_at, decision_note`, a.ID, string(state), decider, note).
		Scan(&a.State, &a.DecidedBy, &a.Decider, &a.DecidedAt, &a.DecisionNote)
	if err != nil {
		return fmt.Errorf("decide assessment: %w", err)
	}
	return recordAssessment(ctx, tx, *a, decider, note)
}

// ApproveAssessment applies a pending assessment and marks it approved by
// approver. The change goes through the same writes as a direct one (SetStatus
// for the status: resolved_at, exception fields + audit row; the base-priority
// recompute for severity), attributed in the history to the requester with
// their reason; the approval is recorded after it, attributed to approver.
//
// The requested target state is applied even if the finding changed since the
// request (a rescan reopened it, someone else triaged it): the reviewer
// approves the outcome they see in the request, not a diff against the past.
// (Risk acceptance is never an assessment: it has its own approval.)
//
// The caller regroups duplicates afterwards when the status or severity moved.
func (r *Repository) ApproveAssessment(ctx context.Context, id, approver, note string) (Assessment, Finding, error) {
	return r.approveAssessment(ctx, id, approver, note, nil, nil)
}

// ApproveAssessments is ApproveAssessment over many ids ("approve with
// edits" when justification is non-nil: its own value and response override
// every one of them, meaningful only for a result of false_positive or
// wont_fix — ignored otherwise, same as a direct edit). Each id is applied
// independently; one that fails (already decided, not found, the requester
// deciding their own request) is reported in failed rather than aborting
// the rest.
func (r *Repository) ApproveAssessments(ctx context.Context, ids []string, approver, note string,
	justification *domain.VexJustification, response []domain.VexResponse,
) (approved []Assessment, findings []Finding, failed []BulkFailure, err error) {
	for _, id := range ids {
		a, f, aerr := r.approveAssessment(ctx, id, approver, note, justification, response)
		if aerr != nil {
			failed = append(failed, BulkFailure{ID: id, Error: aerr.Error()})
			continue
		}
		approved = append(approved, a)
		findings = append(findings, f)
	}
	return approved, findings, failed, nil
}

// approveAssessment is ApproveAssessment with an optional vex_justification /
// vex_response override; nil justification applies the assessment's own
// stored values unchanged.
func (r *Repository) approveAssessment(ctx context.Context, id, approver, note string,
	justification *domain.VexJustification, response []domain.VexResponse,
) (Assessment, Finding, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Assessment{}, Finding{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	a, err := lockPending(ctx, tx, id, approver)
	if err != nil {
		return Assessment{}, Finding{}, err
	}

	// The requester is who asked for the change; keep their email if the
	// account is gone (History shows a non-user actor verbatim).
	actor := a.Requester
	if a.RequestedBy != nil {
		actor = *a.RequestedBy
	}
	if err := withActor(ctx, tx, actor, a.Reason); err != nil {
		return Assessment{}, Finding{}, err
	}
	vj, vr := a.VexJustification, a.VexResponse
	if justification != nil {
		vj, vr = *justification, response
	}
	if a.Status != nil {
		if _, err := setStatusTx(ctx, tx, a.FindingID, Triage{
			Status: *a.Status, Reason: a.Reason, Actor: actor, ExpiresAt: a.ExpiresAt,
			VexJustification: vj, VexResponse: vr,
		}); err != nil {
			return Assessment{}, Finding{}, err
		}
		if err := stampStatusDecided(ctx, tx, a.FindingID, time.Now()); err != nil {
			return Assessment{}, Finding{}, err
		}
	}
	if a.Severity != nil {
		if err := applyChange(ctx, tx, []string{a.FindingID}, Change{Severity: a.Severity}, actor); err != nil {
			return Assessment{}, Finding{}, err
		}
	}
	if err := decide(ctx, tx, &a, AssessmentApproved, approver, note); err != nil {
		return Assessment{}, Finding{}, err
	}
	found, err := readFindings(ctx, tx, []string{a.FindingID})
	if err != nil {
		return Assessment{}, Finding{}, err
	}
	if len(found) != 1 {
		return Assessment{}, Finding{}, ErrNotFound
	}
	f := found[0]
	a.CurrentStatus, a.CurrentSeverity = f.Status, f.Severity
	if err := tx.Commit(ctx); err != nil {
		return Assessment{}, Finding{}, fmt.Errorf("commit: %w", err)
	}
	if a.Severity != nil {
		if _, _, err := r.Reprioritize(ctx, PriorityScope{FindingIDs: []string{a.FindingID}}); err != nil {
			return Assessment{}, Finding{}, err
		}
		if f, err = r.Get(ctx, a.FindingID); err != nil {
			return Assessment{}, Finding{}, err
		}
	}
	if a.Status != nil && r.carrier != nil {
		if err := r.carrier.Carry(ctx, f, actor); err != nil {
			return Assessment{}, Finding{}, fmt.Errorf("carry triage: %w", err)
		}
	}
	return a, f, nil
}

// RejectAssessment marks a pending assessment rejected by decider, leaving the
// finding untouched.
func (r *Repository) RejectAssessment(ctx context.Context, id, decider, note string) (Assessment, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Assessment{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	a, err := lockPending(ctx, tx, id, decider)
	if err != nil {
		return Assessment{}, err
	}
	if err := decide(ctx, tx, &a, AssessmentRejected, decider, note); err != nil {
		return Assessment{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Assessment{}, fmt.Errorf("commit: %w", err)
	}
	return a, nil
}

// RejectAssessments is RejectAssessment over many ids; a failure is reported
// in failed rather than aborting the rest.
func (r *Repository) RejectAssessments(ctx context.Context, ids []string, decider, note string) (rejected []Assessment, failed []BulkFailure) {
	for _, id := range ids {
		a, err := r.RejectAssessment(ctx, id, decider, note)
		if err != nil {
			failed = append(failed, BulkFailure{ID: id, Error: err.Error()})
			continue
		}
		rejected = append(rejected, a)
	}
	return rejected, failed
}
