// Package aitriage is opt-in AI-assisted triage: a bring-your-own model
// (AI_TRIAGE_*) proposes a false-positive verdict, an exploitability
// assessment or a fix for one finding. Every request is recorded as a
// proposal; nothing changes until a person accepts it, and accepting applies
// it through the normal finding mutation path.
package aitriage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/domain"
)

// Errors.
var (
	ErrNotFound = errors.New("AI proposal not found")
	// ErrDecided: the proposal is no longer open (accepted, rejected,
	// superseded or invalid).
	ErrDecided = errors.New("this AI proposal is no longer open")
)

// State is where a proposal is.
type State string

const (
	StateProposed   State = "proposed"
	StateAccepted   State = "accepted"
	StateRejected   State = "rejected"
	StateSuperseded State = "superseded" // a newer proposal of the same kind replaced it
	StateInvalid    State = "invalid"    // the model's answer failed validation
)

// Outcomes of accepting a proposal.
const (
	OutcomeApplied             = "applied"
	OutcomeAssessmentRequested = "assessment_requested"
	OutcomeAcceptanceRequested = "risk_acceptance_requested"
	OutcomeCommentAdded        = "comment_added"
)

// Proposal is one recorded AI answer about a finding. Its text fields come
// from the model: untrusted, render them as text only.
type Proposal struct {
	ID               string                `json:"id"`
	FindingID        string                `json:"finding_id"`
	ProjectID        string                `json:"project_id"`
	Kind             Kind                  `json:"kind"`
	Provider         string                `json:"provider"`
	Model            string                `json:"model"`
	PromptHash       string                `json:"prompt_hash"`
	Response         string                `json:"response"`
	Verdict          string                `json:"verdict"`
	Rationale        string                `json:"rationale"`
	Fix              string                `json:"fix"`
	ProposedStatus   *domain.FindingStatus `json:"proposed_status"`
	ProposedSeverity *domain.Severity      `json:"proposed_severity"`
	Confidence       *float64              `json:"confidence"`
	State            State                 `json:"state"`
	InvalidReason    string                `json:"invalid_reason"`
	CreatedBy        *string               `json:"created_by"`
	CreatedByEmail   string                `json:"created_by_email"`
	CreatedAt        time.Time             `json:"created_at"`
	DecidedBy        *string               `json:"decided_by"`
	DecidedByEmail   string                `json:"decided_by_email"`
	DecidedAt        *time.Time            `json:"decided_at"`
	DecisionNote     string                `json:"decision_note"`
	Outcome          string                `json:"outcome"`
	OutcomeRef       *string               `json:"outcome_ref"`
}

// Repository stores proposals.
type Repository struct{ db *pgxpool.Pool }

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

const proposalColumns = `p.id, p.finding_id, p.project_id, p.kind, p.provider, p.model, p.prompt_hash, p.response,
	p.verdict, p.rationale, p.fix, p.proposed_status, p.proposed_severity, p.confidence, p.state, p.invalid_reason,
	p.created_by, COALESCE(cu.email, ''), p.created_at, p.decided_by, COALESCE(du.email, ''), p.decided_at,
	p.decision_note, p.outcome, p.outcome_ref`

const proposalFrom = ` FROM ai_proposals p
	LEFT JOIN users cu ON cu.id = p.created_by
	LEFT JOIN users du ON du.id = p.decided_by`

func scanProposal(row pgx.Row) (Proposal, error) {
	var p Proposal
	err := row.Scan(&p.ID, &p.FindingID, &p.ProjectID, &p.Kind, &p.Provider, &p.Model, &p.PromptHash, &p.Response,
		&p.Verdict, &p.Rationale, &p.Fix, &p.ProposedStatus, &p.ProposedSeverity, &p.Confidence, &p.State, &p.InvalidReason,
		&p.CreatedBy, &p.CreatedByEmail, &p.CreatedAt, &p.DecidedBy, &p.DecidedByEmail, &p.DecidedAt,
		&p.DecisionNote, &p.Outcome, &p.OutcomeRef)
	return p, err
}

// OptedOut reports whether a project keeps its findings away from the model.
func (r *Repository) OptedOut(ctx context.Context, projectID string) (bool, error) {
	var out bool
	if err := r.db.QueryRow(ctx, `SELECT ai_triage_opt_out FROM projects WHERE id = $1`, projectID).Scan(&out); err != nil {
		return false, fmt.Errorf("project opt-out: %w", err)
	}
	return out, nil
}

// Create records a proposal. A valid (proposed) one supersedes the
// finding's earlier open proposals of the same kind.
func (r *Repository) Create(ctx context.Context, p Proposal) (Proposal, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Proposal{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if p.State == StateProposed {
		if _, err := tx.Exec(ctx, `
			UPDATE ai_proposals SET state = 'superseded', decided_at = now()
			WHERE finding_id = $1 AND kind = $2 AND state = 'proposed'`, p.FindingID, p.Kind); err != nil {
			return Proposal{}, fmt.Errorf("supersede proposals: %w", err)
		}
	}
	var id string
	if err := tx.QueryRow(ctx, `
		INSERT INTO ai_proposals (finding_id, project_id, kind, provider, model, prompt_hash, response, verdict,
			rationale, fix, proposed_status, proposed_severity, confidence, state, invalid_reason, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, NULLIF($16, '')::uuid)
		RETURNING id`,
		p.FindingID, p.ProjectID, p.Kind, p.Provider, p.Model, p.PromptHash, p.Response, p.Verdict,
		p.Rationale, p.Fix, p.ProposedStatus, p.ProposedSeverity, p.Confidence, p.State, p.InvalidReason,
		deref(p.CreatedBy)).Scan(&id); err != nil {
		return Proposal{}, fmt.Errorf("record proposal: %w", err)
	}
	out, err := scanProposal(tx.QueryRow(ctx, `SELECT `+proposalColumns+proposalFrom+` WHERE p.id = $1`, id))
	if err != nil {
		return Proposal{}, fmt.Errorf("read proposal: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Proposal{}, fmt.Errorf("commit: %w", err)
	}
	return out, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// Get returns finding findingID's proposal id.
func (r *Repository) Get(ctx context.Context, findingID, id string) (Proposal, error) {
	p, err := scanProposal(r.db.QueryRow(ctx, `SELECT `+proposalColumns+proposalFrom+` WHERE p.id = $1 AND p.finding_id = $2`, id, findingID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Proposal{}, ErrNotFound
	}
	if err != nil {
		return Proposal{}, fmt.Errorf("get proposal: %w", err)
	}
	return p, nil
}

// List returns a finding's proposals, newest first.
func (r *Repository) List(ctx context.Context, findingID string, limit, offset int) ([]Proposal, error) {
	rows, err := r.db.Query(ctx, `SELECT `+proposalColumns+proposalFrom+`
		WHERE p.finding_id = $1 ORDER BY p.created_at DESC, p.id LIMIT $2 OFFSET $3`, findingID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list proposals: %w", err)
	}
	defer rows.Close()
	out := []Proposal{}
	for rows.Next() {
		p, err := scanProposal(rows)
		if err != nil {
			return nil, fmt.Errorf("scan proposal: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// OpenProposal is an open proposal in a cross-project queue, with what a
// reviewer needs to recognise its finding.
type OpenProposal struct {
	Proposal
	FindingTitle    string          `json:"finding_title"`
	FindingSeverity domain.Severity `json:"finding_severity"`
	ProjectName     string          `json:"project_name"`
}

// OpenFilter narrows ListOpen.
type OpenFilter struct {
	// ProjectIDs restricts to these projects (nil = every project; an empty
	// non-nil slice matches nothing).
	ProjectIDs []string
	// Mine keeps the proposals this user asked for or whose finding is
	// assigned to them.
	Mine   string
	Limit  int
	Offset int
}

// ListOpen returns open proposals (state proposed) across projects, newest
// first, skipping archived findings.
func (r *Repository) ListOpen(ctx context.Context, f OpenFilter) ([]OpenProposal, error) {
	q := `SELECT ` + proposalColumns + `, fd.title, fd.severity, pr.name` + proposalFrom + `
		JOIN findings fd ON fd.id = p.finding_id
		JOIN projects pr ON pr.id = p.project_id
		WHERE p.state = 'proposed' AND ` + strings.TrimSpace(archive.Finding("fd"))
	var args []any
	if f.ProjectIDs != nil {
		args = append(args, f.ProjectIDs)
		q += fmt.Sprintf(" AND p.project_id = ANY($%d)", len(args))
	}
	if f.Mine != "" {
		args = append(args, f.Mine)
		q += fmt.Sprintf(" AND (p.created_by = $%d OR fd.assignee_id = $%d)", len(args), len(args))
	}
	args = append(args, f.Limit, f.Offset)
	q += fmt.Sprintf(" ORDER BY p.created_at DESC, p.id LIMIT $%d OFFSET $%d", len(args)-1, len(args))
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list open proposals: %w", err)
	}
	defer rows.Close()
	out := []OpenProposal{}
	for rows.Next() {
		var o OpenProposal
		p := &o.Proposal
		if err := rows.Scan(&p.ID, &p.FindingID, &p.ProjectID, &p.Kind, &p.Provider, &p.Model, &p.PromptHash, &p.Response,
			&p.Verdict, &p.Rationale, &p.Fix, &p.ProposedStatus, &p.ProposedSeverity, &p.Confidence, &p.State, &p.InvalidReason,
			&p.CreatedBy, &p.CreatedByEmail, &p.CreatedAt, &p.DecidedBy, &p.DecidedByEmail, &p.DecidedAt,
			&p.DecisionNote, &p.Outcome, &p.OutcomeRef, &o.FindingTitle, &o.FindingSeverity, &o.ProjectName); err != nil {
			return nil, fmt.Errorf("scan open proposal: %w", err)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// decision is the closing of an open proposal.
type decision struct {
	state      State
	actor      string
	note       string
	outcome    string
	outcomeRef *string
}

// execer is a pool or a transaction.
type execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// decide closes open proposal id with d inside q (the pool, or the
// transaction that applied it). ErrDecided when it is no longer open.
func decide(ctx context.Context, q execer, id string, d decision) error {
	tag, err := q.Exec(ctx, `
		UPDATE ai_proposals
		SET state = $2, decided_by = NULLIF($3, '')::uuid, decided_at = now(), decision_note = $4,
		    outcome = $5, outcome_ref = $6
		WHERE id = $1 AND state = 'proposed'`, id, d.state, d.actor, d.note, d.outcome, d.outcomeRef)
	if err != nil {
		return fmt.Errorf("decide proposal: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDecided
	}
	return nil
}

// decide closes open proposal id with d on the pool.
func (r *Repository) decide(ctx context.Context, id string, d decision) error {
	return decide(ctx, r.db, id, d)
}
