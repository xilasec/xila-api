package aitriage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/notify"
)

// Service errors.
var (
	ErrDisabled    = errors.New("AI triage is not enabled")
	ErrOptedOut    = errors.New("this project has opted out of AI triage")
	ErrInvalidKind = errors.New("kind must be false_positive, exploitability or fix")
	// ErrBusy: accepting would request a risk acceptance, but the finding is
	// already in one or isn't open.
	ErrBusy = errors.New("the finding is already in a risk acceptance, or isn't open")
)

// RateLimitError: the project used its AI requests for this hour.
type RateLimitError struct{ RetryAfter time.Duration }

func (e RateLimitError) Error() string {
	return fmt.Sprintf("AI triage rate limit reached for this project; retry in %s", e.RetryAfter.Round(time.Second))
}

// Findings is what the service needs of the finding store: reading a finding
// and the normal mutation paths a person's change goes through.
type Findings interface {
	Get(ctx context.Context, id string) (finding.Finding, error)
	ApplyProposed(ctx context.Context, id string, p finding.Proposed, actor string,
		also func(ctx context.Context, tx pgx.Tx, commentID *string) error) (finding.Finding, error)
	RequestAssessment(ctx context.Context, findingID string, c finding.Change, requester string) (finding.Assessment, error)
	RequestAcceptances(ctx context.Context, ids []string, in finding.AcceptanceInput, requester string) ([]finding.RiskAcceptance, []string, error)
}

// Limiter counts requests per key (ratelimit.Limiter).
type Limiter interface {
	Hit(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error)
}

// Notifier delivers events (risk acceptance requested). Optional.
type Notifier interface {
	Notify(ctx context.Context, e notify.Event)
}

// Options configure the Service.
type Options struct {
	// RequireApproval (ASSESSMENT_REQUIRES_APPROVAL): an accepted status /
	// severity becomes a pending assessment, like a manual change.
	RequireApproval bool
	// RateLimit is the AI requests one project may make per hour.
	RateLimit int
}

// Service asks the model and applies accepted proposals.
type Service struct {
	repo     *Repository
	findings Findings
	provider Provider // nil = disabled
	limiter  Limiter
	notifier Notifier
	opts     Options
}

// NewService constructs a Service; a nil provider means AI triage is off.
func NewService(repo *Repository, findings Findings, provider Provider, limiter Limiter, notifier Notifier, opts Options) *Service {
	if opts.RateLimit < 1 {
		opts.RateLimit = 30
	}
	return &Service{repo: repo, findings: findings, provider: provider, limiter: limiter, notifier: notifier, opts: opts}
}

// Enabled reports whether AI triage is configured.
func (s *Service) Enabled() bool { return s.provider != nil }

// Provider / Model name the configured model ("" when disabled).
func (s *Service) Provider() string {
	if s.provider == nil {
		return ""
	}
	return s.provider.Name()
}

// Model is the configured model.
func (s *Service) Model() string {
	if s.provider == nil {
		return ""
	}
	return s.provider.Model()
}

// OptedOut reports whether a project opted out.
func (s *Service) OptedOut(ctx context.Context, projectID string) (bool, error) {
	return s.repo.OptedOut(ctx, projectID)
}

// Preview is exactly what asking would send, and to whom.
type Preview struct {
	Kind       Kind   `json:"kind"`
	Provider   string `json:"provider"`
	Model      string `json:"model"`
	Prompt     Prompt `json:"prompt"`
	PromptHash string `json:"prompt_hash"`
}

// sendable loads a finding that may be sent to the model.
func (s *Service) sendable(ctx context.Context, findingID string, kind Kind) (finding.Finding, error) {
	if !s.Enabled() {
		return finding.Finding{}, ErrDisabled
	}
	if !kind.Valid() {
		return finding.Finding{}, ErrInvalidKind
	}
	f, err := s.findings.Get(ctx, findingID)
	if err != nil {
		return finding.Finding{}, err
	}
	out, err := s.repo.OptedOut(ctx, f.ProjectID)
	if err != nil {
		return finding.Finding{}, err
	}
	if out {
		return finding.Finding{}, ErrOptedOut
	}
	return f, nil
}

// Preview builds the prompt for kind without sending it.
func (s *Service) Preview(ctx context.Context, findingID string, kind Kind) (Preview, error) {
	f, err := s.sendable(ctx, findingID, kind)
	if err != nil {
		return Preview{}, err
	}
	p := BuildPrompt(f, kind)
	return Preview{Kind: kind, Provider: s.provider.Name(), Model: s.provider.Model(), Prompt: p, PromptHash: p.Hash()}, nil
}

// maxResponse caps the raw answer kept on a proposal.
const maxResponse = 16000

// Ask sends the finding to the model and records its answer as a proposal,
// changing nothing else. An answer that fails validation is recorded as an
// invalid proposal and returned together with an ErrInvalidAnswer error.
func (s *Service) Ask(ctx context.Context, findingID string, kind Kind, actor string) (Proposal, error) {
	f, err := s.sendable(ctx, findingID, kind)
	if err != nil {
		return Proposal{}, err
	}
	ok, wait, err := s.limiter.Hit(ctx, "ai-triage:"+f.ProjectID, s.opts.RateLimit, time.Hour)
	if err != nil {
		return Proposal{}, err
	}
	if !ok {
		return Proposal{}, RateLimitError{RetryAfter: wait}
	}
	prompt := BuildPrompt(f, kind)
	raw, err := s.provider.Complete(ctx, prompt)
	if err != nil {
		return Proposal{}, err
	}
	p := Proposal{
		FindingID: f.ID, ProjectID: f.ProjectID, Kind: kind,
		Provider: s.provider.Name(), Model: s.provider.Model(), PromptHash: prompt.Hash(),
		Response: truncate(raw, maxResponse), State: StateProposed,
	}
	if actor != "" {
		p.CreatedBy = &actor
	}
	ans, perr := ParseAnswer(kind, raw)
	if perr != nil {
		p.State, p.InvalidReason = StateInvalid, strings.TrimPrefix(perr.Error(), ErrInvalidAnswer.Error()+": ")
		rec, err := s.repo.Create(ctx, p)
		if err != nil {
			return Proposal{}, err
		}
		return rec, perr
	}
	p.Verdict, p.Rationale, p.Fix = ans.Verdict, ans.Rationale, ans.Fix
	p.ProposedStatus, p.ProposedSeverity, p.Confidence = ans.ProposedStatus, ans.ProposedSeverity, &ans.Confidence
	return s.repo.Create(ctx, p)
}

// List returns a finding's proposals, newest first.
func (s *Service) List(ctx context.Context, findingID string, limit, offset int) ([]Proposal, error) {
	return s.repo.List(ctx, findingID, limit, offset)
}

// ListOpen returns open proposals across projects (Repository.ListOpen).
func (s *Service) ListOpen(ctx context.Context, f OpenFilter) ([]OpenProposal, error) {
	return s.repo.ListOpen(ctx, f)
}

// AcceptResult is what accepting did: the applied finding, or the pending
// assessment / risk acceptance request it filed.
type AcceptResult struct {
	Proposal       Proposal                `json:"proposal"`
	Finding        *finding.Finding        `json:"finding,omitempty"`
	Assessment     *finding.Assessment     `json:"assessment,omitempty"`
	RiskAcceptance *finding.RiskAcceptance `json:"risk_acceptance,omitempty"`
}

// Pending reports whether accepting filed a request rather than applying.
func (r AcceptResult) Pending() bool { return r.Assessment != nil || r.RiskAcceptance != nil }

// reason is the history note (and exception / risk-acceptance reason) of an
// accepted proposal: it names the proposal and the model.
func reason(p Proposal) string {
	conf := ""
	if p.Confidence != nil {
		conf = fmt.Sprintf(", confidence %.2f", *p.Confidence)
	}
	return fmt.Sprintf("Accepted AI proposal %s (%s from %s model %s%s): %s",
		p.ID, p.Kind, p.Provider, p.Model, conf, truncate(p.Rationale, 1500))
}

// comment is what accepting a proposal that changes nothing records: the
// suggested fix, or the rationale.
func comment(p Proposal) string {
	text := p.Fix
	if text == "" {
		text = p.Rationale
	}
	return fmt.Sprintf("AI %s proposal %s from %s model %s, accepted:\n\n%s", p.Kind, p.ID, p.Provider, p.Model, text)
}

// Accept applies open proposal id of finding findingID as actor, through the
// normal paths: a status / severity like a manual change (attributed to
// actor, the note naming the proposal and model; a pending assessment when
// assessments need approval), risk_accepted as a risk acceptance request,
// and a proposal with nothing to change (a fix) as actor's comment.
func (s *Service) Accept(ctx context.Context, findingID, id, actor, note string) (AcceptResult, error) {
	p, err := s.repo.Get(ctx, findingID, id)
	if err != nil {
		return AcceptResult{}, err
	}
	if p.State != StateProposed {
		return AcceptResult{}, ErrDecided
	}
	var res AcceptResult
	why := reason(p)
	d := decision{state: StateAccepted, actor: actor, note: note}
	ch := finding.Proposed{Severity: p.ProposedSeverity, Note: why}
	if p.ProposedStatus != nil {
		if *p.ProposedStatus == domain.FindingRiskAccepted {
			created, busy, err := s.findings.RequestAcceptances(ctx, []string{findingID},
				finding.AcceptanceInput{Justification: why}, actor)
			switch {
			case err != nil:
				return AcceptResult{}, err
			case len(created) == 1:
				res.RiskAcceptance = &created[0]
				d.outcome, d.outcomeRef = OutcomeAcceptanceRequested, &created[0].ID
				if s.notifier != nil {
					go s.notifier.Notify(context.Background(), finding.AcceptanceEvent(
						notify.EventRiskAcceptanceRequested, "Risk acceptance requested", created[0]))
				}
			case len(busy) == 1:
				return AcceptResult{}, ErrBusy
			default:
				return AcceptResult{}, finding.ErrNotFound
			}
		} else {
			ch.Status = p.ProposedStatus
		}
	}

	record := func(outcome string) func(context.Context, pgx.Tx, *string) error {
		return func(ctx context.Context, tx pgx.Tx, commentID *string) error {
			if d.outcome == "" {
				d.outcome, d.outcomeRef = outcome, commentID
			}
			return decide(ctx, tx, p.ID, d)
		}
	}
	switch {
	case ch.Status == nil && ch.Severity == nil && res.RiskAcceptance == nil:
		ch.Comment = comment(p)
		f, err := s.findings.ApplyProposed(ctx, findingID, ch, actor, record(OutcomeCommentAdded))
		if err != nil {
			return AcceptResult{}, err
		}
		res.Finding = &f
	case ch.Status == nil && ch.Severity == nil:
		if err := s.repo.decide(ctx, p.ID, d); err != nil {
			return AcceptResult{}, err
		}
	case s.opts.RequireApproval:
		a, err := s.findings.RequestAssessment(ctx, findingID,
			finding.Change{Status: ch.Status, Severity: ch.Severity, Reason: why}, actor)
		if err != nil {
			return AcceptResult{}, err
		}
		res.Assessment = &a
		if d.outcome == "" {
			d.outcome, d.outcomeRef = OutcomeAssessmentRequested, &a.ID
		}
		if err := s.repo.decide(ctx, p.ID, d); err != nil {
			return AcceptResult{}, err
		}
	default:
		f, err := s.findings.ApplyProposed(ctx, findingID, ch, actor, record(OutcomeApplied))
		if err != nil {
			return AcceptResult{}, err
		}
		res.Finding = &f
	}
	if res.Proposal, err = s.repo.Get(ctx, findingID, id); err != nil {
		return AcceptResult{}, err
	}
	return res, nil
}

// Reject closes open proposal id as rejected by actor; nothing else changes.
func (s *Service) Reject(ctx context.Context, findingID, id, actor, note string) (Proposal, error) {
	if _, err := s.repo.Get(ctx, findingID, id); err != nil {
		return Proposal{}, err
	}
	if err := s.repo.decide(ctx, id, decision{state: StateRejected, actor: actor, note: note}); err != nil {
		return Proposal{}, err
	}
	return s.repo.Get(ctx, findingID, id)
}
