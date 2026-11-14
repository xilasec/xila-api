package cra

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/observability"
)

// Notifier queues events in the outbox (notify.Service).
type Notifier interface {
	Notify(ctx context.Context, e notify.Event)
}

// caseStore is the persistence the service needs (Repository).
type caseStore interface {
	Product(ctx context.Context, projectID string) (Product, error)
	SetProduct(ctx context.Context, projectID string, p Product) error
	Get(ctx context.Context, id string) (Case, error)
	List(ctx context.Context, f CaseFilter) ([]Case, error)
	Events(ctx context.Context, caseID string) ([]Event, error)
	OpenExploited(ctx context.Context, projectID string, now time.Time) ([]Opened, error)
	OpenManual(ctx context.Context, projectID, findingID, actorID, note string, awareAt time.Time) (Opened, error)
	MarkCorrective(ctx context.Context, now time.Time) (int, error)
	MarkMissed(ctx context.Context, now time.Time) ([]Alert, error)
	MarkDueSoon(ctx context.Context, now time.Time, lead time.Duration) ([]Alert, error)
	transition(ctx context.Context, id, actorID string, mutate func(c *Case) (Event, error)) (Case, error)
}

// Service runs Article 14 reporting: it opens cases for actively exploited
// vulnerabilities, keeps their clocks, alerts on deadlines and records each
// submission.
type Service struct {
	repo         caseStore
	notifier     Notifier // optional
	manufacturer Manufacturer
	now          func() time.Time
	features     Features // optional; nil = always on
}

// Features reports runtime feature switches (feature.Store); the CRA work is
// the "cra" feature.
type Features interface {
	Enabled(ctx context.Context, key string) bool
}

// NewService constructs the service; notifier may be nil.
func NewService(repo *Repository, notifier Notifier, m Manufacturer) *Service {
	return &Service{repo: repo, notifier: notifier, manufacturer: m, now: time.Now}
}

// WithFeatures makes the service skip its automatic work while the "cra"
// feature is switched off: no cases open, no deadline alerts. The first sweep
// after it is turned back on opens a case for every vulnerability that became
// actively exploited meanwhile — with its clocks starting then, since Xila
// wasn't tracking awareness while the feature was off.
func (s *Service) WithFeatures(f Features) *Service {
	s.features = f
	return s
}

func (s *Service) off(ctx context.Context) bool {
	return s.features != nil && !s.features.Enabled(ctx, "cra")
}

// SetClock replaces the service's clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// Manufacturer is the configured manufacturer identity.
func (s *Service) Manufacturer() Manufacturer { return s.manufacturer }

// OpenExploited opens a case for every newly actively exploited vulnerability
// of an in-scope project (projectID "" = every project) and alerts
// cra.case_opened for each. It is the hook the KEV enrichment and exploit
// intel passes call after flagging findings, and the sweep's first step.
func (s *Service) OpenExploited(ctx context.Context, projectID string) (int, error) {
	if s.off(ctx) {
		return 0, nil
	}
	opened, err := s.repo.OpenExploited(ctx, projectID, s.now())
	if err != nil {
		return 0, err
	}
	for _, o := range opened {
		s.alertOpened(ctx, o)
	}
	return len(opened), nil
}

func (s *Service) alertOpened(ctx context.Context, o Opened) {
	if s.notifier == nil {
		return
	}
	why := map[string]string{TriggerKEV: "listed in CISA KEV", TriggerWeaponized: "weaponized exploit available",
		TriggerManual: "reported as actively exploited"}[o.Trigger]
	s.notifier.Notify(ctx, notify.Event{
		Type:  notify.EventCRACaseOpened,
		Title: fmt.Sprintf("%s: CRA reporting case opened for actively exploited %s", o.ProjectName, o.VulnID),
		Text: fmt.Sprintf("%s (%s). Early warning to the coordinator CSIRT and ENISA due by %s; vulnerability notification within 72 h.",
			o.Title, why, o.EarlyWarningDueAt.UTC().Format("2006-01-02 15:04 UTC")),
		Severity:  "critical",
		ProjectID: o.ProjectID,
		Fields: map[string]string{"case_id": o.ID, "vulnerability": o.VulnID, "trigger": o.Trigger,
			"early_warning_due_at": o.EarlyWarningDueAt.UTC().Format(time.RFC3339)},
	})
}

// SweepResult reports one sweep.
type SweepResult struct {
	Opened     int `json:"opened"`
	Corrective int `json:"corrective"`
	DueSoon    int `json:"due_soon"`
	Missed     int `json:"missed"`
}

// Sweep opens cases for exploited vulnerabilities, starts final-report
// clocks where a fix became available, and alerts — once per case and
// stage — on deadlines due within DueSoonLead or missed.
func (s *Service) Sweep(ctx context.Context) (SweepResult, error) {
	var res SweepResult
	if s.off(ctx) {
		return res, nil
	}
	var err error
	if res.Opened, err = s.OpenExploited(ctx, ""); err != nil {
		return res, err
	}
	now := s.now()
	if res.Corrective, err = s.repo.MarkCorrective(ctx, now); err != nil {
		return res, err
	}
	missed, err := s.repo.MarkMissed(ctx, now)
	if err != nil {
		return res, err
	}
	soon, err := s.repo.MarkDueSoon(ctx, now, DueSoonLead)
	if err != nil {
		return res, err
	}
	for _, a := range missed {
		s.alertDeadline(ctx, notify.EventCRADeadlineMissed, a)
	}
	for _, a := range soon {
		s.alertDeadline(ctx, notify.EventCRADeadlineDue, a)
	}
	res.Missed, res.DueSoon = len(missed), len(soon)
	return res, nil
}

var stageNames = map[Stage]string{
	StageEarlyWarning: "early warning", StageNotification: "vulnerability notification", StageFinal: "final report",
}

func (s *Service) alertDeadline(ctx context.Context, kind string, a Alert) {
	if s.notifier == nil {
		return
	}
	names := make([]string, len(a.Stages))
	stages := make([]string, len(a.Stages))
	for i, st := range a.Stages {
		names[i], stages[i] = stageNames[st], string(st)
	}
	what, severity := "due within 6 h", "high"
	if kind == notify.EventCRADeadlineMissed {
		what, severity = "deadline missed", "critical"
	}
	s.notifier.Notify(ctx, notify.Event{
		Type:      kind,
		Title:     fmt.Sprintf("%s: CRA %s for %s %s", a.ProjectName, strings.Join(names, " and "), a.VulnID, what),
		Text:      fmt.Sprintf("%s — due %s.", a.Title, a.DueAt.UTC().Format("2006-01-02 15:04 UTC")),
		Severity:  severity,
		ProjectID: a.ProjectID,
		Fields: map[string]string{"case_id": a.CaseID, "vulnerability": a.VulnID, "stages": strings.Join(stages, ","),
			"due_at": a.DueAt.UTC().Format(time.RFC3339)},
	})
}

// RunEvery sweeps on the interval until ctx ends (leader job).
func (s *Service) RunEvery(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		start := time.Now()
		res, err := s.Sweep(ctx)
		observability.RecordJob(ctx, "cra_sweep", start, err)
		switch {
		case errors.Is(err, context.Canceled):
			return
		case err != nil:
			slog.WarnContext(ctx, "cra sweep failed", "error", err)
		case res != SweepResult{}:
			slog.InfoContext(ctx, "cra sweep", "opened", res.Opened, "corrective", res.Corrective,
				"due_soon", res.DueSoon, "missed", res.Missed)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Product reads a project's CRA product declaration.
func (s *Service) Product(ctx context.Context, projectID string) (Product, error) {
	return s.repo.Product(ctx, projectID)
}

// SetProduct validates and stores a project's CRA product declaration; a
// project brought into scope gets its cases for already exploited findings
// at once.
func (s *Service) SetProduct(ctx context.Context, projectID string, p Product) (Product, error) {
	states, err := normalizeMemberStates(p.MemberStates)
	if err != nil {
		return Product{}, err
	}
	p.MemberStates = states
	p.Name, p.Version = strings.TrimSpace(p.Name), strings.TrimSpace(p.Version)
	if len(p.Name) > 200 || len(p.Version) > 100 {
		return Product{}, fmt.Errorf("%w: product name or version too long", ErrInvalid)
	}
	if err := s.repo.SetProduct(ctx, projectID, p); err != nil {
		return Product{}, err
	}
	if p.InScope {
		if _, err := s.OpenExploited(ctx, projectID); err != nil {
			return p, err
		}
	}
	return p, nil
}

// Open opens a case by hand for a finding, aware at awareAt (nil = now).
func (s *Service) Open(ctx context.Context, projectID, findingID, actorID, note string, awareAt *time.Time) (Case, error) {
	now := s.now()
	at := now
	if awareAt != nil {
		if awareAt.After(now) {
			return Case{}, fmt.Errorf("%w: aware_at is in the future", ErrInvalid)
		}
		at = *awareAt
	}
	if note == "" {
		note = "Opened by hand"
	}
	o, err := s.repo.OpenManual(ctx, projectID, findingID, actorID, note, at)
	if err != nil {
		return Case{}, err
	}
	c, err := s.Get(ctx, o.ID)
	if err != nil {
		return Case{}, err
	}
	o.ProjectName = c.ProjectName
	s.alertOpened(ctx, o)
	return c, nil
}

// Get reads a case with its derived deadlines.
func (s *Service) Get(ctx context.Context, id string) (Case, error) {
	c, err := s.repo.Get(ctx, id)
	if err != nil {
		return Case{}, err
	}
	c.derive(s.now())
	return c, nil
}

// List lists cases with their derived deadlines.
func (s *Service) List(ctx context.Context, f CaseFilter) ([]Case, error) {
	cases, err := s.repo.List(ctx, f)
	if err != nil {
		return nil, err
	}
	now := s.now()
	for i := range cases {
		cases[i].derive(now)
	}
	return cases, nil
}

// Events lists a case's history.
func (s *Service) Events(ctx context.Context, id string) ([]Event, error) {
	return s.repo.Events(ctx, id)
}

// Payload builds a stage's submission for the case as it stands now.
func (s *Service) Payload(ctx context.Context, id string, stage Stage) (Payload, error) {
	if !stage.Valid() {
		return Payload{}, fmt.Errorf("%w: stage must be early_warning, notification or final", ErrInvalid)
	}
	c, err := s.repo.Get(ctx, id)
	if err != nil {
		return Payload{}, err
	}
	return BuildPayload(c, stage, s.manufacturer, s.now()), nil
}

// Submit records that the stage was submitted (with the platform's
// reference, if any), storing the payload as sent.
func (s *Service) Submit(ctx context.Context, id, actorID string, stage Stage, reference, note string) (Case, error) {
	now := s.now()
	return s.finish(ctx)(s.repo.transition(ctx, id, actorID, func(c *Case) (Event, error) {
		if err := submit(c, stage, now); err != nil {
			return Event{}, err
		}
		p := BuildPayload(*c, stage, s.manufacturer, now)
		return Event{Stage: stage, Payload: &p, Reference: reference, Note: note}, nil
	}))
}

// Dismiss ends a case without reporting (e.g. not exploitable in this
// product), with a reason.
func (s *Service) Dismiss(ctx context.Context, id, actorID, reason string) (Case, error) {
	now := s.now()
	reason = strings.TrimSpace(reason)
	return s.finish(ctx)(s.repo.transition(ctx, id, actorID, func(c *Case) (Event, error) {
		return Event{Note: reason}, dismiss(c, reason, now)
	}))
}

// Close closes a case whose final report was submitted.
func (s *Service) Close(ctx context.Context, id, actorID, note string) (Case, error) {
	now := s.now()
	return s.finish(ctx)(s.repo.transition(ctx, id, actorID, func(c *Case) (Event, error) {
		return Event{Note: note}, closeCase(c, now)
	}))
}

// Update edits a case's report content.
func (s *Service) Update(ctx context.Context, id, actorID string, e Edit) (Case, error) {
	now := s.now()
	return s.finish(ctx)(s.repo.transition(ctx, id, actorID, func(c *Case) (Event, error) {
		if !c.State.Active() {
			return Event{}, fmt.Errorf("%w: a %s case can't be edited", ErrTransition, c.State)
		}
		if err := e.apply(c, now); err != nil {
			return Event{}, err
		}
		note := "Report details updated"
		if e.CorrectiveAvailableAt != nil {
			note = "Corrective measure available " + c.CorrectiveAvailableAt.Format("2006-01-02 15:04 UTC") +
				"; final report due " + c.FinalReportDueAt.Format("2006-01-02 15:04 UTC")
		}
		return Event{Note: note}, nil
	}))
}

// finish re-reads a transitioned case with its derived deadlines.
func (s *Service) finish(ctx context.Context) func(Case, error) (Case, error) {
	return func(c Case, err error) (Case, error) {
		if err != nil {
			return Case{}, err
		}
		return s.Get(ctx, c.ID)
	}
}

// normalizeMemberStates upper-cases, validates and de-duplicates ISO codes.
func normalizeMemberStates(in []string) ([]string, error) {
	out := []string{}
	for _, s := range in {
		code := strings.ToUpper(strings.TrimSpace(s))
		if !domain.EUMemberState(code) {
			return nil, fmt.Errorf("%w: %q is not an EU Member State code (ISO 3166-1 alpha-2, e.g. DE, FR, GR)", ErrInvalid, s)
		}
		if !slices.Contains(out, code) {
			out = append(out, code)
		}
	}
	return out, nil
}
