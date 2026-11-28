package reportschedule

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/evidence"
	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/report"
	"github.com/xilasec/xila-api/internal/user"
)

// Store is the persistence the service needs (implemented by *Repository).
type Store interface {
	ListByOwner(ctx context.Context, ownerID string) ([]Schedule, error)
	ListAll(ctx context.Context) ([]Schedule, error)
	ListEnabled(ctx context.Context) ([]Schedule, error)
	Get(ctx context.Context, id string) (Schedule, error)
	Create(ctx context.Context, s Schedule) (Schedule, error)
	Update(ctx context.Context, s Schedule) (Schedule, error)
	Delete(ctx context.Context, id string) error
	RecordRun(ctx context.Context, scheduleID, status, errMsg string, recipients int) error
	ListRuns(ctx context.Context, scheduleID string, limit int) ([]Run, error)
}

// Reports renders project and portfolio reports (report.Service).
type Reports interface {
	Project(ctx context.Context, projectID string, opts report.Options) (report.Report, error)
	Portfolio(ctx context.Context, pids []string, opts report.Options) (report.Report, error)
}

// Evidence renders a framework's evidence report for a project
// (evidence.Handler).
type Evidence interface {
	Build(ctx context.Context, projectID, framework string) (evidence.Report, error)
}

// Templates resolves a schedule's chosen report template.
type Templates interface {
	Get(ctx context.Context, id string) (report.Template, error)
}

// Membership answers the owner's RBAC scope at send time (membership.Repository).
type Membership interface {
	AdminStatus(ctx context.Context, userID string) (isAdmin, isOwner bool, err error)
	ProjectIDsForUser(ctx context.Context, userID string) ([]string, error)
}

// Users looks up the owner's account state (user.Repository).
type Users interface {
	GetByID(ctx context.Context, id string) (user.User, error)
}

// Channels resolves a notification channel by id (notify.Repository).
type Channels interface {
	Get(ctx context.Context, id string) (notify.Channel, error)
}

// Mailer delivers the rendered report (notify.Service).
type Mailer interface {
	SendAttachment(ctx context.Context, to []string, subject, body string, att notify.Attachment) error
	SendTo(ctx context.Context, ch notify.Channel, e notify.Event) error
}

// Service renders and delivers scheduled reports.
type Service struct {
	store      Store
	reports    Reports
	evidence   Evidence
	templates  Templates
	membership Membership
	users      Users
	channels   Channels
	mail       Mailer
	publicURL  string
	now        func() time.Time
}

// NewService constructs a Service.
func NewService(store Store, reports Reports, evidence Evidence, templates Templates, membership Membership,
	users Users, channels Channels, mail Mailer, publicURL string) *Service {
	return &Service{
		store: store, reports: reports, evidence: evidence, templates: templates, membership: membership,
		users: users, channels: channels, mail: mail, publicURL: publicURL, now: time.Now,
	}
}

// ValidationError is a rejected schedule (HTTP 400).
type ValidationError struct{ msg string }

func (e ValidationError) Error() string { return e.msg }

func invalid(format string, args ...any) error {
	return ValidationError{msg: fmt.Sprintf(format, args...)}
}

// Input is a schedule as written by the API.
type Input struct {
	Name                string   `json:"name"`
	Kind                Kind     `json:"kind"`
	ProjectID           *string  `json:"project_id"`
	FrameworkKey        string   `json:"framework_key"`
	TemplateID          *string  `json:"template_id"`
	EngagementID        *string  `json:"engagement_id"`
	Cadence             Cadence  `json:"cadence"`
	Hour                int      `json:"hour"`
	Weekday             *int     `json:"weekday"`
	DayOfMonth          *int     `json:"day_of_month"`
	RecipientEmails     []string `json:"recipient_emails"`
	RecipientChannelIDs []string `json:"recipient_channel_ids"`
	Enabled             *bool    `json:"enabled"`
}

// maxRecipients bounds how many addresses/channels one schedule can carry.
const maxRecipients = 50

// Normalize validates in and returns the Schedule it describes (ownerID and
// id are filled by the caller).
func (in Input) Normalize() (Schedule, error) {
	s := Schedule{
		Name: strings.TrimSpace(in.Name), Kind: in.Kind, ProjectID: in.ProjectID,
		FrameworkKey: strings.TrimSpace(in.FrameworkKey), TemplateID: in.TemplateID, EngagementID: in.EngagementID,
		Cadence: in.Cadence, Hour: in.Hour, Weekday: in.Weekday, DayOfMonth: in.DayOfMonth,
		RecipientEmails: in.RecipientEmails, RecipientChannelIDs: in.RecipientChannelIDs, Enabled: true,
	}
	if in.Enabled != nil {
		s.Enabled = *in.Enabled
	}
	if s.Name == "" {
		return Schedule{}, invalid("name is required")
	}
	switch s.Kind {
	case KindProject, KindEvidence:
		if s.ProjectID == nil || *s.ProjectID == "" {
			return Schedule{}, invalid("project_id is required for a %s report", s.Kind)
		}
	case KindPortfolio:
		s.ProjectID = nil
		s.EngagementID = nil
	default:
		return Schedule{}, invalid("kind must be project, portfolio or evidence")
	}
	if s.Kind == KindEvidence {
		if s.FrameworkKey == "" {
			return Schedule{}, invalid("framework_key is required for an evidence report")
		}
		s.TemplateID, s.EngagementID = nil, nil
	} else {
		s.FrameworkKey = ""
	}
	switch s.Cadence {
	case CadenceDaily:
		s.Weekday, s.DayOfMonth = nil, nil
	case CadenceWeekly:
		if s.Weekday == nil || *s.Weekday < 0 || *s.Weekday > 6 {
			return Schedule{}, invalid("weekday (0-6) is required for a weekly cadence")
		}
		s.DayOfMonth = nil
	case CadenceMonthly:
		if s.DayOfMonth == nil || *s.DayOfMonth < 1 || *s.DayOfMonth > 28 {
			return Schedule{}, invalid("day_of_month (1-28) is required for a monthly cadence")
		}
		s.Weekday = nil
	default:
		return Schedule{}, invalid("cadence must be daily, weekly or monthly")
	}
	if s.Hour < 0 || s.Hour > 23 {
		return Schedule{}, invalid("hour must be 0-23 (UTC)")
	}
	if len(s.RecipientEmails) == 0 && len(s.RecipientChannelIDs) == 0 {
		return Schedule{}, invalid("at least one recipient email or channel is required")
	}
	if len(s.RecipientEmails)+len(s.RecipientChannelIDs) > maxRecipients {
		return Schedule{}, invalid("at most %d recipients", maxRecipients)
	}
	emails, err := notify.ParseRecipients(strings.Join(s.RecipientEmails, ","))
	if err != nil && len(s.RecipientEmails) > 0 {
		return Schedule{}, invalid("recipient_emails: %v", err)
	}
	s.RecipientEmails = emails
	return s, nil
}

// Get returns one schedule; the caller checks ownership.
func (s *Service) Get(ctx context.Context, id string) (Schedule, error) { return s.store.Get(ctx, id) }

// List returns ownerID's schedules, or every schedule when admin.
func (s *Service) List(ctx context.Context, ownerID string, admin bool) ([]Schedule, error) {
	if admin {
		return s.store.ListAll(ctx)
	}
	return s.store.ListByOwner(ctx, ownerID)
}

// Create inserts ownerID's schedule.
func (s *Service) Create(ctx context.Context, ownerID string, in Input) (Schedule, error) {
	sch, err := in.Normalize()
	if err != nil {
		return Schedule{}, err
	}
	sch.OwnerID = ownerID
	return s.store.Create(ctx, sch)
}

// Update rewrites id's configuration; the caller checks ownership.
func (s *Service) Update(ctx context.Context, id, ownerID string, in Input) (Schedule, error) {
	sch, err := in.Normalize()
	if err != nil {
		return Schedule{}, err
	}
	sch.ID, sch.OwnerID = id, ownerID
	return s.store.Update(ctx, sch)
}

// Delete removes id. The caller checks ownership.
func (s *Service) Delete(ctx context.Context, id string) error { return s.store.Delete(ctx, id) }

// Runs returns a schedule's run history, newest first.
func (s *Service) Runs(ctx context.Context, scheduleID string) ([]Run, error) {
	return s.store.ListRuns(ctx, scheduleID, 20)
}

// RunResult summarizes one sweep.
type RunResult struct {
	Ran    int `json:"ran"`
	Failed int `json:"failed"`
}

// RunDue renders and delivers every schedule due this tick (its cadence and
// hour match now, and it hasn't already run in this period).
func (s *Service) RunDue(ctx context.Context) (RunResult, error) {
	schedules, err := s.store.ListEnabled(ctx)
	if err != nil {
		return RunResult{}, err
	}
	now := s.now().UTC()
	var res RunResult
	for _, sch := range schedules {
		if !isDue(sch, now) {
			continue
		}
		if err := s.run(ctx, sch); err != nil {
			res.Failed++
		} else {
			res.Ran++
		}
	}
	return res, nil
}

// SendNow renders and delivers id immediately, outside its schedule.
func (s *Service) SendNow(ctx context.Context, id string) error {
	sch, err := s.store.Get(ctx, id)
	if err != nil {
		return err
	}
	return s.run(ctx, sch)
}

// isDue reports whether sch should run at now (UTC): its cadence/hour match,
// and its last run (if any) wasn't in the same period. Pure, so the schedule
// math is unit-tested without a database or a leader job.
func isDue(sch Schedule, now time.Time) bool {
	if !sch.Enabled || now.Hour() != sch.Hour {
		return false
	}
	switch sch.Cadence {
	case CadenceDaily:
	case CadenceWeekly:
		if sch.Weekday == nil || int(now.Weekday()) != *sch.Weekday {
			return false
		}
	case CadenceMonthly:
		if sch.DayOfMonth == nil || now.Day() != *sch.DayOfMonth {
			return false
		}
	default:
		return false
	}
	if sch.LastRunAt == nil {
		return true
	}
	last := sch.LastRunAt.UTC()
	switch sch.Cadence {
	case CadenceDaily:
		return last.Format(time.DateOnly) != now.Format(time.DateOnly)
	case CadenceWeekly:
		ly, lw := last.ISOWeek()
		ny, nw := now.ISOWeek()
		return ly != ny || lw != nw
	case CadenceMonthly:
		return last.Year() != now.Year() || last.Month() != now.Month()
	}
	return false
}

// ErrOwnerUnavailable is recorded (never sent) when the owner is deactivated
// or has lost access to the schedule's project.
var ErrOwnerUnavailable = errors.New("report schedule owner is deactivated or has lost access")

// run resolves the owner's scope, renders the report and delivers it,
// recording the outcome (success or failure, never silently skipped).
func (s *Service) run(ctx context.Context, sch Schedule) error {
	html, name, err := s.render(ctx, sch)
	if err != nil {
		s.record(ctx, sch, err, 0)
		return err
	}
	sent, err := s.deliver(ctx, sch, html, name)
	s.record(ctx, sch, err, sent)
	return err
}

func (s *Service) record(ctx context.Context, sch Schedule, err error, sent int) {
	status, msg := "success", ""
	if err != nil {
		status, msg = "failure", err.Error()
	}
	if rerr := s.store.RecordRun(ctx, sch.ID, status, msg, sent); rerr != nil {
		// A failed history write never blocks delivery (already done).
		_ = rerr
	}
}

// render resolves the owner's scope and builds the report HTML.
func (s *Service) render(ctx context.Context, sch Schedule) (html []byte, name string, err error) {
	owner, err := s.users.GetByID(ctx, sch.OwnerID)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", ErrOwnerUnavailable, err)
	}
	if owner.Disabled() {
		return nil, "", fmt.Errorf("%w: account is deactivated", ErrOwnerUnavailable)
	}
	isAdmin, _, err := s.membership.AdminStatus(ctx, sch.OwnerID)
	if err != nil {
		return nil, "", err
	}
	var pids []string // nil = admin: every project
	if !isAdmin {
		if pids, err = s.membership.ProjectIDsForUser(ctx, sch.OwnerID); err != nil {
			return nil, "", err
		}
		if sch.ProjectID != nil && !slices.Contains(pids, *sch.ProjectID) {
			return nil, "", fmt.Errorf("%w: no access to the project", ErrOwnerUnavailable)
		}
	}

	opts := report.Options{}
	if sch.EngagementID != nil {
		opts.EngagementID = *sch.EngagementID
	}
	if sch.TemplateID != nil {
		tpl, err := s.templates.Get(ctx, *sch.TemplateID)
		if err != nil {
			return nil, "", fmt.Errorf("report template: %w", err)
		}
		opts.Template = tpl
	}

	var buf bytes.Buffer
	switch sch.Kind {
	case KindProject:
		rep, err := s.reports.Project(ctx, *sch.ProjectID, opts)
		if err != nil {
			return nil, "", err
		}
		if err := report.Render(&buf, rep); err != nil {
			return nil, "", err
		}
		name = safeName(rep.Project.Slug)
	case KindPortfolio:
		rep, err := s.reports.Portfolio(ctx, pids, opts)
		if err != nil {
			return nil, "", err
		}
		if err := report.Render(&buf, rep); err != nil {
			return nil, "", err
		}
		name = "portfolio"
	case KindEvidence:
		rep, err := s.evidence.Build(ctx, *sch.ProjectID, sch.FrameworkKey)
		if err != nil {
			return nil, "", err
		}
		if err := evidence.Render(&buf, rep); err != nil {
			return nil, "", err
		}
		name = safeName(sch.FrameworkKey)
	default:
		return nil, "", fmt.Errorf("unknown schedule kind %q", sch.Kind)
	}
	return buf.Bytes(), name, nil
}

// deliver emails the HTML as an attachment to the schedule's addresses and
// sends a link-only notification to its channels. It keeps going after a
// failed recipient, returning the first error (if any) once every recipient
// was tried, and the number it reached.
func (s *Service) deliver(ctx context.Context, sch Schedule, html []byte, name string) (sent int, err error) {
	subject := "Xila scheduled report: " + sch.Name
	if len(sch.RecipientEmails) > 0 {
		att := notify.Attachment{Name: "xila-" + name + "-" + time.Now().UTC().Format(time.DateOnly) + ".html",
			MIME: "text/html", Data: html}
		body := fmt.Sprintf("Attached: %s\n\nGenerated by Xila on %s.", sch.Name, time.Now().UTC().Format(time.DateOnly))
		if serr := s.mail.SendAttachment(ctx, sch.RecipientEmails, subject, body, att); serr != nil {
			err = serr
		} else {
			sent += len(sch.RecipientEmails)
		}
	}
	for _, chID := range sch.RecipientChannelIDs {
		ch, cerr := s.channels.Get(ctx, chID)
		if cerr != nil {
			err = cerr
			continue
		}
		text := fmt.Sprintf("The scheduled report %q is ready.", sch.Name)
		if s.publicURL != "" {
			text += " " + s.reportLink(sch)
		}
		e := notify.Event{Type: notify.EventSummary, Title: subject, Text: text, Timestamp: time.Now()}
		if serr := s.mail.SendTo(ctx, ch, e); serr != nil {
			err = serr
			continue
		}
		sent++
	}
	return sent, err
}

// reportLink is the UI link a channel notification carries (a login-gated
// page, never the HTML itself — only email attaches the document).
func (s *Service) reportLink(sch Schedule) string {
	switch sch.Kind {
	case KindProject:
		return s.publicURL + "/projects/" + *sch.ProjectID + "?tab=report"
	case KindEvidence:
		return s.publicURL + "/projects/" + *sch.ProjectID + "?tab=compliance"
	default:
		return s.publicURL + "/"
	}
}

func safeName(s string) string {
	s = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			return r
		}
		return '-'
	}, s)
	if s == "" {
		return "report"
	}
	return s
}
