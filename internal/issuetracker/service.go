package issuetracker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/netguard"
	"github.com/xilasec/xila-api/internal/secretbox"
)

// AutoCreateCap bounds how many issues one sync run opens per tracker, so
// switching auto-create on over a large backlog (or lowering the threshold)
// trickles issues in instead of flooding the tracker.
const AutoCreateCap = 50

// SyncActor is recorded as the actor when the tracker changes a finding.
const SyncActor = "issue-tracker"

// ErrNoTracker is returned when creating an issue for a project that has no
// enabled tracker.
var ErrNoTracker = errors.New("project has no enabled issue tracker")

// ValidationError is a rejected tracker config (HTTP 400).
type ValidationError struct{ msg string }

func (e ValidationError) Error() string { return e.msg }

func invalid(format string, args ...any) error {
	return ValidationError{msg: fmt.Sprintf(format, args...)}
}

// Store is the persistence the service needs (implemented by *Repository).
type Store interface {
	GetByProject(ctx context.Context, projectID string) (Tracker, error)
	ListEnabled(ctx context.Context) ([]Tracker, error)
	Put(ctx context.Context, t Tracker, tokenEnc []byte) (Tracker, error)
	Delete(ctx context.Context, projectID string) error
	GetLink(ctx context.Context, findingID string) (Link, error)
	LinkOnce(ctx context.Context, findingID, trackerID string,
		create func(context.Context) (string, string, error)) (Link, bool, error)
	ListSyncItems(ctx context.Context, trackerID string) ([]SyncItem, error)
	SetLinkState(ctx context.Context, linkID string, s State) error
	AutoCreateCandidates(ctx context.Context, projectID string, min domain.Severity, limit int) ([]string, error)
	TrySyncLock(ctx context.Context) (release func(), ok bool, err error)
}

// Findings is the finding access the service needs (implemented by
// *finding.Repository).
type Findings interface {
	Get(ctx context.Context, id string) (finding.Finding, error)
	SetStatus(ctx context.Context, id string, t finding.Triage) (finding.Finding, error)
}

// LinkSyncer reconciles another kind of tracker link (remediation actions'
// tickets) as part of each tracker's sync run, under the same lock and with
// the same client. Failures it counts in res.Errors itself; a returned error
// fails the tracker.
type LinkSyncer interface {
	SyncLinks(ctx context.Context, t Tracker, c Client, res *SyncResult) error
}

// Service manages trackers, creates issues and runs the two-way sync.
type Service struct {
	store     Store
	findings  Findings
	cipher    *secretbox.Cipher
	publicURL string
	hc        *http.Client
	syncers   []LinkSyncer
}

// NewService constructs a Service. cipher may be nil (no INTEGRATION_SECRET_KEY):
// trackers can then not be configured or used. publicURL, when set, is the UI
// origin issues link back to.
func NewService(store Store, findings Findings, cipher *secretbox.Cipher, publicURL string) *Service {
	return &Service{
		store: store, findings: findings, cipher: cipher,
		publicURL: strings.TrimRight(publicURL, "/"),
		hc:        netguard.NewClient(20 * time.Second),
	}
}

// AddLinkSyncer has every sync run reconcile ls's links too.
func (s *Service) AddLinkSyncer(ls LinkSyncer) { s.syncers = append(s.syncers, ls) }

// OpenClient returns the project's enabled tracker and a client for it, for
// filing issues that aren't one finding's (ErrNoTracker when there is none).
func (s *Service) OpenClient(ctx context.Context, projectID string) (Tracker, Client, error) {
	t, err := s.store.GetByProject(ctx, projectID)
	if errors.Is(err, ErrNotFound) || (err == nil && !t.Enabled) {
		return Tracker{}, nil, ErrNoTracker
	}
	if err != nil {
		return Tracker{}, nil, err
	}
	c, err := s.client(t)
	if err != nil {
		return Tracker{}, nil, err
	}
	return t, c, nil
}

// Input is a tracker config as written by PUT. Token is write-only: empty keeps
// the stored one.
type Input struct {
	Kind             Kind            `json:"kind"`
	BaseURL          string          `json:"base_url"`
	Target           string          `json:"target"`
	Token            string          `json:"token"`
	JiraEmail        string          `json:"jira_email"`
	AuthUser         string          `json:"auth_user"`
	IssueType        string          `json:"issue_type"`
	DoneTransition   string          `json:"done_transition"`
	ReopenTransition string          `json:"reopen_transition"`
	MinSeverity      domain.Severity `json:"min_severity"`
	AutoCreate       bool            `json:"auto_create"`
	Labels           []string        `json:"labels"`
	Enabled          *bool           `json:"enabled"`
}

// baseURLExample is the hint shown when a kind with no DefaultBaseURL is
// missing one.
func baseURLExample(k Kind) string {
	switch k {
	case KindAzureDevOps:
		return "https://dev.azure.com/your-org"
	case KindServiceNow:
		return "https://your-instance.service-now.com"
	}
	return "https://your-site.atlassian.net"
}

// Normalize validates the input and applies defaults, returning the tracker
// config it describes (without the token).
func (in Input) Normalize(projectID string) (Tracker, error) {
	kind := Kind(strings.ToLower(strings.TrimSpace(string(in.Kind))))
	defDone, defReopen := kind.DefaultTransitions()
	t := Tracker{
		ProjectID:        projectID,
		Kind:             kind,
		BaseURL:          strings.TrimRight(strings.TrimSpace(in.BaseURL), "/"),
		Target:           strings.Trim(strings.TrimSpace(in.Target), "/"),
		MinSeverity:      in.MinSeverity,
		AutoCreate:       in.AutoCreate,
		Enabled:          in.Enabled == nil || *in.Enabled,
		IssueType:        cmpOr(in.IssueType, "Bug"),
		DoneTransition:   cmpOr(in.DoneTransition, defDone),
		ReopenTransition: cmpOr(in.ReopenTransition, defReopen),
		Labels:           []string{},
	}
	if !t.Kind.Valid() {
		return Tracker{}, invalid("kind must be jira, github, gitlab, azure-devops, linear or servicenow")
	}
	if t.BaseURL == "" {
		t.BaseURL = t.Kind.DefaultBaseURL()
	}
	if t.BaseURL == "" {
		return Tracker{}, invalid("base_url is required for %s (e.g. %s)", t.Kind, baseURLExample(t.Kind))
	}
	u, err := url.Parse(t.BaseURL)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return Tracker{}, invalid("base_url must be an http(s) URL")
	}
	if err := netguard.CheckURL(t.BaseURL); err != nil {
		return Tracker{}, invalid("base_url is not an allowed destination: %v", err)
	}
	if t.Target == "" && t.Kind == KindServiceNow {
		t.Target = "incident" // the table every instance ships with
	}
	if t.Target == "" {
		return Tracker{}, invalid("target is required")
	}
	switch t.Kind {
	case KindGitHub:
		if owner, repo, ok := strings.Cut(t.Target, "/"); !ok || owner == "" || repo == "" || strings.Contains(repo, "/") {
			return Tracker{}, invalid("target must be owner/repo for github")
		}
	case KindJira:
		if strings.ContainsAny(t.Target, "/ ") {
			return Tracker{}, invalid("target must be a Jira project key (e.g. SEC)")
		}
		t.JiraEmail = strings.TrimSpace(in.JiraEmail)
	case KindAzureDevOps:
		if strings.Contains(t.Target, "/") {
			return Tracker{}, invalid("target must be the Azure DevOps project name")
		}
	case KindLinear:
		if strings.ContainsAny(t.Target, "/ ") {
			return Tracker{}, invalid("target must be the Linear team id or key")
		}
	case KindServiceNow:
		if strings.ContainsAny(t.Target, "/ ") {
			return Tracker{}, invalid("target must be a ServiceNow table name (e.g. incident)")
		}
		t.AuthUser = strings.TrimSpace(in.AuthUser)
	}
	if t.MinSeverity == "" {
		t.MinSeverity = domain.SeverityHigh
	}
	if !t.MinSeverity.Valid() {
		return Tracker{}, invalid("min_severity must be one of info, low, medium, high, critical")
	}
	for _, l := range in.Labels {
		l = strings.TrimSpace(l)
		if l == "" || slices.Contains(t.Labels, l) {
			continue
		}
		if strings.Contains(l, ",") || len(l) > 50 {
			return Tracker{}, invalid("labels must be at most 50 characters and contain no commas")
		}
		t.Labels = append(t.Labels, l)
	}
	if len(t.Labels) > 20 {
		return Tracker{}, invalid("at most 20 labels")
	}
	return t, nil
}

func cmpOr(v, fallback string) string {
	if v = strings.TrimSpace(v); v != "" {
		return v
	}
	return fallback
}

// Get returns the project's tracker.
func (s *Service) Get(ctx context.Context, projectID string) (Tracker, error) {
	return s.store.GetByProject(ctx, projectID)
}

// Put creates or replaces the project's tracker. A token is required when
// creating; on update an empty one keeps the stored token.
func (s *Service) Put(ctx context.Context, projectID string, in Input) (Tracker, error) {
	if s.cipher == nil {
		return Tracker{}, secretbox.ErrNoKey
	}
	t, err := in.Normalize(projectID)
	if err != nil {
		return Tracker{}, err
	}
	var sealed []byte
	if tok := strings.TrimSpace(in.Token); tok != "" {
		if sealed, err = s.cipher.Seal(tok, projectID); err != nil {
			return Tracker{}, err
		}
	} else if _, err := s.store.GetByProject(ctx, projectID); errors.Is(err, ErrNotFound) {
		return Tracker{}, invalid("token is required")
	} else if err != nil {
		return Tracker{}, err
	}
	return s.store.Put(ctx, t, sealed)
}

// Delete removes the project's tracker and its links (the issues themselves
// stay in the tracker).
func (s *Service) Delete(ctx context.Context, projectID string) error {
	return s.store.Delete(ctx, projectID)
}

// Test verifies the project's stored credentials and target against the tracker.
func (s *Service) Test(ctx context.Context, projectID string) error {
	t, err := s.store.GetByProject(ctx, projectID)
	if err != nil {
		return err
	}
	c, err := s.client(t)
	if err != nil {
		return err
	}
	return c.Check(ctx)
}

func (s *Service) client(t Tracker) (Client, error) {
	token, err := s.cipher.Open(t.tokenEnc, t.ProjectID)
	if err != nil {
		return nil, err
	}
	return NewClient(t, token, s.hc)
}

// Link returns the finding's linked issue.
func (s *Service) Link(ctx context.Context, findingID string) (Link, error) {
	return s.store.GetLink(ctx, findingID)
}

// CreateIssue files an issue for the finding in its project's tracker now,
// regardless of the severity threshold. Idempotent: an existing link is
// returned as is (created=false).
func (s *Service) CreateIssue(ctx context.Context, findingID string) (Link, bool, error) {
	f, err := s.findings.Get(ctx, findingID)
	if err != nil {
		return Link{}, false, err
	}
	if l, err := s.store.GetLink(ctx, findingID); err == nil {
		return l, false, nil
	} else if !errors.Is(err, ErrNoLink) {
		return Link{}, false, err
	}
	t, err := s.store.GetByProject(ctx, f.ProjectID)
	if errors.Is(err, ErrNotFound) || (err == nil && !t.Enabled) {
		return Link{}, false, ErrNoTracker
	}
	if err != nil {
		return Link{}, false, err
	}
	c, err := s.client(t)
	if err != nil {
		return Link{}, false, err
	}
	return s.store.LinkOnce(ctx, findingID, t.ID, func(ctx context.Context) (string, string, error) {
		ref, err := c.Create(ctx, BuildIssue(f, t.Labels, s.publicURL))
		return ref.ExternalID, ref.URL, err
	})
}

// maxTitle keeps titles within every tracker's limit (GitHub 256, Jira 255).
const maxTitle = 250

// maxDescription keeps the body well within Jira's 32k text field.
const maxDescription = 20000

// BuildIssue renders a finding as an issue: "[severity] title", and a plain-text
// body (it reads the same in Markdown and Jira wiki markup) with the facts a
// developer needs to fix it, and a link back to Xila when publicURL is set.
func BuildIssue(f finding.Finding, labels []string, publicURL string) Issue {
	title := "[" + string(f.Severity) + "] " + f.Title
	if r := []rune(title); len(r) > maxTitle {
		title = string(r[:maxTitle-1]) + "…"
	}

	var b strings.Builder
	line := func(k, v string) {
		if v != "" {
			b.WriteString(k + ": " + v + "\n")
		}
	}
	if d := strings.TrimSpace(f.Description); d != "" {
		if r := []rune(d); len(r) > maxDescription {
			d = string(r[:maxDescription]) + "…"
		}
		b.WriteString(d + "\n\n")
	}
	line("Severity", string(f.Severity))
	line("Scanner", f.Scanner)
	line("Rule", f.RuleID)
	if f.PackageName != "" {
		pkg := f.PackageName
		if f.PackageVersion != "" {
			pkg += "@" + f.PackageVersion
		}
		line("Package", pkg)
	}
	line("Fixed version", f.FixedVersion)
	line("CVEs", strings.Join(f.CVE, ", "))
	if f.CWE != nil {
		line("CWE", "CWE-"+strconv.Itoa(*f.CWE))
	}
	if f.CVSS != nil {
		line("CVSS", strconv.FormatFloat(*f.CVSS, 'f', 1, 64))
	}
	if f.EPSS != nil {
		line("EPSS", fmt.Sprintf("%.3f (%.1f%% chance of exploitation in 30 days)", *f.EPSS, *f.EPSS*100))
	}
	if f.KEV {
		line("Known exploited (CISA KEV)", "yes")
	} else {
		line("Known exploited (CISA KEV)", "no")
	}
	if f.FilePath != "" {
		loc := f.FilePath
		if f.Line != nil {
			loc += ":" + strconv.Itoa(*f.Line)
		}
		line("Location", loc)
	}
	line("Reference", f.URL)
	if publicURL != "" {
		b.WriteString("\nView in Xila: " + publicURL + "/findings/" + f.ID + "\n")
	}
	return Issue{Title: title, Body: b.String(), Labels: labels}
}

// SyncResult summarizes one sync run.
type SyncResult struct {
	Skipped          bool `json:"skipped"` // another instance is syncing
	Trackers         int  `json:"trackers"`
	Created          int  `json:"created"`
	ClosedIssues     int  `json:"closed_issues"`
	ReopenedIssues   int  `json:"reopened_issues"`
	ResolvedFindings int  `json:"resolved_findings"`
	ReopenedFindings int  `json:"reopened_findings"`
	// Remediation actions closed / reopened from their ticket.
	ResolvedActions int `json:"resolved_actions"`
	ReopenedActions int `json:"reopened_actions"`
	Errors          int `json:"errors"`
}

// Sync reconciles every enabled tracker's links in both directions, then opens
// issues for findings over the auto-create threshold. A failing tracker or link
// is logged and counted, never aborts the run.
func (s *Service) Sync(ctx context.Context) (SyncResult, error) {
	var res SyncResult
	release, ok, err := s.store.TrySyncLock(ctx)
	if err != nil {
		return res, err
	}
	if !ok {
		res.Skipped = true
		return res, nil
	}
	defer release()

	trackers, err := s.store.ListEnabled(ctx)
	if err != nil {
		return res, err
	}
	for _, t := range trackers {
		res.Trackers++
		if err := s.syncTracker(ctx, t, &res); err != nil {
			res.Errors++
			slog.WarnContext(ctx, "issue tracker sync failed",
				"tracker_id", t.ID, "project_id", t.ProjectID, "kind", t.Kind, "error", err)
		}
	}
	return res, nil
}

func (s *Service) syncTracker(ctx context.Context, t Tracker, res *SyncResult) error {
	c, err := s.client(t)
	if err != nil {
		return err
	}
	items, err := s.store.ListSyncItems(ctx, t.ID)
	if err != nil {
		return err
	}
	for _, it := range items {
		if err := s.reconcile(ctx, c, it, res); err != nil {
			res.Errors++
			slog.WarnContext(ctx, "issue sync failed",
				"tracker_id", t.ID, "finding_id", it.FindingID, "issue", it.ExternalID, "error", err)
		}
	}
	for _, ls := range s.syncers {
		if err := ls.SyncLinks(ctx, t, c, res); err != nil {
			return err
		}
	}
	if !t.AutoCreate {
		return nil
	}
	ids, err := s.store.AutoCreateCandidates(ctx, t.ProjectID, t.MinSeverity, AutoCreateCap)
	if err != nil {
		return err
	}
	for _, id := range ids {
		_, created, err := s.store.LinkOnce(ctx, id, t.ID, func(ctx context.Context) (string, string, error) {
			f, err := s.findings.Get(ctx, id)
			if err != nil {
				return "", "", err
			}
			ref, err := c.Create(ctx, BuildIssue(f, t.Labels, s.publicURL))
			return ref.ExternalID, ref.URL, err
		})
		if err != nil {
			res.Errors++
			slog.WarnContext(ctx, "issue auto-create failed", "tracker_id", t.ID, "finding_id", id, "error", err)
			continue
		}
		if created {
			res.Created++
		}
	}
	return nil
}

// reconcile applies Decide to one link.
func (s *Service) reconcile(ctx context.Context, c Client, it SyncItem, res *SyncResult) error {
	remote, err := c.State(ctx, it.ExternalID)
	if err != nil {
		return err
	}
	d := Decide(it.State, it.Status, remote)
	switch d.Action {
	case ActNone:
		return nil
	case ActRecord:
	case ActCloseIssue:
		if err := c.Close(ctx, it.ExternalID); err != nil {
			return err
		}
		res.ClosedIssues++
	case ActReopenIssue:
		if err := c.Reopen(ctx, it.ExternalID); err != nil {
			return err
		}
		res.ReopenedIssues++
	case ActResolveFinding:
		if _, err := s.findings.SetStatus(ctx, it.FindingID, finding.Triage{Status: domain.FindingRemediated, Actor: SyncActor}); err != nil {
			return err
		}
		res.ResolvedFindings++
	case ActReopenFinding:
		if _, err := s.findings.SetStatus(ctx, it.FindingID, finding.Triage{Status: domain.FindingOpen, Actor: SyncActor}); err != nil {
			return err
		}
		res.ReopenedFindings++
	}
	return s.store.SetLinkState(ctx, it.ID, d.State)
}
