package remediation

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/fixplan"
	"github.com/xilasec/xila-api/internal/issuetracker"
	"github.com/xilasec/xila-api/internal/pkgmeta"
)

// Store is the persistence the service needs (implemented by *Repository).
type Store interface {
	Get(ctx context.Context, id string) (Action, error)
	Findings(ctx context.Context, actionID string) ([]ActionFinding, error)
	LiveActions(ctx context.Context, projectID string) ([]LiveAction, error)
	Ensure(ctx context.Context, n NewAction, findingIDs []string) (string, bool, error)
	AddFindings(ctx context.Context, actionID string, findingIDs []string) (int, error)
	SetTarget(ctx context.Context, actionID, target string) error
	Refresh(ctx context.Context, projectID string) ([]string, error)
	Update(ctx context.Context, id string, p Patch, actorID string) error
	SetStatusFromTracker(ctx context.Context, id string, s Status) error
	LinkIssueOnce(ctx context.Context, actionID, trackerID string,
		create func(context.Context) (string, string, error)) (IssueLink, bool, error)
	IssueSyncItems(ctx context.Context, trackerID string) ([]IssueSyncItem, error)
	SetIssueState(ctx context.Context, linkID string, s issuetracker.State) error
}

// Candidates loads the live findings to group (implemented by
// *finding.Repository).
type Candidates interface {
	FixCandidates(ctx context.Context, ff finding.FixFilter) ([]finding.FixCandidate, error)
}

// Trackers opens a project's issue tracker (implemented by
// *issuetracker.Service).
type Trackers interface {
	OpenClient(ctx context.Context, projectID string) (issuetracker.Tracker, issuetracker.Client, error)
}

// Service proposes, creates, refreshes and files remediation actions.
type Service struct {
	store      Store
	cands      Candidates
	trackers   Trackers
	autoCreate bool
	publicURL  string
	features   Features // optional; nil = always on
}

// Features reports runtime feature switches (feature.Store); remediation
// tracking is the "remediation" feature.
type Features interface {
	Enabled(ctx context.Context, key string) bool
}

// WithFeatures makes the ingest pass, the sweep and the ticket sync skip while
// the "remediation" feature is switched off. Actions keep their state; the
// first sweep after it is turned back on catches up.
func (s *Service) WithFeatures(f Features) *Service {
	s.features = f
	return s
}

func (s *Service) off(ctx context.Context) bool {
	return s.features != nil && !s.features.Enabled(ctx, "remediation")
}

// NewService constructs a Service. autoCreate (REMEDIATION_AUTO_CREATE) turns
// every proposal into an action as soon as it's found; trackers may be nil
// (no issue filing). publicURL, when set, is the UI origin tickets link to.
func NewService(store Store, cands Candidates, trackers Trackers, autoCreate bool, publicURL string) *Service {
	return &Service{store: store, cands: cands, trackers: trackers, autoCreate: autoCreate,
		publicURL: strings.TrimRight(publicURL, "/")}
}

// groupOpts: actions rebuild images rather than bump their distro packages one
// by one.
var groupOpts = fixplan.Options{BaseImages: true}

func actionKey(project string, kind fixplan.Kind, key string) string {
	return project + "\x00" + string(kind) + "\x00" + key
}

// Proposals returns the changes that would resolve the project's live
// findings not yet in an action (and not just joining a live action's
// change), most risk removed first.
func (s *Service) Proposals(ctx context.Context, projectID string) ([]fixplan.Change, error) {
	cands, err := s.cands.FixCandidates(ctx, finding.FixFilter{ProjectIDs: []string{projectID}, Unactioned: true})
	if err != nil {
		return nil, err
	}
	changes, _ := fixplan.Changes(cands, groupOpts)
	live, err := s.store.LiveActions(ctx, projectID)
	if err != nil {
		return nil, err
	}
	taken := map[string]bool{}
	for _, a := range live {
		taken[actionKey(a.ProjectID, a.Kind, a.Key)] = true
	}
	out := make([]fixplan.Change, 0, len(changes))
	for _, c := range changes {
		if !taken[actionKey(c.ProjectID, c.Kind, c.Key)] {
			out = append(out, c)
		}
	}
	return out, nil
}

// Accept turns a proposed change into an action (or, if one was created
// meanwhile, adds the findings to it). created reports a new action.
func (s *Service) Accept(ctx context.Context, projectID string, kind fixplan.Kind, key, actorID string) (Action, bool, error) {
	cands, err := s.cands.FixCandidates(ctx, finding.FixFilter{ProjectIDs: []string{projectID}, Unactioned: true})
	if err != nil {
		return Action{}, false, err
	}
	changes, _ := fixplan.Changes(cands, groupOpts)
	for _, c := range changes {
		if c.Kind != kind || c.Key != key {
			continue
		}
		var by *string
		if actorID != "" {
			by = &actorID
		}
		id, created, err := s.store.Ensure(ctx, NewAction{ProjectID: projectID, Kind: c.Kind, Key: c.Key,
			Title: c.Title, Target: c.Target, CreatedBy: by}, c.FindingIDs)
		if err != nil {
			return Action{}, false, err
		}
		if _, err := s.store.Refresh(ctx, projectID); err != nil {
			return Action{}, false, err
		}
		a, err := s.store.Get(ctx, id)
		return a, created, err
	}
	return Action{}, false, ErrNoProposal
}

// Update applies a user's patch and returns the refreshed action.
func (s *Service) Update(ctx context.Context, id string, p Patch, actorID string) (Action, error) {
	if err := s.store.Update(ctx, id, p, actorID); err != nil {
		return Action{}, err
	}
	a, err := s.store.Get(ctx, id)
	if err != nil {
		return Action{}, err
	}
	// Owner handed back to the assignees, or reopened: recompute from findings.
	if p.AutoOwner || (p.Status != nil && p.Status.Live()) {
		if _, err := s.store.Refresh(ctx, a.ProjectID); err != nil {
			return Action{}, err
		}
		return s.store.Get(ctx, id)
	}
	return a, nil
}

// SweepResult summarizes a sweep.
type SweepResult struct {
	Proposed int `json:"proposed"` // changes left as proposals
	Created  int `json:"created"`  // actions auto-created
	Joined   int `json:"joined"`   // findings added to existing actions
	Closed   int `json:"closed"`   // actions closed (all findings resolved)
}

// Sweep proposes / joins / auto-creates across every project and refreshes
// every live action.
func (s *Service) Sweep(ctx context.Context) (SweepResult, error) {
	return s.sweep(ctx, "", "")
}

// Name identifies the post-ingest pass.
func (s *Service) Name() string { return "remediation" }

// ApplyToScan is the post-ingest pass: it groups the findings the scan
// reported that aren't in an action yet (joining live actions of the same
// change, auto-creating when enabled), and refreshes the project's live
// actions — closing those the scan resolved.
func (s *Service) ApplyToScan(ctx context.Context, projectID, scanID string) (int, error) {
	res, err := s.sweep(ctx, projectID, scanID)
	return res.Created + res.Joined + res.Closed, err
}

func (s *Service) sweep(ctx context.Context, projectID, scanID string) (SweepResult, error) {
	var res SweepResult
	if s.off(ctx) {
		return res, nil
	}
	ff := finding.FixFilter{ScanID: scanID, Unactioned: true}
	if projectID != "" {
		ff.ProjectIDs = []string{projectID}
	}
	cands, err := s.cands.FixCandidates(ctx, ff)
	if err != nil {
		return res, err
	}
	changes, _ := fixplan.Changes(cands, groupOpts)
	live, err := s.store.LiveActions(ctx, projectID)
	if err != nil {
		return res, err
	}
	byKey := make(map[string]LiveAction, len(live))
	for _, a := range live {
		byKey[actionKey(a.ProjectID, a.Kind, a.Key)] = a
	}
	for _, c := range changes {
		if a, ok := byKey[actionKey(c.ProjectID, c.Kind, c.Key)]; ok {
			n, err := s.store.AddFindings(ctx, a.ID, c.FindingIDs)
			if err != nil {
				return res, err
			}
			res.Joined += n
			// The upgrade has to fix the newcomers too.
			if c.Kind == fixplan.KindPackageUpgrade && pkgmeta.CompareVersions(c.Ecosystem, c.Target, a.Target) > 0 {
				if err := s.store.SetTarget(ctx, a.ID, c.Target); err != nil {
					return res, err
				}
			}
			continue
		}
		if !s.autoCreate {
			res.Proposed++
			continue
		}
		if _, created, err := s.store.Ensure(ctx, NewAction{ProjectID: c.ProjectID, Kind: c.Kind, Key: c.Key,
			Title: c.Title, Target: c.Target}, c.FindingIDs); err != nil {
			return res, err
		} else if created {
			res.Created++
		}
	}
	closed, err := s.store.Refresh(ctx, projectID)
	if err != nil {
		return res, err
	}
	res.Closed = len(closed)
	return res, nil
}

// ErrNoTracker is returned when filing an action's ticket in a project
// without an enabled tracker.
var ErrNoTracker = issuetracker.ErrNoTracker

// CreateIssue files the action as one ticket in its project's tracker.
// Idempotent: an existing ticket is returned as is (created=false).
func (s *Service) CreateIssue(ctx context.Context, actionID string) (IssueLink, bool, error) {
	a, err := s.store.Get(ctx, actionID)
	if err != nil {
		return IssueLink{}, false, err
	}
	if a.Issue != nil {
		return *a.Issue, false, nil
	}
	if s.trackers == nil {
		return IssueLink{}, false, ErrNoTracker
	}
	t, c, err := s.trackers.OpenClient(ctx, a.ProjectID)
	if err != nil {
		return IssueLink{}, false, err
	}
	fs, err := s.store.Findings(ctx, actionID)
	if err != nil {
		return IssueLink{}, false, err
	}
	return s.store.LinkIssueOnce(ctx, actionID, t.ID, func(ctx context.Context) (string, string, error) {
		ref, err := c.Create(ctx, BuildIssue(a, fs, t.Labels, s.publicURL))
		return ref.ExternalID, ref.URL, err
	})
}

// maxIssueFindings bounds the findings listed in a ticket body.
const maxIssueFindings = 100

// maxIssueTitle keeps titles within every tracker's limit (GitHub 256, Jira 255).
const maxIssueTitle = 250

// BuildIssue renders an action as one ticket: "[severity] title (N findings)",
// and a plain-text body (it reads the same in Markdown and Jira wiki markup)
// with the change, its due date and the findings it closes.
func BuildIssue(a Action, fs []ActionFinding, labels []string, publicURL string) issuetracker.Issue {
	sev := a.MaxSeverity
	if sev == "" {
		sev = domain.SeverityInfo
	}
	var live []ActionFinding
	for _, f := range fs {
		if (f.Status == domain.FindingOpen || f.Status == domain.FindingConfirmed) && f.DuplicateOf == nil {
			live = append(live, f)
		}
	}
	title := "[" + string(sev) + "] " + a.Title
	if a.Target != "" {
		title += " → " + a.Target
	}
	title += " (" + plural(len(live), "finding") + ")"
	if r := []rune(title); len(r) > maxIssueTitle {
		title = string(r[:maxIssueTitle-1]) + "…"
	}

	var b strings.Builder
	line := func(k, v string) {
		if v != "" {
			b.WriteString(k + ": " + v + "\n")
		}
	}
	b.WriteString("Remediation action: " + a.Title + "\n\n")
	line("Change", kindLabel(a.Kind))
	line("Target", a.Target)
	if a.DueAt != nil {
		line("Due", a.DueAt.UTC().Format(time.DateOnly))
	}
	if a.OwnerEmail != nil {
		line("Owner", *a.OwnerEmail)
	}
	line("Closes", plural(len(live), "finding"))
	b.WriteString("\nFindings:\n")
	for i, f := range live {
		if i == maxIssueFindings {
			b.WriteString("- … and " + strconv.Itoa(len(live)-maxIssueFindings) + " more\n")
			break
		}
		b.WriteString("- [" + string(f.Severity) + "] " + f.Title)
		if len(f.CVE) > 0 {
			b.WriteString(" (" + strings.Join(f.CVE, ", ") + ")")
		}
		if f.PackageName != "" {
			b.WriteString(" — " + f.PackageName)
			if f.PackageVersion != "" {
				b.WriteString("@" + f.PackageVersion)
			}
		} else if f.FilePath != "" {
			b.WriteString(" — " + f.FilePath)
			if f.Line != nil {
				b.WriteString(":" + strconv.Itoa(*f.Line))
			}
		}
		if publicURL != "" {
			b.WriteString(" " + publicURL + "/findings/" + f.ID)
		}
		b.WriteString("\n")
	}
	if publicURL != "" {
		b.WriteString("\nView in Xila: " + publicURL + "/projects/" + a.ProjectID + "?tab=remediation\n")
	}
	return issuetracker.Issue{Title: title, Body: b.String(), Labels: labels}
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

func kindLabel(k fixplan.Kind) string {
	switch k {
	case fixplan.KindPackageUpgrade:
		return "package upgrade"
	case fixplan.KindBaseImage:
		return "base image rebuild"
	case fixplan.KindIaCRule:
		return "infrastructure-as-code rule"
	case fixplan.KindCodeLocation:
		return "code fix"
	case fixplan.KindConfig:
		return "configuration change"
	}
	return string(k)
}

// trackerStatus maps an action's status onto the finding status the shared
// sync decision (issuetracker.Decide) reasons about: live is open; done is
// remediated (a reopened ticket reopens it); won't-do is a decision made in
// Xila that a reopened ticket doesn't overturn.
func trackerStatus(s Status) domain.FindingStatus {
	switch s {
	case StatusDone:
		return domain.FindingRemediated
	case StatusWontDo:
		return domain.FindingWontFix
	}
	return domain.FindingOpen
}

// SyncLinks reconciles a tracker's action tickets both ways (an
// issuetracker.LinkSyncer): an action closing closes its ticket, a ticket
// closed in the tracker closes the action.
func (s *Service) SyncLinks(ctx context.Context, t issuetracker.Tracker, c issuetracker.Client, res *issuetracker.SyncResult) error {
	if s.off(ctx) {
		return nil
	}
	items, err := s.store.IssueSyncItems(ctx, t.ID)
	if err != nil {
		return err
	}
	for _, it := range items {
		if err := s.reconcile(ctx, c, it, res); err != nil {
			res.Errors++
			slog.WarnContext(ctx, "action issue sync failed",
				"tracker_id", t.ID, "action_id", it.ActionID, "issue", it.ExternalID, "error", err)
		}
	}
	return nil
}

func (s *Service) reconcile(ctx context.Context, c issuetracker.Client, it IssueSyncItem, res *issuetracker.SyncResult) error {
	remote, err := c.State(ctx, it.ExternalID)
	if err != nil {
		return err
	}
	d := issuetracker.Decide(it.State, trackerStatus(it.Status), remote)
	switch d.Action {
	case issuetracker.ActNone:
		return nil
	case issuetracker.ActRecord:
	case issuetracker.ActCloseIssue:
		if err := c.Close(ctx, it.ExternalID); err != nil {
			return err
		}
		res.ClosedIssues++
	case issuetracker.ActReopenIssue:
		if err := c.Reopen(ctx, it.ExternalID); err != nil {
			return err
		}
		res.ReopenedIssues++
	case issuetracker.ActResolveFinding:
		if err := s.store.SetStatusFromTracker(ctx, it.ActionID, StatusDone); err != nil {
			return err
		}
		res.ResolvedActions++
	case issuetracker.ActReopenFinding:
		if err := s.store.SetStatusFromTracker(ctx, it.ActionID, StatusOpen); errors.Is(err, ErrConflict) {
			// Another live action tracks the change now: the ticket is closed again.
			if err := c.Close(ctx, it.ExternalID); err != nil {
				return err
			}
			d.State = issuetracker.StateClosed
			res.ClosedIssues++
		} else if err != nil {
			return err
		} else {
			res.ReopenedActions++
		}
	default:
		return fmt.Errorf("unexpected sync action %q", d.Action)
	}
	return s.store.SetIssueState(ctx, it.ID, d.State)
}
