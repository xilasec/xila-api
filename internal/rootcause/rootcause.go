// Package rootcause answers "what's the same problem everywhere?": it merges
// every visible project's fixplan.Changes into one row per (kind, key) — the
// same package upgrade, base-image rebuild, or rule fix needed in more than
// one project — so a shared CVE or component version is one work item instead
// of a separate remediation action per project (DefectDojo Pro "Root
// Causes"). The grouping itself is fixplan.Changes / fixplan.RootCauses; this
// package only loads the candidates, merges across the caller's visible
// projects, and creates the missing per-project remediation actions by
// reusing remediation.Service.Accept, so its invariants (one live action per
// change, idempotent) hold.
package rootcause

import (
	"context"
	"errors"
	"sort"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/fixplan"
	"github.com/xilasec/xila-api/internal/remediation"
)

// ErrNotFound is returned for a (kind, key) with no matching change among the
// projects searched.
var ErrNotFound = errors.New("root cause not found")

// Candidates loads the live findings to group (finding.Repository).
type Candidates interface {
	FixCandidates(ctx context.Context, ff finding.FixFilter) ([]finding.FixCandidate, error)
}

// LiveActions reports every project's live remediation actions
// (remediation.Repository), so a root cause can report whether it is already
// tracked where it's needed.
type LiveActions interface {
	LiveActions(ctx context.Context, projectID string) ([]remediation.LiveAction, error)
}

// Remediator creates (or joins) the live remediation action for one
// project's share of a root cause (remediation.Service).
type Remediator interface {
	Accept(ctx context.Context, projectID string, kind fixplan.Kind, key, actorID string) (remediation.Action, bool, error)
}

// access answers per-project authorization questions (membership.Repository).
type access interface {
	RoleOnProject(ctx context.Context, userID, projectID string) (domain.TeamRole, bool, error)
	AdminStatus(ctx context.Context, userID string) (isAdmin, isOwner bool, err error)
}

// Service merges and acts on root causes.
type Service struct {
	cands  Candidates
	live   LiveActions
	rem    Remediator
	access access
}

// NewService constructs a Service.
func NewService(cands Candidates, live LiveActions, rem Remediator, access access) *Service {
	return &Service{cands: cands, live: live, rem: rem, access: access}
}

// groupOpts matches remediation's grouping (base images rebuild rather than
// bump their distro packages one by one) so a root cause's AllActioned lines
// up with the same actions remediation tracks.
var groupOpts = fixplan.Options{BaseImages: true}

// Filter selects and limits the root causes List returns.
type Filter struct {
	ProjectIDs  []string // nil = every project (instance admin)
	Kind        fixplan.Kind
	Ecosystem   string
	Query       string // matches title, package, rule id, file path or key, case-insensitive
	KEVOnly     bool
	MinSeverity domain.Severity
}

func (s *Service) changes(ctx context.Context, projectIDs []string) ([]fixplan.Change, error) {
	cands, err := s.cands.FixCandidates(ctx, finding.FixFilter{ProjectIDs: projectIDs})
	if err != nil {
		return nil, err
	}
	changes, _ := fixplan.Changes(cands, groupOpts)
	return changes, nil
}

// liveMap returns every live action across the instance, as the
// (project, kind, key) set fixplan.RootCauses needs, plus the actions
// themselves for per-project lookups (Detail).
func (s *Service) liveMap(ctx context.Context) (map[fixplan.RootCauseLive]bool, []remediation.LiveAction, error) {
	actions, err := s.live.LiveActions(ctx, "")
	if err != nil {
		return nil, nil, err
	}
	m := make(map[fixplan.RootCauseLive]bool, len(actions))
	for _, a := range actions {
		m[fixplan.RootCauseLive{ProjectID: a.ProjectID, Kind: a.Kind, Key: a.Key}] = true
	}
	return m, actions, nil
}

// List returns every root cause over f.ProjectIDs' live findings, most risk
// removed first, matching f's filters.
func (s *Service) List(ctx context.Context, f Filter) ([]fixplan.RootCause, error) {
	changes, err := s.changes(ctx, f.ProjectIDs)
	if err != nil {
		return nil, err
	}
	live, _, err := s.liveMap(ctx)
	if err != nil {
		return nil, err
	}
	return filterRootCauses(fixplan.RootCauses(changes, live), f), nil
}

// filterRootCauses applies f's display filters. Not a grouping decision —
// fixplan.RootCauses already decided the groups; this only narrows which of
// them are shown.
func filterRootCauses(in []fixplan.RootCause, f Filter) []fixplan.RootCause {
	if f.Kind == "" && f.Ecosystem == "" && f.Query == "" && !f.KEVOnly && f.MinSeverity == "" {
		return in
	}
	q := strings.ToLower(strings.TrimSpace(f.Query))
	out := make([]fixplan.RootCause, 0, len(in))
	for _, rc := range in {
		switch {
		case f.Kind != "" && rc.Kind != f.Kind:
			continue
		case f.Ecosystem != "" && !strings.EqualFold(rc.Ecosystem, f.Ecosystem):
			continue
		case f.KEVOnly && rc.KEV == 0:
			continue
		case f.MinSeverity != "" && rc.MaxSeverity.Weight() < f.MinSeverity.Weight():
			continue
		}
		if q != "" {
			hay := strings.ToLower(rc.Title + " " + rc.Package + " " + rc.RuleID + " " + rc.FilePath + " " + rc.Key)
			if !strings.Contains(hay, q) {
				continue
			}
		}
		out = append(out, rc)
	}
	return out
}

// ActionRef is the live remediation action already tracking a project's share
// of a root cause, if any.
type ActionRef struct {
	ID     string             `json:"id"`
	Status remediation.Status `json:"status"`
}

// ProjectShare is one project's part of a root cause.
type ProjectShare struct {
	ProjectID       string          `json:"project_id"`
	ProjectName     string          `json:"project_name"`
	Findings        int             `json:"findings"`
	MaxSeverity     domain.Severity `json:"max_severity"`
	PriorityRemoved float64         `json:"priority_removed"`
	KEV             int             `json:"kev"`
	Action          *ActionRef      `json:"action"`
}

// Detail is one root cause and the projects (within projectIDs) it affects.
type Detail struct {
	fixplan.RootCause
	AffectedProjects []ProjectShare `json:"affected_projects"`
}

// Detail returns one (kind, key) root cause's affected projects, restricted
// to projectIDs (nil = every project). ErrNotFound when none of them carries
// that change — including when every carrier is outside projectIDs, so a
// caller who can see 2 of 3 affected projects sees exactly those 2.
func (s *Service) Detail(ctx context.Context, projectIDs []string, kind fixplan.Kind, key string) (Detail, error) {
	changes, err := s.changes(ctx, projectIDs)
	if err != nil {
		return Detail{}, err
	}
	live, actions, err := s.liveMap(ctx)
	if err != nil {
		return Detail{}, err
	}
	actionByKey := make(map[fixplan.RootCauseLive]remediation.LiveAction, len(actions))
	for _, a := range actions {
		actionByKey[fixplan.RootCauseLive{ProjectID: a.ProjectID, Kind: a.Kind, Key: a.Key}] = a
	}
	var matched []fixplan.Change
	shares := []ProjectShare{}
	for _, c := range changes {
		if c.Kind != kind || c.Key != key {
			continue
		}
		matched = append(matched, c)
		share := ProjectShare{ProjectID: c.ProjectID, ProjectName: c.ProjectName, Findings: c.Closes,
			MaxSeverity: c.MaxSeverity, PriorityRemoved: c.PriorityRemoved, KEV: c.KEV}
		if a, ok := actionByKey[fixplan.RootCauseLive{ProjectID: c.ProjectID, Kind: c.Kind, Key: c.Key}]; ok {
			share.Action = &ActionRef{ID: a.ID, Status: a.Status}
		}
		shares = append(shares, share)
	}
	if len(matched) == 0 {
		return Detail{}, ErrNotFound
	}
	sort.Slice(shares, func(i, j int) bool { return shares[i].ProjectName < shares[j].ProjectName })
	rcs := fixplan.RootCauses(matched, live)
	return Detail{RootCause: rcs[0], AffectedProjects: shares}, nil
}

// SkippedProject is one project CreateMissing didn't create an action in.
type SkippedProject struct {
	ProjectID   string `json:"project_id"`
	ProjectName string `json:"project_name,omitempty"`
	Reason      string `json:"reason"` // "forbidden" or "already_live"
}

// CreateResult summarizes a CreateMissing call.
type CreateResult struct {
	Created int              `json:"created"`
	Skipped []SkippedProject `json:"skipped"`
}

// CreateMissing creates the live remediation action in every project among
// projectIDs (the caller's visible projects; nil = every project, for an
// instance admin) that carries the (kind, key) change and where actorID holds
// at least editor, reusing remediation.Service.Accept so its invariants hold.
// Projects outside projectIDs are never loaded, so they are neither touched
// nor named. Visible projects the actor can't edit, or that already have a
// live action for this change, are reported in Skipped rather than touched.
// Idempotent: a second call creates 0. ErrNotFound when no project among
// projectIDs carries the change.
func (s *Service) CreateMissing(ctx context.Context, actorID string, projectIDs []string, kind fixplan.Kind, key string) (CreateResult, error) {
	changes, err := s.changes(ctx, projectIDs)
	if err != nil {
		return CreateResult{}, err
	}
	res := CreateResult{Skipped: []SkippedProject{}} // a list, never null
	found := false
	for _, c := range changes {
		if c.Kind != kind || c.Key != key {
			continue
		}
		found = true
		ok, err := s.canEdit(ctx, actorID, c.ProjectID)
		if err != nil {
			return res, err
		}
		if !ok {
			res.Skipped = append(res.Skipped, SkippedProject{ProjectID: c.ProjectID, ProjectName: c.ProjectName, Reason: "forbidden"})
			continue
		}
		_, created, err := s.rem.Accept(ctx, c.ProjectID, kind, key, actorID)
		switch {
		case errors.Is(err, remediation.ErrNoProposal):
			// Already has a live action for this change (or every finding is
			// already in one): nothing to do, as a second call should find.
			res.Skipped = append(res.Skipped, SkippedProject{ProjectID: c.ProjectID, ProjectName: c.ProjectName, Reason: "already_live"})
		case err != nil:
			return res, err
		case created:
			res.Created++
		default:
			// Joined an already-live action (created meanwhile by another caller).
			res.Skipped = append(res.Skipped, SkippedProject{ProjectID: c.ProjectID, ProjectName: c.ProjectName, Reason: "already_live"})
		}
	}
	if !found {
		return res, ErrNotFound
	}
	return res, nil
}

// canEdit reports whether userID holds at least editor on projectID (instance
// admins always do).
func (s *Service) canEdit(ctx context.Context, userID, projectID string) (bool, error) {
	isAdmin, _, err := s.access.AdminStatus(ctx, userID)
	if err != nil || isAdmin {
		return isAdmin, err
	}
	role, ok, err := s.access.RoleOnProject(ctx, userID, projectID)
	if err != nil || !ok {
		return false, err
	}
	return role.AtLeast(domain.TeamEditor), nil
}
