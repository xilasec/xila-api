package triagecarry

import (
	"context"
	"fmt"
	"regexp"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

// Eligible reports whether a status is one triage carry tracks: a person
// decided the finding is not real (false_positive), decided not to fix it
// (wont_fix), or reversed either of those (open, reopening it). Everything
// else is excluded by design, see the package doc.
func Eligible(s domain.FindingStatus) bool {
	return s == domain.FindingFalsePositive || s == domain.FindingWontFix || s == domain.FindingOpen
}

// projectSettings reads a project's carry configuration and version names
// (project.Repository satisfies it).
type projectSettings interface {
	TriageCarrySettings(ctx context.Context, projectID string) (enabled bool, branchRegex string, err error)
	VersionNames(ctx context.Context, projectID string) (map[string]string, error)
}

// findingStore is the subset of the finding repository the engine needs.
type findingStore interface {
	ListByFingerprint(ctx context.Context, projectID, fingerprint, excludeID string, statuses []domain.FindingStatus) ([]finding.Finding, error)
	ListForTriageScan(ctx context.Context, projectID, scanID string) ([]finding.Finding, error)
	SetStatusCarried(ctx context.Context, id string, t finding.Triage, decidedAt time.Time, note string) (finding.Finding, error)
}

// Service carries manual triage decisions across a project's in-scope
// branches, and reapplies a project's stored decisions to new findings at
// ingest (satisfies finding.Carrier and scan.Applier).
type Service struct {
	decisions *Repository
	projects  projectSettings
	findings  findingStore
}

// NewService wires the triage-carry dependencies.
func NewService(decisions *Repository, projects projectSettings, findings findingStore) *Service {
	return &Service{decisions: decisions, projects: projects, findings: findings}
}

// Name identifies this pass in the ingest pipeline.
func (s *Service) Name() string { return "triage-carry" }

// scope is one project's resolved carry configuration: whether it's on, the
// compiled branch filter (nil matches every version), and its version names.
type scope struct {
	enabled  bool
	filter   *regexp.Regexp
	versions map[string]string // version id -> name
}

func (s *Service) scopeFor(ctx context.Context, projectID string) (scope, error) {
	enabled, branchRegex, err := s.projects.TriageCarrySettings(ctx, projectID)
	if err != nil || !enabled {
		return scope{enabled: enabled}, err
	}
	var filter *regexp.Regexp
	if branchRegex != "" {
		filter, err = regexp.Compile(branchRegex)
		if err != nil {
			return scope{}, fmt.Errorf("triage carry branch_regex: %w", err)
		}
	}
	versions, err := s.projects.VersionNames(ctx, projectID)
	if err != nil {
		return scope{}, err
	}
	return scope{enabled: true, filter: filter, versions: versions}, nil
}

// inScope reports whether versionID both exists and matches the branch
// filter (nil filter = every version).
func (sc scope) inScope(versionID string) bool {
	name, ok := sc.versions[versionID]
	if !ok {
		return false
	}
	return sc.filter == nil || sc.filter.MatchString(name)
}

// targetStatuses is which findings a decision reaches: false_positive/wont_fix
// looks for currently open/confirmed findings to suppress; open (a reopen)
// looks for currently suppressed ones (false_positive/wont_fix) to reopen —
// exactly what an earlier carry, or independent triage, suppressed.
func targetStatuses(status domain.FindingStatus) []domain.FindingStatus {
	if status == domain.FindingOpen {
		return []domain.FindingStatus{domain.FindingFalsePositive, domain.FindingWontFix}
	}
	return []domain.FindingStatus{domain.FindingOpen, domain.FindingConfirmed}
}

// Carry records f's status as the project's latest decision for its
// fingerprint (when carry is on and f's version is in scope) and propagates
// it to every other matching finding on an in-scope version of the same
// project (see targetStatuses), attributed to actor with the history note
// "carried from <branch>". It never overturns a target whose own status was
// decided more recently (see applyDecision); a status outside Eligible
// (confirmed, remediated, risk_accepted) is a no-op.
func (s *Service) Carry(ctx context.Context, f finding.Finding, actor string) error {
	if !Eligible(f.Status) {
		return nil
	}
	sc, err := s.scopeFor(ctx, f.ProjectID)
	if err != nil || !sc.enabled || !sc.inScope(f.VersionID) {
		return err
	}

	decidedAt := time.Now()
	if f.StatusDecidedAt != nil {
		decidedAt = *f.StatusDecidedAt
	}
	d := Decision{
		ProjectID: f.ProjectID, Fingerprint: f.Fingerprint, Status: f.Status,
		Reason: f.ExceptionReason, ExpiresAt: f.ExceptionExpiresAt, Actor: actor,
		VexJustification: f.VexJustification, VexResponse: f.VexResponse,
		SourceFindingID: f.ID, SourceVersionID: f.VersionID,
		SourceBranch: sc.versions[f.VersionID], DecidedAt: decidedAt,
	}
	recorded, err := s.decisions.Upsert(ctx, d)
	if err != nil {
		return err
	}
	if !recorded {
		return nil // a decision at least as recent is already on file
	}

	candidates, err := s.findings.ListByFingerprint(ctx, d.ProjectID, d.Fingerprint, d.SourceFindingID, targetStatuses(d.Status))
	if err != nil {
		return err
	}
	for _, c := range candidates {
		if !sc.inScope(c.VersionID) {
			continue
		}
		if _, err := s.applyDecision(ctx, c, d); err != nil {
			return err
		}
	}
	return nil
}

// applyDecision brings target to d's status, unless target's own status was
// decided more recently (a targeted, later override on that one instance
// wins) or it already reflects d exactly (nothing to do — idempotent).
func (s *Service) applyDecision(ctx context.Context, target finding.Finding, d Decision) (bool, error) {
	if target.StatusDecidedAt != nil && target.StatusDecidedAt.After(d.DecidedAt) {
		return false, nil
	}
	if target.Status == d.Status && target.StatusDecidedAt != nil && !target.StatusDecidedAt.Before(d.DecidedAt) {
		return false, nil
	}
	note := "carried from " + d.SourceBranch
	if _, err := s.findings.SetStatusCarried(ctx, target.ID, finding.Triage{
		Status: d.Status, Reason: d.Reason, ExpiresAt: d.ExpiresAt, Actor: d.Actor,
		VexJustification: d.VexJustification, VexResponse: d.VexResponse,
	}, d.DecidedAt, note); err != nil {
		return false, err
	}
	return true, nil
}

// ApplyToScan is the ingest pipeline's applier seam (internal/scan.Applier):
// every open/confirmed finding the scan reported — a brand-new finding
// included — is matched against the project's carried decisions by
// fingerprint. This is how a new finding, or a new version's very first scan,
// inherits a decision made elsewhere in the project without any separate
// clone step. Placed after VEX and vulnerability policies (an authoritative
// verdict always wins) and before the generic triage rules (so a rule can
// still see what carry already settled); see cmd/api/main.go.
func (s *Service) ApplyToScan(ctx context.Context, projectID, scanID string) (int, error) {
	sc, err := s.scopeFor(ctx, projectID)
	if err != nil || !sc.enabled {
		return 0, err
	}
	findings, err := s.findings.ListForTriageScan(ctx, projectID, scanID)
	if err != nil {
		return 0, err
	}
	changed := 0
	for _, f := range findings {
		if !sc.inScope(f.VersionID) {
			continue
		}
		d, found, err := s.decisions.Get(ctx, projectID, f.Fingerprint)
		if err != nil {
			return changed, err
		}
		if !found {
			continue
		}
		applied, err := s.applyDecision(ctx, f, d)
		if err != nil {
			return changed, err
		}
		if applied {
			changed++
		}
	}
	return changed, nil
}
