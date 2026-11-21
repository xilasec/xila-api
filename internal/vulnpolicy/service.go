package vulnpolicy

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/expr"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/notify"
)

// policyActor is recorded as the actor on findings a policy sets, so a person
// reading the audit trail can see the decision came from a named vulnerability
// policy, not a person.
func policyActor(name string) string { return "vuln-policy:" + name }

type policyStore interface {
	List(ctx context.Context) ([]Policy, error)
	Enabled(ctx context.Context) ([]Policy, error)
	ProjectFacts(ctx context.Context, projectID string) (ProjectFacts, error)
	ProjectsWithCandidates(ctx context.Context) ([]string, error)
	CandidateFindingIDs(ctx context.Context, projectID string) ([]string, error)
	MatchesByProject(ctx context.Context, projectID string) (map[string]Match, error)
	UpsertMatch(ctx context.Context, m Match) error
	DeleteMatch(ctx context.Context, findingID string) error
	ReplaceAll(ctx context.Context, ps []Policy, actor string) ([]Policy, error)
}

// findingStore is the subset of the finding repository the engine needs.
type findingStore interface {
	ListForTriageScan(ctx context.Context, projectID, scanID string) ([]finding.Finding, error)
	ListByIDs(ctx context.Context, ids []string) ([]finding.Finding, error)
	SetStatus(ctx context.Context, id string, t finding.Triage) (finding.Finding, error)
	SetSeverity(ctx context.Context, id string, sev domain.Severity) (finding.Finding, error)
}

// deduper recomputes cross-tool grouping for a project (finding.Repository
// satisfies it). Optional: only needed because a rating override changes
// severity, and dedup re-elects a group's primary by severity.
type deduper interface {
	Deduplicate(ctx context.Context, projectID string) (int, error)
}

// eventNotifier dispatches events (notify.Service satisfies it). Optional.
type eventNotifier interface {
	Notify(ctx context.Context, e notify.Event)
}

// Service applies vulnerability policies to component/vulnerability pairs
// (package findings).
type Service struct {
	policies policyStore
	findings findingStore
	dedup    deduper
	now      func() time.Time
	notifier eventNotifier // optional
}

// NewService constructs the apply Service. dedup may be nil.
func NewService(policies policyStore, findings findingStore, dedup deduper) *Service {
	return &Service{policies: policies, findings: findings, dedup: dedup, now: time.Now}
}

// WithNotifier raises finding.status_changed once per evaluation when any
// policy changed a finding's status or severity (batched, never per finding).
func (s *Service) WithNotifier(n eventNotifier) *Service {
	s.notifier = n
	return s
}

// Name identifies this pass in the ingest pipeline. It runs after VEX
// (whose verdicts are authoritative) and before the generic triage rules —
// see cmd/api/main.go's applier order comment.
func (s *Service) Name() string { return "vuln-policy" }

// ApplyToScan evaluates only the findings a scan just reported — the ingest
// path. Reverts (a policy that expired or stopped matching) are handled by
// the project-wide sweep (ApplyToProject / EvaluateAll on
// VULN_POLICY_EVAL_INTERVAL), exactly like component policies: ingest cost
// tracks the scan's size, not every policy's validity window.
func (s *Service) ApplyToScan(ctx context.Context, projectID, scanID string) (int, error) {
	findings, err := s.findings.ListForTriageScan(ctx, projectID, scanID)
	if err != nil {
		return 0, err
	}
	return s.evaluate(ctx, projectID, findings)
}

// ApplyToProject re-evaluates every candidate in a project: its active
// backlog (new matches) plus every finding still carrying a tracked policy
// match (so an expired or edited policy gets reverted even though the
// finding itself didn't change).
func (s *Service) ApplyToProject(ctx context.Context, projectID string) (int, error) {
	ids, err := s.policies.CandidateFindingIDs(ctx, projectID)
	if err != nil {
		return 0, err
	}
	findings, err := s.findings.ListByIDs(ctx, ids)
	if err != nil {
		return 0, err
	}
	return s.evaluate(ctx, projectID, findings)
}

// EvaluateAll re-evaluates every project that has a candidate — the backfill
// path for a new/edited/deleted policy and the periodic sweep that catches
// validity-window expiry.
func (s *Service) EvaluateAll(ctx context.Context) (int, error) {
	projectIDs, err := s.policies.ProjectsWithCandidates(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, id := range projectIDs {
		n, err := s.ApplyToProject(ctx, id)
		if err != nil {
			return total, fmt.Errorf("project %s: %w", id, err)
		}
		total += n
	}
	return total, nil
}

func (s *Service) evaluate(ctx context.Context, projectID string, findings []finding.Finding) (int, error) {
	if len(findings) == 0 {
		return 0, nil
	}
	policies, err := s.policies.Enabled(ctx)
	if err != nil {
		return 0, err
	}
	projectFacts, err := s.policies.ProjectFacts(ctx, projectID)
	if err != nil {
		return 0, err
	}
	matches, err := s.policies.MatchesByProject(ctx, projectID)
	if err != nil {
		return 0, err
	}
	now := s.now()
	changed := 0
	regroup := false
	for _, f := range findings {
		doc := pairDoc(f, projectFacts)
		elected, ok := Elect(ctx, policies, now, projectID, projectFacts.Tags, doc)
		m := matches[f.ID]
		m.FindingID = f.ID

		statusChanged, err := s.reconcileStatus(ctx, &f, elected, ok, &m)
		if err != nil {
			return changed, err
		}
		sevChanged, err := s.reconcileSeverity(ctx, &f, elected, ok, &m)
		if err != nil {
			return changed, err
		}
		if statusChanged {
			changed++
		}
		if sevChanged {
			changed++
			regroup = true
		}

		if m.AppliedStatus == "" && m.AppliedSeverity == "" {
			if _, had := matches[f.ID]; had {
				if err := s.policies.DeleteMatch(ctx, f.ID); err != nil {
					return changed, err
				}
			}
		} else if err := s.policies.UpsertMatch(ctx, m); err != nil {
			return changed, err
		}
	}
	if regroup && s.dedup != nil {
		if _, err := s.dedup.Deduplicate(ctx, projectID); err != nil {
			return changed, err
		}
	}
	if changed > 0 && s.notifier != nil {
		go s.notifier.Notify(context.Background(), notify.Event{
			Type: notify.EventStatusChanged, ProjectID: projectID,
			Title:  fmt.Sprintf("Vulnerability policies changed %d finding(s)", changed),
			Fields: map[string]string{"count": fmt.Sprintf("%d", changed), "actor": "vuln-policy"},
		})
	}
	return changed, nil
}

// reconcileStatus decides the analysis-status half of one finding against
// the policy currently elected for it (ok reports whether any apply-mode
// policy is elected) and updates m in place. It returns whether a write
// happened.
//
// Three outcomes, mirroring an expired triage exception reopening a finding:
//   - still claimed by the same policy at the same target: no-op.
//   - the finding moved away from what we last set (someone/something else
//     changed it since): we stop claiming it — never move it back. This is
//     the "don't overturn a person's later triage" rule.
//   - no longer elected (disabled, expired, condition stopped matching, or
//     its target state changed): revert to the status recorded before we
//     touched it, then — in the same pass — claim fresh if a (possibly
//     different) policy now wants something else.
func (s *Service) reconcileStatus(ctx context.Context, f *finding.Finding, elected Policy, ok bool, m *Match) (bool, error) {
	wantStatus, want := "", false
	if ok && elected.Analysis != nil {
		if st, has := elected.Analysis.State.Status(); has {
			wantStatus, want = string(st), true
		}
	}

	if m.AppliedStatus != "" {
		if string(f.Status) != m.AppliedStatus {
			// Overturned since we set it. Abandon the claim; leave it alone.
			m.AppliedStatus, m.PriorStatus = "", ""
			return false, nil
		}
		if want && ok && elected.ID == m.PolicyID && wantStatus == m.AppliedStatus {
			return false, nil // still claimed, nothing changed
		}
		// No longer elected at this target: revert, then maybe reclaim.
		prior := domain.FindingStatus(m.PriorStatus)
		if prior == "" {
			prior = domain.FindingOpen
		}
		changed := false
		if f.Status != prior {
			if _, err := s.findings.SetStatus(ctx, f.ID, finding.Triage{
				Status: prior, Actor: policyActor(m.PolicyName),
				Reason: "vulnerability policy no longer applies: " + m.PolicyName,
			}); err != nil {
				return false, err
			}
			f.Status = prior
			changed = true
		}
		m.AppliedStatus, m.PriorStatus = "", ""
		if want && isClaimable(f.Status) && string(f.Status) != wantStatus {
			priorNow := f.Status
			if _, err := s.findings.SetStatus(ctx, f.ID, finding.Triage{
				Status: domain.FindingStatus(wantStatus), Actor: policyActor(elected.Name), Reason: reasonFor(elected),
			}); err != nil {
				return changed, err
			}
			m.AppliedStatus, m.PriorStatus, m.PolicyID, m.PolicyName = wantStatus, string(priorNow), elected.ID, elected.Name
			return true, nil
		}
		return changed, nil
	}

	// No existing claim: claim fresh only out of the live backlog, and only
	// when it actually moves the finding (a coincidental pre-existing match
	// isn't ours to track or later revert).
	if want && isClaimable(f.Status) && string(f.Status) != wantStatus {
		prior := f.Status
		if _, err := s.findings.SetStatus(ctx, f.ID, finding.Triage{
			Status: domain.FindingStatus(wantStatus), Actor: policyActor(elected.Name), Reason: reasonFor(elected),
		}); err != nil {
			return false, err
		}
		m.AppliedStatus, m.PriorStatus, m.PolicyID, m.PolicyName = wantStatus, string(prior), elected.ID, elected.Name
		return true, nil
	}
	return false, nil
}

// isClaimable reports whether a finding is in the live backlog a policy may
// move — deliberately narrower than triage/VEX's open+confirmed eligibility:
// "confirmed" is itself frequently a person's deliberate verdict (or this
// same engine's own AnalysisExploitable target), and once the tracking row
// for an earlier claim is gone (overturned, or the policy that set it was
// deleted), a finding sitting at "confirmed" must never look like a fresh,
// untouched candidate again.
func isClaimable(s domain.FindingStatus) bool {
	return s == domain.FindingOpen
}

// reconcileSeverity is reconcileStatus for the rating half. It leans on
// finding.Repository.SetSeverity's own guard (never overwrites a
// severity_manual finding) for overturn-safety, rather than duplicating that
// check here.
func (s *Service) reconcileSeverity(ctx context.Context, f *finding.Finding, elected Policy, ok bool, m *Match) (bool, error) {
	want := ""
	if ok && elected.Rating != nil {
		want = string(elected.Rating.Severity)
	}

	if m.AppliedSeverity != "" {
		if string(f.Severity) != m.AppliedSeverity {
			// Changed since we set it (a manual edit sets severity_manual,
			// which also makes every SetSeverity below a no-op).
			m.AppliedSeverity, m.PriorSeverity = "", ""
			return false, nil
		}
		if want != "" && ok && elected.ID == m.PolicyID && want == m.AppliedSeverity {
			return false, nil
		}
		changed := false
		if prior := domain.Severity(m.PriorSeverity); prior != "" && f.Severity != prior {
			nf, err := s.findings.SetSeverity(ctx, f.ID, prior)
			if err != nil {
				return false, err
			}
			f.Severity = nf.Severity
			changed = f.Severity == prior
		}
		m.AppliedSeverity, m.PriorSeverity = "", ""
		if want != "" && f.Severity != domain.Severity(want) {
			priorNow := f.Severity
			nf, err := s.findings.SetSeverity(ctx, f.ID, domain.Severity(want))
			if err != nil {
				return changed, err
			}
			if nf.Severity == domain.Severity(want) {
				m.AppliedSeverity, m.PriorSeverity, m.PolicyID, m.PolicyName = want, string(priorNow), elected.ID, elected.Name
				return true, nil
			}
		}
		return changed, nil
	}

	if want != "" && f.Severity != domain.Severity(want) {
		prior := f.Severity
		nf, err := s.findings.SetSeverity(ctx, f.ID, domain.Severity(want))
		if err != nil {
			return false, err
		}
		if nf.Severity == domain.Severity(want) {
			m.AppliedSeverity, m.PriorSeverity, m.PolicyID, m.PolicyName = want, string(prior), elected.ID, elected.Name
			return true, nil
		}
	}
	return false, nil
}

// reasonFor is the human-readable rationale recorded on a finding a policy
// claims.
func reasonFor(p Policy) string {
	if p.Analysis == nil {
		return "matched vulnerability policy: " + p.Name
	}
	parts := make([]string, 0, 2)
	if p.Analysis.Justification != "" {
		parts = append(parts, p.Analysis.Justification)
	}
	if p.Analysis.Details != "" {
		parts = append(parts, p.Analysis.Details)
	}
	if len(parts) == 0 {
		return "matched vulnerability policy: " + p.Name
	}
	return "vulnerability policy: " + p.Name + " — " + strings.Join(parts, "; ")
}

// List returns every policy (for the admin UI / bundle export).
func (s *Service) List(ctx context.Context) ([]Policy, error) { return s.policies.List(ctx) }

// PreviewLimit caps the findings a preview lists; Total still counts them all.
const PreviewLimit = 200

// PreviewItem is one finding a candidate policy would act on, and how.
type PreviewItem struct {
	FindingID       string               `json:"finding_id"`
	ProjectID       string               `json:"project_id"`
	Title           string               `json:"title"`
	PackageName     string               `json:"package_name"`
	PackageVersion  string               `json:"package_version"`
	Purl            string               `json:"purl"`
	VulnerabilityID string               `json:"vulnerability_id"`
	CurrentStatus   domain.FindingStatus `json:"current_status"`
	SetStatus       domain.FindingStatus `json:"set_status,omitempty"`
	CurrentSeverity domain.Severity      `json:"current_severity"`
	SetSeverity     domain.Severity      `json:"set_severity,omitempty"`
}

// Preview is a dry run's result.
type Preview struct {
	Total    int           `json:"total"`
	Findings []PreviewItem `json:"findings"`
}

// Preview reports which candidate findings a (possibly unsaved) candidate
// policy would act on, mutating nothing. candidate must already be compiled
// (Validate). projectID ("" = every project the candidate's scope covers)
// narrows it further. Election against other live policies is intentionally
// ignored — the point of previewing is "what would this policy, on its own,
// do", the same way triage's Preview works on a candidate rule.
func (s *Service) Preview(ctx context.Context, candidate Policy, projectID string) (Preview, error) {
	now := s.now()
	projectIDs := []string{projectID}
	if projectID == "" {
		ids, err := s.policies.ProjectsWithCandidates(ctx)
		if err != nil {
			return Preview{}, err
		}
		projectIDs = ids
	}
	var out Preview
	for _, pid := range projectIDs {
		facts, err := s.policies.ProjectFacts(ctx, pid)
		if err != nil {
			continue // a stale/removed project id; skip rather than fail the whole preview
		}
		if !candidate.covers(pid, facts.Tags) {
			continue
		}
		ids, err := s.policies.CandidateFindingIDs(ctx, pid)
		if err != nil {
			return Preview{}, err
		}
		findings, err := s.findings.ListByIDs(ctx, ids)
		if err != nil {
			return Preview{}, err
		}
		for _, f := range findings {
			doc := pairDoc(f, facts)
			if !candidate.AppliesNow(now, pid, facts.Tags) || !candidate.Match(ctx, doc) {
				continue
			}
			item := PreviewItem{
				FindingID: f.ID, ProjectID: f.ProjectID, Title: f.Title,
				PackageName: f.PackageName, PackageVersion: f.PackageVersion, Purl: f.Purl,
				VulnerabilityID: vulnID(f), CurrentStatus: f.Status, CurrentSeverity: f.Severity,
			}
			if candidate.Analysis != nil {
				if st, has := candidate.Analysis.State.Status(); has {
					item.SetStatus = st
				}
			}
			if candidate.Rating != nil {
				item.SetSeverity = candidate.Rating.Severity
			}
			out.Total++
			if len(out.Findings) < PreviewLimit {
				out.Findings = append(out.Findings, item)
			}
		}
	}
	return out, nil
}

// ImportBundle validates every policy in ps against schema, then atomically
// replaces the whole policy set (GET/PUT /vuln-policies/bundle): a bundle
// lives in git and is applied as a unit. dryRun validates without writing.
// actor ("" for none, e.g. a scheduled BUNDLE_URL sync) is recorded as every
// policy's author.
func (s *Service) ImportBundle(ctx context.Context, ps []Policy, schema expr.Schema, actor string, dryRun bool) ([]Policy, error) {
	seen := map[string]bool{}
	for i := range ps {
		if seen[strings.ToLower(ps[i].Name)] {
			return nil, &ValidationError{"duplicate policy name in bundle: " + ps[i].Name}
		}
		seen[strings.ToLower(ps[i].Name)] = true
		if err := ps[i].Validate(schema); err != nil {
			return nil, fmt.Errorf("policy %q: %w", ps[i].Name, err)
		}
	}
	if dryRun {
		return ps, nil
	}
	out, err := s.policies.ReplaceAll(ctx, ps, actor)
	if err != nil {
		return nil, err
	}
	// The new set may claim or release findings immediately (e.g. a bundle
	// that drops a policy the old set had applying) — same as any backfill.
	if _, err := s.EvaluateAll(ctx); err != nil {
		return out, err
	}
	return out, nil
}
