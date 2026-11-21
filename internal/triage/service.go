package triage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/notify"
)

// ruleSource yields the enabled, approved rules that apply to a project, records
// their hits, and resolves the project's facts (self-defined for testability;
// *Repository satisfies it).
type ruleSource interface {
	ListEnabledForProject(ctx context.Context, projectID string) ([]Rule, error)
	RecordHits(ctx context.Context, hits map[string]int) error
	ProjectFacts(ctx context.Context, projectID string) (ProjectFacts, error)
	// ProjectOwner resolves the assign action's owner_from = "project_owner".
	ProjectOwner(ctx context.Context, projectID string) (string, bool, error)
	// FiredActions/RecordActions track the comment/notify side actions
	// already posted for a (rule, finding), so re-running an idempotent rule
	// never reposts them.
	FiredActions(ctx context.Context, ruleIDs []string) (map[string]bool, error)
	RecordActions(ctx context.Context, fired []FiredAction) error
}

// findingStore is the subset of the finding repository the engine needs.
type findingStore interface {
	ListForTriage(ctx context.Context, projectID string) ([]finding.Finding, error)
	ListForTriageScan(ctx context.Context, projectID, scanID string) ([]finding.Finding, error)
	// GetOneForTriage is ListForTriage narrowed to one finding — the
	// finding-event trigger (a status/severity change elsewhere) re-evaluates
	// just that finding. false when it isn't in the active, non-duplicate
	// backlog the other triggers already evaluate.
	GetOneForTriage(ctx context.Context, id string) (finding.Finding, bool, error)
	SetStatus(ctx context.Context, id string, t finding.Triage) (finding.Finding, error)
	AcceptBySystem(ctx context.Context, s finding.SystemAcceptance, ids []string) ([]string, error)
	SetSeverity(ctx context.Context, id string, sev domain.Severity, actor string) (finding.Finding, error)
	SetCustom(ctx context.Context, id string, set map[string]any, unset []string, actor, note string) (map[string]any, error)
	ProjectIDsWithFindings(ctx context.Context) ([]string, error)
	// Apply and AddComment back the assign/add_tags and comment side actions.
	Apply(ctx context.Context, ids []string, c finding.Change, actor string) ([]finding.Finding, error)
	AddComment(ctx context.Context, findingID, authorID, body string) (finding.Comment, error)
}

// customChecker validates a custom-field write against the field definitions
// (customfield.Service): the type, the finding's organization, and that a
// user value can see the finding's project.
type customChecker interface {
	Prepare(ctx context.Context, entity customfield.Entity, id string, patch map[string]any, requireAll bool) (customfield.Change, error)
}

// errSkip: the rule matched, but its change can't be made to this finding
// (a set_custom_field value that isn't valid here); the finding is left alone.
var errSkip = errors.New("skip")

// deduper recomputes cross-tool grouping for a project (finding.Repository
// satisfies it). Optional.
type deduper interface {
	Deduplicate(ctx context.Context, projectID string) (int, error)
}

// notifier enqueues the "notify" side action's event on the durable outbox
// (notify.Service satisfies it). Optional: without one, notify never fires.
type notifier interface {
	Notify(ctx context.Context, e notify.Event)
}

// Service applies triage rules to findings.
type Service struct {
	rules    ruleSource
	findings findingStore
	dedup    deduper       // optional
	custom   customChecker // set_custom_field needs it; without, those rules change nothing
	notifier notifier      // optional; without, the notify side action never fires
}

// WithCustomFields lets set_custom_field rules validate their writes.
func (s *Service) WithCustomFields(c customChecker) *Service {
	s.custom = c
	return s
}

// WithNotifier lets the notify side action enqueue its event.
func (s *Service) WithNotifier(n notifier) *Service {
	s.notifier = n
	return s
}

// NewService constructs the apply Service. dedup may be nil.
func NewService(rules ruleSource, findings findingStore, dedup deduper) *Service {
	return &Service{rules: rules, findings: findings, dedup: dedup}
}

// ApplyToProject evaluates the project's whole active backlog against its rules,
// applying the first matching rule to each. Returns how many findings changed.
// This is the backfill path (a rule was added or edited); the ingest path uses
// ApplyToScan.
func (s *Service) ApplyToProject(ctx context.Context, projectID string) (int, error) {
	changed, err := s.applyTo(ctx, projectID, func(ctx context.Context) ([]finding.Finding, error) {
		return s.findings.ListForTriage(ctx, projectID)
	})
	// A backfill can suppress or downgrade findings anywhere in the project, and
	// severity is what decides which tool's report of a CVE leads its group — so
	// the whole project has to be regrouped. (The ingest path doesn't need this:
	// it dedups the groups its own scan touched right after ApplyToScan.)
	if err == nil && changed > 0 && s.dedup != nil {
		if _, derr := s.dedup.Deduplicate(ctx, projectID); derr != nil {
			return changed, fmt.Errorf("regroup after triage: %w", derr)
		}
	}
	return changed, err
}

// ApplyToScan evaluates only the findings a scan just reported. Rules are
// idempotent and every finding is evaluated on the ingest that reported it, so
// re-running the whole backlog on each upload would re-decide thousands of
// findings nothing has changed about — cost that grows with the project's size
// instead of with the scan. A rule added later reaches the existing backlog via
// ApplyToProject (POST /triage-rules/apply).
func (s *Service) ApplyToScan(ctx context.Context, projectID, scanID string) (int, error) {
	return s.applyTo(ctx, projectID, func(ctx context.Context) ([]finding.Finding, error) {
		return s.findings.ListForTriageScan(ctx, projectID, scanID)
	})
}

// ApplyToFinding re-evaluates a project's rules against exactly one finding —
// the finding-event trigger (status changed, severity changed, reopened),
// via EventTrigger. Regroups the project when something changed, like
// ApplyToProject.
func (s *Service) ApplyToFinding(ctx context.Context, projectID, findingID string) (int, error) {
	changed, err := s.applyTo(ctx, projectID, func(ctx context.Context) ([]finding.Finding, error) {
		f, ok, err := s.findings.GetOneForTriage(ctx, findingID)
		if err != nil || !ok || f.ProjectID != projectID {
			return nil, err
		}
		return []finding.Finding{f}, nil
	})
	if err == nil && changed > 0 && s.dedup != nil {
		if _, derr := s.dedup.Deduplicate(ctx, projectID); derr != nil {
			return changed, fmt.Errorf("regroup after triage: %w", derr)
		}
	}
	return changed, err
}

// eventTrigger adapts Service to finding.ChangeTrigger.
type eventTrigger struct{ s *Service }

// EventTrigger returns the finding.ChangeTrigger a finding.Repository wires in
// (WithChangeTrigger): any write that changes a finding's status or severity
// — a manual edit, VEX, a vulnerability policy, issue-tracker sync, an
// exception reopening it — gives triage rules a chance to react without
// waiting for the next ingest or scheduled run. No recursion: a write whose
// actor is a triage rule's own ("triage-rule:" + name) is skipped, or a
// rule's change would re-trigger rules forever.
func (s *Service) EventTrigger() finding.ChangeTrigger { return eventTrigger{s} }

// OnFindingChanged implements finding.ChangeTrigger. Best-effort, like
// notify.Service.Notify: a failure here must not fail the write that
// triggered it, so it is only logged.
func (t eventTrigger) OnFindingChanged(ctx context.Context, projectID, findingID, actor string) {
	if strings.HasPrefix(actor, "triage-rule:") {
		return
	}
	if _, err := t.s.ApplyToFinding(ctx, projectID, findingID); err != nil {
		slog.WarnContext(ctx, "triage: event trigger failed", "error", err, "finding_id", findingID)
	}
}

func (s *Service) applyTo(ctx context.Context, projectID string, load func(context.Context) ([]finding.Finding, error)) (int, error) {
	rules, err := s.rules.ListEnabledForProject(ctx, projectID)
	if err != nil {
		return 0, err
	}
	if len(rules) == 0 {
		return 0, nil
	}
	facts, err := s.factsFor(ctx, projectID, rules)
	if err != nil {
		return 0, err
	}
	findings, err := load(ctx)
	if err != nil {
		return 0, err
	}
	fired, err := s.loadFired(ctx, rules)
	if err != nil {
		return 0, err
	}

	changed := 0
	hits := map[string]int{}
	var logged []FiredAction
	notifyAcc := map[string][]finding.Finding{}
	for _, f := range findings {
		err := chain(rules, f, facts,
			func(_ int, rule Rule, f finding.Finding, ch change) (bool, error) {
				if err := s.apply(ctx, rule, f, ch); errors.Is(err, errSkip) {
					return false, nil
				} else if err != nil {
					return false, err
				}
				changed++
				hits[rule.ID]++
				return true, nil
			},
			func(_ int, rule Rule, f finding.Finding) (bool, error) {
				acted, err := s.applySide(ctx, rule, f, fired, &logged, notifyAcc)
				if err != nil {
					return false, err
				}
				if acted {
					changed++
					hits[rule.ID]++
				}
				return acted, nil
			},
		)
		if err != nil {
			// Count what already changed before failing.
			_ = s.rules.RecordHits(ctx, hits)
			_ = s.rules.RecordActions(ctx, logged)
			return changed, err
		}
	}
	s.sendNotifications(ctx, rules, notifyAcc)
	if err := s.rules.RecordActions(ctx, logged); err != nil {
		return changed, err
	}
	if err := s.rules.RecordHits(ctx, hits); err != nil {
		return changed, err
	}
	return changed, nil
}

// factsFor looks the project's facts up once per run, and only when some rule
// actually conditions on them.
func (s *Service) factsFor(ctx context.Context, projectID string, rules []Rule) (ProjectFacts, error) {
	for i := range rules {
		if rules[i].needsProject() {
			return s.rules.ProjectFacts(ctx, projectID)
		}
	}
	return ProjectFacts{}, nil
}

// loadFired preloads the comment/notify side actions already posted for every
// rule that configures one of them, one query for the whole run.
func (s *Service) loadFired(ctx context.Context, rules []Rule) (map[string]bool, error) {
	var ids []string
	for _, r := range rules {
		if r.Comment != "" || r.Notify {
			ids = append(ids, r.ID)
		}
	}
	if len(ids) == 0 {
		return nil, nil
	}
	return s.rules.FiredActions(ctx, ids)
}

// matchFrom returns the index of the first rule at or after start matching f.
func matchFrom(rules []Rule, start int, f finding.Finding, p ProjectFacts) (int, bool) {
	for i := start; i < len(rules); i++ {
		if rules[i].Matches(f, p) {
			return i, true
		}
	}
	return 0, false
}

// chain evaluates rules (in sort order) against one finding: the first match
// acts, and evaluation stops there unless that rule has Continue set, in
// which case the following rules see the finding as the rule left it (rule
// chaining). do performs a decided primary-action change (rule is rules[i])
// and reports whether it took effect; only a change that took effect is
// visible to later rules. side performs the rule's configured side actions
// (assign/add_tags/comment/notify), independent of whether the primary
// action had anything to do. A rule whose target state the finding is
// already in changes nothing but still chains. It is the single evaluation
// order of apply and preview.
func chain(rules []Rule, f finding.Finding, p ProjectFacts,
	do func(i int, rule Rule, f finding.Finding, ch change) (bool, error),
	side func(i int, rule Rule, f finding.Finding) (bool, error),
) error {
	for start := 0; ; {
		i, ok := matchFrom(rules, start, f, p)
		if !ok {
			return nil
		}
		rule := rules[i]
		if ch, ok := decide(rule, f); ok {
			applied, err := do(i, rule, f, ch)
			if err != nil {
				return err
			}
			if applied {
				f = withChange(f, rule, ch)
			}
		}
		if rule.hasSideActions() {
			if _, err := side(i, rule, f); err != nil {
				return err
			}
		}
		if !rule.Continue {
			return nil
		}
		start = i + 1
	}
}

// withChange is f after rule's change ch, for the rules chained after it.
func withChange(f finding.Finding, rule Rule, ch change) finding.Finding {
	if rule.Action == ActionSetCustomField {
		custom := make(map[string]any, len(f.Custom)+1)
		maps.Copy(custom, f.Custom)
		if rule.CustomValue == nil {
			delete(custom, rule.CustomField)
		} else {
			custom[rule.CustomField] = rule.CustomValue
		}
		f.Custom = custom
		return f
	}
	f.Status, f.Severity = ch.Status, ch.Severity
	return f
}

// change is the outcome of a rule acting on a finding.
type change struct {
	Status   domain.FindingStatus
	Severity domain.Severity
}

// decide computes what rule would turn f into, and false when f is already in
// the target state (so re-applying on every ingest is idempotent). It is the
// single source of truth for both apply and preview.
func decide(rule Rule, f finding.Finding) (change, bool) {
	if rule.Action == ActionSetCustomField {
		cur, has := f.Custom[rule.CustomField]
		if (rule.CustomValue == nil && !has) || (has && reflect.DeepEqual(cur, rule.CustomValue)) {
			return change{}, false
		}
		return change{Status: f.Status, Severity: f.Severity}, true
	}
	if rule.Action == ActionSetSeverity {
		if rule.NewSeverity == "" || f.Severity == rule.NewSeverity {
			return change{}, false
		}
		return change{Status: f.Status, Severity: rule.NewSeverity}, true
	}
	target := domain.FindingStatus(rule.Action)
	if f.Status == target {
		return change{}, false
	}
	return change{Status: target, Severity: f.Severity}, true
}

// sideChange is what a rule's side actions would do to a finding right now.
type sideChange struct {
	// Assign is the user id the assign action would set, nil = it wouldn't fire.
	Assign *string
	// AddTags is only the tags f doesn't already carry.
	AddTags []string
	Comment bool
	Notify  bool
}

// hasAny reports whether any side action would fire.
func (sc sideChange) hasAny() bool {
	return sc.Assign != nil || len(sc.AddTags) > 0 || sc.Comment || sc.Notify
}

// decideSide computes what rule's side actions would do to f right now:
// assign (unless already assigned and only_if_unassigned), add_tags (only
// what f doesn't already carry), comment/notify (unless firedFor already
// says they fired for this finding+rule). ownerID resolves
// owner_from=project_owner lazily (called only if needed). Pure — makes no
// writes — so applySide and Preview share one decision.
func decideSide(rule Rule, f finding.Finding, firedFor func(action string) bool, ownerID func() (string, bool)) sideChange {
	var sc sideChange
	alreadyAssigned := rule.onlyIfUnassigned() && f.AssigneeID != nil
	switch {
	case rule.AssignUserID != nil:
		if !alreadyAssigned {
			id := *rule.AssignUserID
			sc.Assign = &id
		}
	case rule.AssignOwnerFrom == "project_owner":
		if !alreadyAssigned {
			if id, ok := ownerID(); ok {
				sc.Assign = &id
			}
		}
	}
	for _, t := range rule.AddTags {
		if !slices.Contains(f.Tags, t) {
			sc.AddTags = append(sc.AddTags, t)
		}
	}
	if rule.Comment != "" && !firedFor("comment") {
		sc.Comment = true
	}
	if rule.Notify && !firedFor("notify") {
		sc.Notify = true
	}
	return sc
}

// applySide performs rule's configured side actions on f (if any are still
// due) and reports whether anything happened. fired is the run's preloaded
// "already posted" set; newly fired comment/notify entries are appended to
// *logged for one batched RecordActions call at the end of the run. A
// pending notify recipient accumulates in notifyAcc, sent once per rule per
// run (sendNotifications), never one notification per finding.
func (s *Service) applySide(ctx context.Context, rule Rule, f finding.Finding, fired map[string]bool,
	logged *[]FiredAction, notifyAcc map[string][]finding.Finding,
) (bool, error) {
	if !rule.hasSideActions() {
		return false, nil
	}
	var ownerCached *string
	var ownerOK, ownerResolved bool
	ownerID := func() (string, bool) {
		if !ownerResolved {
			ownerResolved = true
			if id, ok, err := s.rules.ProjectOwner(ctx, f.ProjectID); err == nil {
				ownerCached, ownerOK = &id, ok
			}
		}
		if ownerCached == nil {
			return "", false
		}
		return *ownerCached, ownerOK
	}
	firedFor := func(action string) bool { return fired[fireKey(rule.ID, f.ID, action)] }
	sc := decideSide(rule, f, firedFor, ownerID)
	if !sc.hasAny() {
		return false, nil
	}
	acted := false
	if sc.Assign != nil || len(sc.AddTags) > 0 {
		ch := finding.Change{}
		if sc.Assign != nil {
			ch.SetAssignee, ch.AssigneeID = true, sc.Assign
		}
		if len(sc.AddTags) > 0 {
			ch.AddTags = sc.AddTags
		}
		if _, err := s.findings.Apply(ctx, []string{f.ID}, ch, "triage-rule:"+rule.Name); err != nil {
			return false, err
		}
		acted = true
	}
	if sc.Comment {
		body := "[triage rule: " + rule.Name + "] " + rule.Comment
		if _, err := s.findings.AddComment(ctx, f.ID, "", body); err != nil {
			return false, err
		}
		*logged = append(*logged, FiredAction{RuleID: rule.ID, FindingID: f.ID, Action: "comment"})
		acted = true
	}
	if sc.Notify {
		notifyAcc[rule.ID] = append(notifyAcc[rule.ID], f)
		*logged = append(*logged, FiredAction{RuleID: rule.ID, FindingID: f.ID, Action: "notify"})
		acted = true
	}
	return acted, nil
}

// notifyBatchLimit caps how many findings a triage-rule notification names;
// the rest still count toward its total.
const notifyBatchLimit = 10

// sendNotifications enqueues one notification per rule that accumulated a
// pending notify batch this run (never one per finding).
func (s *Service) sendNotifications(ctx context.Context, rules []Rule, notifyAcc map[string][]finding.Finding) {
	if s.notifier == nil || len(notifyAcc) == 0 {
		return
	}
	byID := make(map[string]Rule, len(rules))
	for _, r := range rules {
		byID[r.ID] = r
	}
	for ruleID, findings := range notifyAcc {
		if len(findings) == 0 {
			continue
		}
		rule := byID[ruleID]
		shown := findings
		if len(shown) > notifyBatchLimit {
			shown = shown[:notifyBatchLimit]
		}
		titles := make([]string, len(shown))
		for i, f := range shown {
			titles[i] = string(f.Severity) + ": " + f.Title
		}
		s.notifier.Notify(ctx, notify.Event{
			Type:      notify.EventTriageRule,
			Title:     fmt.Sprintf("Triage rule %q matched %d finding(s)", rule.Name, len(findings)),
			Text:      strings.Join(titles, "\n"),
			ProjectID: findings[0].ProjectID,
			Fields: map[string]string{
				"rule":    rule.Name,
				"rule_id": rule.ID,
				"total":   strconv.Itoa(len(findings)),
			},
		})
	}
}

// ApplyAll runs ApplyToProject for every project that has findings — used to
// backfill after a global rule is created or changed.
func (s *Service) ApplyAll(ctx context.Context) (int, error) {
	ids, err := s.findings.ProjectIDsWithFindings(ctx)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, id := range ids {
		n, err := s.ApplyToProject(ctx, id)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// apply performs a decided primary-action change on a finding.
func (s *Service) apply(ctx context.Context, rule Rule, f finding.Finding, ch change) error {
	if rule.Action == ActionSetCustomField {
		if s.custom == nil {
			return errSkip
		}
		w, err := s.custom.Prepare(ctx, customfield.EntityFinding, f.ID, map[string]any{rule.CustomField: rule.CustomValue}, false)
		var invalid *customfield.ValidationError
		if errors.As(err, &invalid) || errors.Is(err, customfield.ErrEntityNotFound) {
			return errSkip // e.g. the field is scoped to another org, or the user can't see this project
		}
		if err != nil {
			return err
		}
		if w.Empty() {
			return errSkip
		}
		_, err = s.findings.SetCustom(ctx, f.ID, w.Set, w.Unset, "triage-rule:"+rule.Name, "matched triage rule: "+rule.Name)
		return err
	}
	if rule.Action == ActionSetSeverity {
		_, err := s.findings.SetSeverity(ctx, f.ID, ch.Severity, "triage-rule:"+rule.Name)
		return err
	}
	reason := rule.Reason
	if reason == "" {
		reason = "matched triage rule: " + rule.Name
	}
	if ch.Status == domain.FindingRiskAccepted {
		// A rule's acceptances live in one acceptance per project, approved
		// at once: the rule itself is admin policy (with its own four-eyes,
		// TRIAGE_RULES_REQUIRE_APPROVAL). A finding already in another live
		// acceptance stays there.
		_, err := s.findings.AcceptBySystem(ctx, finding.SystemAcceptance{
			ProjectID: f.ProjectID, SourceKey: "triage-rule:" + rule.ID,
			Title: "Triage rule: " + rule.Name, Justification: reason,
			Actor: "triage-rule:" + rule.Name, Approve: true,
		}, []string{f.ID})
		return err
	}
	_, err := s.findings.SetStatus(ctx, f.ID, finding.Triage{
		Status: ch.Status,
		Reason: reason,
		Actor:  "triage-rule:" + rule.Name,
	})
	return err
}

// PreviewLimit caps the findings a preview lists; Total still counts them all.
const PreviewLimit = 200

// PreviewItem is one finding a rule would change, and how.
type PreviewItem struct {
	ID          string               `json:"id"`
	ProjectID   string               `json:"project_id"`
	Title       string               `json:"title"`
	Severity    domain.Severity      `json:"severity"`
	Status      domain.FindingStatus `json:"status"`
	NewSeverity domain.Severity      `json:"new_severity"`
	NewStatus   domain.FindingStatus `json:"new_status"`
	// Side actions the rule would also perform (or did, if it's shown
	// because only a side action, not the primary one, matched).
	WouldAssign  *string  `json:"would_assign,omitempty"`
	WouldAddTags []string `json:"would_add_tags,omitempty"`
	WouldComment bool     `json:"would_comment,omitempty"`
	WouldNotify  bool     `json:"would_notify,omitempty"`
}

// Preview is a dry run's result.
type Preview struct {
	Total    int           `json:"total"`
	Findings []PreviewItem `json:"findings"`
}

// Preview reports which findings candidate would change if it were live, without
// mutating anything. It evaluates exactly like a backfill: over each in-scope
// project's open/confirmed non-duplicate backlog, with candidate slotted into
// that project's live rules at its sort_order (replacing its stored version),
// first match wins — so a finding an earlier rule already claims isn't listed.
// The candidate's own approval/enabled state is ignored (that's the point of a
// preview). projectID ("" = all) narrows the scope further. Side actions are
// shown (WouldAssign/WouldAddTags/WouldComment/WouldNotify) but never
// recorded: a finding stays eligible for the real comment/notify action after
// only being previewed.
func (s *Service) Preview(ctx context.Context, candidate Rule, projectID string) (Preview, error) {
	out := Preview{Findings: []PreviewItem{}}
	if err := candidate.compile(); err != nil {
		return out, err
	}
	var projects []string
	switch {
	case candidate.ProjectID != nil && projectID != "" && *candidate.ProjectID != projectID:
		return out, nil // disjoint scopes
	case candidate.ProjectID != nil:
		projects = []string{*candidate.ProjectID}
	case projectID != "":
		projects = []string{projectID}
	default:
		ids, err := s.findings.ProjectIDsWithFindings(ctx)
		if err != nil {
			return out, err
		}
		projects = ids
	}

	for _, pid := range projects {
		live, err := s.rules.ListEnabledForProject(ctx, pid)
		if err != nil {
			return out, err
		}
		rules, at := withCandidate(live, candidate)
		facts, err := s.factsFor(ctx, pid, rules)
		if err != nil {
			return out, err
		}
		findings, err := s.findings.ListForTriage(ctx, pid)
		if err != nil {
			return out, err
		}
		var fired map[string]bool
		if candidate.Comment != "" || candidate.Notify {
			fired, err = s.rules.FiredActions(ctx, []string{candidate.ID})
			if err != nil {
				return out, err
			}
		}
		var ownerCached *string
		var ownerOK, ownerResolved bool
		ownerID := func() (string, bool) {
			if !ownerResolved {
				ownerResolved = true
				if id, ok, oerr := s.rules.ProjectOwner(ctx, pid); oerr == nil {
					ownerCached, ownerOK = &id, ok
				}
			}
			if ownerCached == nil {
				return "", false
			}
			return *ownerCached, ownerOK
		}
		for _, f := range findings {
			var hit bool
			var item PreviewItem
			_ = chain(rules, f, facts,
				func(i int, _ Rule, cur finding.Finding, ch change) (bool, error) {
					if i == at {
						hit = true
						item.ID, item.ProjectID, item.Title = f.ID, f.ProjectID, f.Title
						item.Severity, item.Status = cur.Severity, cur.Status
						item.NewSeverity, item.NewStatus = ch.Severity, ch.Status
					}
					return true, nil // simulate every change, so later chained rules see it
				},
				func(i int, rule Rule, cur finding.Finding) (bool, error) {
					if i != at {
						return true, nil
					}
					firedFor := func(action string) bool { return fired[fireKey(rule.ID, f.ID, action)] }
					sc := decideSide(rule, cur, firedFor, ownerID)
					if !sc.hasAny() {
						return true, nil
					}
					if !hit {
						hit = true
						item.ID, item.ProjectID, item.Title = f.ID, f.ProjectID, f.Title
						item.Severity, item.Status = cur.Severity, cur.Status
						item.NewSeverity, item.NewStatus = cur.Severity, cur.Status
					}
					item.WouldAssign, item.WouldAddTags = sc.Assign, sc.AddTags
					item.WouldComment, item.WouldNotify = sc.Comment, sc.Notify
					return true, nil
				},
			)
			if hit {
				out.Total++
				if len(out.Findings) < PreviewLimit {
					out.Findings = append(out.Findings, item)
				}
			}
		}
	}
	return out, nil
}

// withCandidate returns live with candidate placed where it would evaluate
// (sort_order, then created_at; an unsaved rule sorts after its sort_order
// peers, as it would once created now), plus its index. Its stored version
// (same ID) is dropped. live is not modified.
func withCandidate(live []Rule, candidate Rule) ([]Rule, int) {
	out := make([]Rule, 0, len(live)+1)
	for _, r := range live {
		if candidate.ID != "" && r.ID == candidate.ID {
			continue
		}
		out = append(out, r)
	}
	at := len(out)
	for i, r := range out {
		if r.SortOrder > candidate.SortOrder || (r.SortOrder == candidate.SortOrder &&
			!candidate.CreatedAt.IsZero() && r.CreatedAt.After(candidate.CreatedAt)) {
			at = i
			break
		}
	}
	return slices.Insert(out, at, candidate), at
}

// Name identifies this pass in the ingest pipeline.
func (s *Service) Name() string { return "auto-triage" }
