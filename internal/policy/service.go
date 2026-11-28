package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/expr"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/license"
	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/pkgmeta"
	"github.com/xilasec/xila-api/internal/sbom"
	"github.com/xilasec/xila-api/internal/scan"
)

// policyStore reads policies and the bookkeeping evaluation needs (Repository).
type policyStore interface {
	Enabled(ctx context.Context) ([]Policy, error)
	Targets(ctx context.Context, projectID, versionID string) ([]target, error)
	Projects(ctx context.Context, ids []string) ([]string, error)
	ProjectTags(ctx context.Context, ids []string) (map[string][]string, error)
	LockProject(ctx context.Context, projectID string) (func(), error)
	NewViolations(ctx context.Context, scanID string) ([]NewViolation, error)
}

// inventoryStore yields current SBOM inventory with its facts, and the
// snapshots' dependency graphs (sbom.Repository).
type inventoryStore interface {
	CurrentInventory(ctx context.Context, projectIDs []string, versionID string) ([]sbom.InventoryComponent, error)
	SnapshotGraphs(ctx context.Context, sbomIDs []string) (map[string]sbom.SnapshotGraph, error)
}

// packageMeta yields package-repository metadata per purl (pkgmeta.Repository);
// purls it knows nothing about are absent.
type packageMeta interface {
	Info(ctx context.Context, purls []string) (map[string]pkgmeta.Info, error)
}

// licenseGroups resolves license group refs (license.Groups).
type licenseGroups interface {
	Members(ctx context.Context, ref string) ([]string, error)
}

// findingApplier records a producer's complete findings through the ingest
// pipeline — upsert, auto-close, auto-triage, dedup, alert (scan.Service).
type findingApplier interface {
	ApplyFindings(ctx context.Context, projectID, versionID, scanner string, category domain.Category, findings []finding.Finding) (scan.Scan, error)
}

// eventNotifier dispatches events (notify.Service). Optional.
type eventNotifier interface {
	Notify(ctx context.Context, e notify.Event)
}

// Service evaluates policies against current SBOM inventory.
type Service struct {
	store     policyStore
	inventory inventoryStore
	meta      packageMeta
	groups    licenseGroups
	apply     findingApplier
	notifier  eventNotifier
	now       func() time.Time
	// fields lists project custom fields, readable as project.custom.<key>
	// (optional: nil = none defined).
	fields customFieldLister

	// Background re-evaluation after policy changes: one worker at a time,
	// draining a deduplicated set of projects.
	mu      sync.Mutex
	pending map[string]bool
	all     bool
	running bool
	idle    sync.WaitGroup
}

// NewService wires the policy engine. notifier may be nil.
func NewService(store policyStore, inventory inventoryStore, meta packageMeta, groups licenseGroups, apply findingApplier, notifier eventNotifier) *Service {
	return &Service{store: store, inventory: inventory, meta: meta, groups: groups, apply: apply,
		notifier: notifier, now: time.Now, pending: map[string]bool{}}
}

// customFieldLister lists custom-field definitions (customfield.Repository).
type customFieldLister interface {
	List(ctx context.Context, entity customfield.Entity) ([]customfield.Definition, error)
}

// WithCustomFields lets expressions read project.custom.<key>.
func (s *Service) WithCustomFields(fields customFieldLister) *Service {
	s.fields = fields
	return s
}

// schema is the document expressions are checked against: ComponentSchema
// with every project custom field currently defined.
func (s *Service) schema(ctx context.Context) (expr.Schema, error) {
	if s.fields == nil {
		return ComponentSchema, nil
	}
	defs, err := s.fields.List(ctx, customfield.EntityProject)
	if err != nil {
		return expr.Schema{}, err
	}
	return ComponentSchemaFor(defs), nil
}

// Validate checks and normalizes a policy for storage. A *ValidationError is
// the caller's fault (400); anything else is internal.
func (s *Service) Validate(ctx context.Context, p *Policy) error {
	schema, err := s.schema(ctx)
	if err != nil {
		return err
	}
	_, err = validate(p, s.strictGroups(ctx), schema)
	return err
}

// strictGroups resolves license group refs for a policy being saved or
// previewed: an unknown group is the caller's mistake.
func (s *Service) strictGroups(ctx context.Context) groupResolver {
	return func(ref string) ([]string, error) {
		ids, err := s.groups.Members(ctx, ref)
		if errors.Is(err, license.ErrGroupNotFound) || errors.Is(err, license.ErrInvalidGroupRef) {
			return nil, invalid("license_group: %v: %q", err, ref)
		}
		return ids, err
	}
}

// compileAll compiles enabled policies for evaluation. Group refs resolve once
// per run; a policy that no longer compiles (it was valid when saved) is
// logged and skipped.
func (s *Service) compileAll(ctx context.Context, policies []Policy) []compiledPolicy {
	cache := map[string][]string{}
	resolve := func(ref string) ([]string, error) {
		if ids, ok := cache[ref]; ok {
			return ids, nil
		}
		ids, err := s.groups.Members(ctx, ref)
		if errors.Is(err, license.ErrGroupNotFound) || errors.Is(err, license.ErrInvalidGroupRef) {
			slog.WarnContext(ctx, "policy: license group is gone; its condition never matches", "ref", ref)
			return nil, errGroupGone
		}
		if err != nil {
			return nil, err
		}
		cache[ref] = ids
		return ids, nil
	}
	// A policy whose expression names a custom field deleted since is
	// skipped below like any other that no longer compiles.
	schema, err := s.schema(ctx)
	if err != nil {
		slog.WarnContext(ctx, "policy: custom fields unavailable; expressions see none", "error", err)
		schema = ComponentSchema
	}
	// This run's own frame: the graph functions read the component it is
	// evaluating, so two runs must never share one.
	schema.Frame = expr.NewGraphFrame()
	out := make([]compiledPolicy, 0, len(policies))
	for _, p := range policies {
		cp, err := validate(&p, resolve, schema)
		if err != nil {
			slog.WarnContext(ctx, "policy: skipping a policy that does not compile", "policy_id", p.ID, "error", err)
			continue
		}
		out = append(out, cp)
	}
	return out
}

// Result summarizes an evaluation run.
type Result struct {
	Projects   int `json:"projects"`
	Violations int `json:"violations"`
}

// EvaluateAll re-evaluates every project with inventory or open violations.
// One failing project doesn't stop the sweep.
func (s *Service) EvaluateAll(ctx context.Context) (Result, error) {
	ids, err := s.store.Projects(ctx, nil)
	if err != nil {
		return Result{}, err
	}
	var res Result
	for _, id := range ids {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		n, err := s.evaluate(ctx, id, "")
		if err != nil {
			slog.WarnContext(ctx, "policy: evaluating project failed", "project_id", id, "error", err)
			continue
		}
		res.Projects++
		res.Violations += n
	}
	slog.InfoContext(ctx, "policy evaluation complete", "projects", res.Projects, "violations", res.Violations)
	return res, nil
}

// EvaluateProject re-evaluates every version of one project.
func (s *Service) EvaluateProject(ctx context.Context, projectID string) (Result, error) {
	n, err := s.evaluate(ctx, projectID, "")
	if err != nil {
		return Result{}, err
	}
	return Result{Projects: 1, Violations: n}, nil
}

// Evaluate is the SBOM post-ingest hook (sbom.ComponentEvaluator): the stored
// snapshot is now its version's current inventory, so that version is
// re-evaluated in full (components is the uploaded document, not needed).
func (s *Service) Evaluate(ctx context.Context, projectID, versionID string, _ []sbom.Component) error {
	_, err := s.evaluate(ctx, projectID, versionID)
	return err
}

// evaluate applies the complete violation set of each target version of a
// project (versionID "" = all), under the project's policy lock. Returns the
// number of violations recorded.
func (s *Service) evaluate(ctx context.Context, projectID, versionID string) (int, error) {
	unlock, err := s.store.LockProject(ctx, projectID)
	if err != nil {
		return 0, err
	}
	defer unlock()

	targets, err := s.store.Targets(ctx, projectID, versionID)
	if err != nil || len(targets) == 0 {
		return 0, err
	}
	enabled, err := s.store.Enabled(ctx)
	if err != nil {
		return 0, err
	}
	tags, err := s.store.ProjectTags(ctx, []string{projectID})
	if err != nil {
		return 0, err
	}
	var inForce []Policy
	for _, p := range enabled {
		if p.AppliesTo(projectID, tags[projectID]) {
			inForce = append(inForce, p)
		}
	}
	policies := s.compileAll(ctx, inForce)
	byVersion := map[string][]*Component{}
	if len(policies) > 0 {
		comps, err := s.components(ctx, []string{projectID}, versionID, policies)
		if err != nil {
			return 0, err
		}
		for _, c := range comps {
			byVersion[c.VersionID] = append(byVersion[c.VersionID], c)
		}
	}

	licensePolicies := slices.ContainsFunc(policies, compiledPolicy.usesLicense)
	now := s.now()
	total := 0
	var fresh []NewViolation
	for _, t := range targets {
		// License resolution hasn't run on some of this version's components
		// yet (rows stored before it existed, awaiting the backfill): judging
		// them as license-less would close their license violations. Leave the
		// version as it is until the data is there.
		if licensePolicies && slices.ContainsFunc(byVersion[t.VersionID], func(c *Component) bool { return c.LicenseResolved == nil }) {
			slog.InfoContext(ctx, "policy: licenses not resolved yet; skipping version",
				"project_id", projectID, "version_id", t.VersionID)
			continue
		}
		found := violations(policies, byVersion[t.VersionID], t.IsDefault, now)
		if len(found) == 0 && !t.HasOpen {
			continue // nothing to record and nothing to close
		}
		sc, err := s.apply.ApplyFindings(ctx, projectID, t.VersionID, Scanner, domain.CategorySCA, found)
		if err != nil {
			return total, fmt.Errorf("apply policy violations to version %s: %w", t.VersionID, err)
		}
		total += len(found)
		if s.notifier != nil {
			nv, err := s.store.NewViolations(ctx, sc.ID)
			if err != nil {
				slog.WarnContext(ctx, "policy: listing new violations failed", "error", err, "scan_id", sc.ID)
			}
			fresh = append(fresh, nv...)
		}
	}
	s.notifyFailures(projectID, policies, fresh)
	return total, nil
}

// components loads current inventory (one entry per component version and
// project version — two artifacts may ship the same package) with parsed
// licenses and, when a policy reads it, package metadata.
func (s *Service) components(ctx context.Context, projectIDs []string, versionID string, policies []compiledPolicy) ([]*Component, error) {
	inv, err := s.inventory.CurrentInventory(ctx, projectIDs, versionID)
	if err != nil {
		return nil, err
	}
	exprs := map[string]license.Expr{}
	var (
		out   []*Component
		purls []string
	)
	for _, ic := range inv {
		// Every occurrence is kept: one package version can sit in several
		// artifacts of a version with different facts (an artifact's hashes and
		// so its integrity, its dependency scope). violations judges each and
		// reports the package once.
		c := &Component{InventoryComponent: ic}
		if e := ic.LicenseExpression; e != "" {
			expr, ok := exprs[e]
			if !ok {
				expr, _ = license.ParseExpression(e) // stored normalized; a failure stays zero (unknown)
				exprs[e] = expr
			}
			c.License = expr
		}
		if ic.Purl != "" {
			purls = append(purls, ic.Purl)
		}
		out = append(out, c)
	}
	needMeta, needGraph := false, false
	for _, cp := range policies {
		needMeta = needMeta || cp.needsMeta()
		needGraph = needGraph || cp.needsGraph()
	}
	if needGraph {
		if err := s.attachGraphs(ctx, out); err != nil {
			return nil, err
		}
	}
	if needMeta && len(purls) > 0 {
		info, err := s.meta.Info(ctx, purls)
		if err != nil {
			return nil, fmt.Errorf("package metadata: %w", err)
		}
		for _, c := range out {
			if m, ok := info[c.Purl]; ok && c.Purl != "" {
				c.Meta = &PackageInfo{Latest: m.Latest, Outdated: m.Outdated, VersionsBehind: m.VersionsBehind, Published: m.Published}
			}
		}
	}
	return out, nil
}

// attachGraphs gives every component its snapshot's dependency graph, built
// once per snapshot: every component of it a node (its versionless purl for
// exact patterns, the full one for regexes), every edge the SBOM recorded.
func (s *Service) attachGraphs(ctx context.Context, comps []*Component) error {
	var ids []string
	for _, c := range comps {
		if !slices.Contains(ids, c.SbomID) {
			ids = append(ids, c.SbomID)
		}
	}
	stored, err := s.inventory.SnapshotGraphs(ctx, ids)
	if err != nil {
		return fmt.Errorf("dependency graphs: %w", err)
	}
	graphs := make(map[string]*expr.Graph, len(ids))
	for id, sg := range stored {
		g := expr.NewGraph(sg.Root)
		for _, e := range sg.Edges {
			g.AddEdge(e.Parent, e.Child)
		}
		graphs[id] = g
	}
	for _, c := range comps {
		g := graphs[c.SbomID]
		if g == nil {
			continue
		}
		node := sbom.ComponentRef(c.BomRef, c.ID)
		base := ""
		if p, err := pkgmeta.ParsePURL(c.Purl); err == nil {
			p.Version = ""
			base = p.Base()
		}
		g.AddNode(expr.GraphNode{ID: node, Base: base, Purl: c.Purl})
		c.Graph, c.GraphNode = g, node
	}
	return nil
}

// notifyFailures sends one policy.violation event for the new violations of
// fail-state policies an evaluation of a project introduced.
func (s *Service) notifyFailures(projectID string, policies []compiledPolicy, fresh []NewViolation) {
	if s.notifier == nil || len(fresh) == 0 {
		return
	}
	failing := map[string]string{}
	for _, cp := range policies {
		if cp.ViolationState == StateFail {
			failing[cp.ID] = cp.Name
		}
	}
	var (
		titles []string
		names  []string
		count  int
	)
	for _, v := range fresh {
		name, ok := failing[v.PolicyID]
		if !ok {
			continue
		}
		count++
		if len(titles) < 3 {
			titles = append(titles, v.Title)
		}
		if !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	if count == 0 {
		return
	}
	go s.notifier.Notify(context.Background(), notify.Event{
		Type:      notify.EventPolicyViolation,
		Title:     fmt.Sprintf("%d new policy violation(s)", count),
		Text:      strings.Join(titles, "\n"),
		Severity:  string(StateFail.Severity()),
		ProjectID: projectID,
		Fields: map[string]string{
			"total":    strconv.Itoa(count),
			"policies": strings.Join(names, ", "),
		},
	})
}

// PreviewHit is one component a draft policy would flag.
type PreviewHit struct {
	ProjectID   string          `json:"project_id"`
	ProjectName string          `json:"project_name"`
	VersionID   string          `json:"version_id"`
	VersionName string          `json:"version_name"`
	Name        string          `json:"name"`
	Group       string          `json:"group"`
	Version     string          `json:"version"`
	Purl        string          `json:"purl"`
	Severity    domain.Severity `json:"severity"`
	Category    domain.Category `json:"category"`
	Matches     []Match         `json:"matches"`
}

// PreviewResult is what a draft policy would do, without writing anything.
type PreviewResult struct {
	Components int          `json:"components"` // evaluated
	Total      int          `json:"total"`      // violations
	Violations []PreviewHit `json:"violations"` // the first previewLimit
	Truncated  bool         `json:"truncated"`
}

// previewLimit caps the violations a preview lists (Total counts them all).
const previewLimit = 500

// Preview evaluates a draft policy (enabled or not; a name is optional)
// against the current inventory of projectIDs (nil = every project),
// intersected with the policy's own scope. It writes nothing.
func (s *Service) Preview(ctx context.Context, p Policy, projectIDs []string) (PreviewResult, error) {
	if strings.TrimSpace(p.Name) == "" {
		p.Name = "preview"
	}
	schema, err := s.schema(ctx)
	if err != nil {
		return PreviewResult{}, err
	}
	schema.Frame = expr.NewGraphFrame() // this preview's own; see compileAll
	cp, err := validate(&p, s.strictGroups(ctx), schema)
	if err != nil {
		return PreviewResult{}, err
	}
	scope := projectIDs
	if p.Scope == ScopeProjects {
		scope = intersect(projectIDs, p.ProjectIDs)
	}
	out := PreviewResult{Violations: []PreviewHit{}}
	if scope != nil && len(scope) == 0 {
		return out, nil
	}
	comps, err := s.components(ctx, scope, "", []compiledPolicy{cp})
	if err != nil {
		return PreviewResult{}, err
	}
	// The tag scope: the projects' tags, loaded once.
	var tags map[string][]string
	if len(p.IncludeTags)+len(p.ExcludeTags) > 0 {
		ids := []string{}
		for _, c := range comps {
			if !slices.Contains(ids, c.ProjectID) {
				ids = append(ids, c.ProjectID)
			}
		}
		if tags, err = s.store.ProjectTags(ctx, ids); err != nil {
			return PreviewResult{}, err
		}
	}
	now := s.now()
	counted, hit := map[string]bool{}, map[string]bool{}
	for _, c := range comps {
		if p.Versions == VersionsDefault && !c.IsDefault {
			continue
		}
		if tags != nil && !p.covers(c.ProjectID, tags[c.ProjectID]) {
			continue
		}
		key := c.ProjectID + "|" + c.VersionID + "|" + componentKey(c)
		if !counted[key] {
			counted[key] = true
			out.Components++
		}
		if hit[key] {
			continue
		}
		matches, ok := cp.evaluate(c, now)
		if !ok {
			continue
		}
		hit[key] = true
		out.Total++
		if len(out.Violations) >= previewLimit {
			out.Truncated = true
			continue
		}
		out.Violations = append(out.Violations, PreviewHit{
			ProjectID: c.ProjectID, ProjectName: c.ProjectName, VersionID: c.VersionID, VersionName: c.VersionName,
			Name: c.Name, Group: c.Group, Version: c.Version, Purl: c.Purl,
			Severity: p.ViolationState.Severity(), Category: violationCategory(matches), Matches: matches,
		})
	}
	return out, nil
}

// intersect returns the ids in both lists; a nil a means "everything".
func intersect(a, b []string) []string {
	if a == nil {
		return b
	}
	out := []string{}
	for _, x := range b {
		if slices.Contains(a, x) {
			out = append(out, x)
		}
	}
	return out
}

// reevalTimeout bounds a background re-evaluation of one project.
const reevalTimeout = 5 * time.Minute

// Reevaluate re-evaluates projects in the background after a policy change:
// projectIDs, or every project when all is set. Requests coalesce into one
// worker, so a burst of edits costs one pass per affected project.
func (s *Service) Reevaluate(projectIDs []string, all bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.all = s.all || all
	for _, id := range projectIDs {
		s.pending[id] = true
	}
	if s.running {
		return
	}
	s.running = true
	s.idle.Add(1)
	go s.drain()
}

func (s *Service) drain() {
	defer s.idle.Done()
	for {
		s.mu.Lock()
		all, ids := s.all, make([]string, 0, len(s.pending))
		for id := range s.pending {
			ids = append(ids, id)
		}
		s.all, s.pending = false, map[string]bool{}
		if !all && len(ids) == 0 {
			s.running = false
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()

		if all {
			var err error
			if ids, err = s.store.Projects(context.Background(), nil); err != nil {
				slog.Warn("policy: listing projects to re-evaluate failed", "error", err)
				continue
			}
		}
		for _, id := range ids {
			ctx, cancel := context.WithTimeout(context.Background(), reevalTimeout)
			if _, err := s.evaluate(ctx, id, ""); err != nil {
				slog.Warn("policy: re-evaluation failed", "project_id", id, "error", err)
			}
			cancel()
		}
	}
}

// WaitIdle blocks until background re-evaluation has drained (tests).
func (s *Service) WaitIdle() {
	s.idle.Wait()
}

// AfterMatch wraps the advisory matcher an SBOM upload starts so policies are
// re-evaluated once the new snapshot's advisories are recorded: security
// conditions then see them right away rather than at the next scheduled run.
func (s *Service) AfterMatch(m sbom.AdvisoryMatcher) sbom.AdvisoryMatcher {
	return matchThenEvaluate{matcher: m, policies: s}
}

type matchThenEvaluate struct {
	matcher  sbom.AdvisoryMatcher
	policies *Service
}

func (m matchThenEvaluate) MatchProject(ctx context.Context, projectID string) (int, error) {
	n, err := m.matcher.MatchProject(ctx, projectID)
	if err != nil {
		return n, err
	}
	if _, err := m.policies.evaluate(ctx, projectID, ""); err != nil {
		slog.WarnContext(ctx, "policy: evaluation after advisory match failed", "project_id", projectID, "error", err)
	}
	return n, nil
}

// AfterRefresh wraps the registry lookup an SBOM upload starts so policies are
// re-evaluated once the new packages' metadata is in: outdated / versions
// behind / age conditions then judge them right away (they were unknown at
// upload time) rather than at the next scheduled run.
func (s *Service) AfterRefresh(p sbom.PackageRefresher) sbom.PackageRefresher {
	return refreshThenEvaluate{refresher: p, policies: s}
}

type refreshThenEvaluate struct {
	refresher sbom.PackageRefresher
	policies  *Service
}

func (r refreshThenEvaluate) RefreshProject(ctx context.Context, projectID string) error {
	if err := r.refresher.RefreshProject(ctx, projectID); err != nil {
		return err
	}
	if _, err := r.policies.evaluate(ctx, projectID, ""); err != nil {
		slog.WarnContext(ctx, "policy: evaluation after package refresh failed", "project_id", projectID, "error", err)
	}
	return nil
}
