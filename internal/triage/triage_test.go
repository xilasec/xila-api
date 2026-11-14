package triage

import (
	"context"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

func intp(n int) *int { return &n }

func TestMatches(t *testing.T) {
	f := finding.Finding{
		Scanner: "trivy", Category: domain.CategorySCA, Severity: domain.SeverityLow,
		RuleID: "CVE-2021-1", CVE: []string{"CVE-2021-1"}, CWE: intp(79),
		FilePath: "test/app_test.go", PackageName: "lodash",
	}
	cases := []struct {
		name string
		rule Rule
		want bool
	}{
		{"empty matches anything", Rule{Action: ActionFalsePositive}, true},
		{"scanner match", Rule{Scanner: "trivy"}, true},
		{"scanner mismatch", Rule{Scanner: "grype"}, false},
		{"category match", Rule{Category: domain.CategorySCA}, true},
		{"severity in set", Rule{Severities: []domain.Severity{domain.SeverityLow, domain.SeverityInfo}}, true},
		{"severity not in set", Rule{Severities: []domain.Severity{domain.SeverityCritical}}, false},
		{"cwe match", Rule{CWE: intp(79)}, true},
		{"cwe mismatch", Rule{CWE: intp(89)}, false},
		{"rule_id match", Rule{RuleID: "CVE-2021-1"}, true},
		{"cve_in match", Rule{CVEIn: []string{"CVE-2020-9", "CVE-2021-1"}}, true},
		{"cve_in miss", Rule{CVEIn: []string{"CVE-2020-9"}}, false},
		{"path regex match", Rule{PathRegex: `_test\.go$`}, true},
		{"path regex miss", Rule{PathRegex: `^src/`}, false},
		{"package regex match", Rule{PackageRegex: `^lo`}, true},
		{"combined AND all true", Rule{Scanner: "trivy", Severities: []domain.Severity{domain.SeverityLow}, PathRegex: `^test/`}, true},
		{"combined one false", Rule{Scanner: "trivy", Severities: []domain.Severity{domain.SeverityHigh}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.rule.compile(); err != nil {
				t.Fatalf("compile: %v", err)
			}
			if got := tc.rule.Matches(f, ProjectFacts{}); got != tc.want {
				t.Errorf("Matches = %v, want %v", got, tc.want)
			}
		})
	}
}

// recordingFindings is a fake findingStore that records the mutations applied.
type recordingFindings struct {
	items      []finding.Finding
	statuses   map[string]domain.FindingStatus
	severities map[string]domain.Severity
	custom     map[string]map[string]any
}

func newRecording(items ...finding.Finding) *recordingFindings {
	return &recordingFindings{items: items, statuses: map[string]domain.FindingStatus{}, severities: map[string]domain.Severity{}}
}
func (r *recordingFindings) ListForTriage(context.Context, string) ([]finding.Finding, error) {
	return r.items, nil
}

func (r *recordingFindings) ListForTriageScan(ctx context.Context, projectID, _ string) ([]finding.Finding, error) {
	return r.ListForTriage(ctx, projectID)
}
func (r *recordingFindings) SetStatus(_ context.Context, id string, t finding.Triage) (finding.Finding, error) {
	r.statuses[id] = t.Status
	return finding.Finding{ID: id, Status: t.Status}, nil
}
func (r *recordingFindings) AcceptBySystem(_ context.Context, _ finding.SystemAcceptance, ids []string) ([]string, error) {
	for _, id := range ids {
		r.statuses[id] = domain.FindingRiskAccepted
	}
	return ids, nil
}
func (r *recordingFindings) SetSeverity(_ context.Context, id string, s domain.Severity) (finding.Finding, error) {
	r.severities[id] = s
	return finding.Finding{ID: id, Severity: s}, nil
}
func (r *recordingFindings) SetCustom(_ context.Context, id string, set map[string]any, unset []string, _, _ string) (map[string]any, error) {
	if r.custom == nil {
		r.custom = map[string]map[string]any{}
	}
	r.custom[id] = maps.Clone(set)
	for _, k := range unset {
		r.custom[id][k] = nil
	}
	return set, nil
}
func (r *recordingFindings) ProjectIDsWithFindings(context.Context) ([]string, error) {
	return []string{"p1"}, nil
}

// acceptingFields is a customChecker that accepts every value except "bad".
type acceptingFields struct{}

func (acceptingFields) Prepare(_ context.Context, _ customfield.Entity, _ string, patch map[string]any, _ bool) (customfield.Change, error) {
	for _, v := range patch {
		if v == "bad" {
			return customfield.Change{}, &customfield.ValidationError{}
		}
	}
	return customfield.Change{Set: patch, Unset: []string{}}, nil
}

// A set_custom_field rule writes its value once: a finding already holding
// it is left alone (idempotent), and a value the field refuses is skipped.
func TestSetCustomFieldAction(t *testing.T) {
	ctx := context.Background()
	rule := Rule{ID: "r1", Name: "owner", Action: ActionSetCustomField, CustomField: "team", CustomValue: "payments"}
	store := newRecording(
		finding.Finding{ID: "unset"},
		finding.Finding{ID: "same", Custom: map[string]any{"team": "payments"}},
		finding.Finding{ID: "other", Custom: map[string]any{"team": "web"}},
	)
	svc := NewService(staticRules{rule}, store, nil).WithCustomFields(acceptingFields{})
	n, err := svc.ApplyToProject(ctx, "p1")
	if err != nil || n != 2 {
		t.Fatalf("applied %d (%v), want 2", n, err)
	}
	if _, ok := store.custom["same"]; ok {
		t.Error("a finding already holding the value was rewritten")
	}
	if store.custom["unset"]["team"] != "payments" || store.custom["other"]["team"] != "payments" {
		t.Errorf("custom writes = %v", store.custom)
	}

	bad := Rule{ID: "r2", Name: "bad", Action: ActionSetCustomField, CustomField: "team", CustomValue: "bad"}
	store = newRecording(finding.Finding{ID: "f"})
	if n, err := NewService(staticRules{bad}, store, nil).WithCustomFields(acceptingFields{}).ApplyToProject(ctx, "p1"); err != nil || n != 0 || len(store.custom) != 0 {
		t.Errorf("an invalid value: applied %d (%v), writes %v; want a skip", n, err, store.custom)
	}
}

// finding.custom and project.custom are readable by expressions, but only
// for defined fields: a misspelled key is refused on save.
func TestExpressionReadsCustomFields(t *testing.T) {
	fields := []customfield.Definition{{Key: "risk_owner", Type: customfield.TypeText}, {Key: "score", Type: customfield.TypeNumber}}
	project := []customfield.Definition{{Key: "tier", Type: customfield.TypeEnum, Options: []string{"gold", "silver"}}}
	schema := FindingSchemaFor(fields, project)
	r := Rule{Name: "r", Action: ActionFalsePositive, Expression: `finding.custom.score >= 5 && project.custom.tier == "gold"`}
	if err := r.Validate(schema); err != nil {
		t.Fatal(err)
	}
	f := finding.Finding{Custom: map[string]any{"score": 7.0}}
	if !r.Matches(f, ProjectFacts{Custom: map[string]any{"tier": "gold"}}) {
		t.Error("custom values should match")
	}
	if r.Matches(f, ProjectFacts{Custom: map[string]any{}}) {
		t.Error("an unset project field must not match")
	}
	if r.Matches(finding.Finding{}, ProjectFacts{Custom: map[string]any{"tier": "gold"}}) {
		t.Error("an unset finding field must not match")
	}
	if err := (&Rule{Name: "r", Action: ActionFalsePositive, Expression: `finding.custom.scor >= 5`}).Validate(schema); err == nil {
		t.Error("an undefined custom field must be rejected on save")
	}
	// Loaded later, after the field was deleted: it matches nothing, not everything.
	stored := Rule{Name: "r", Action: ActionFalsePositive, Expression: `finding.custom.score >= 5`}
	if err := stored.compile(); err != nil || stored.Matches(finding.Finding{}, ProjectFacts{}) {
		t.Errorf("a vanished field must not match (err %v)", err)
	}
}

type staticRules []Rule

func (s staticRules) ListEnabledForProject(context.Context, string) ([]Rule, error) {
	return []Rule(s), nil
}
func (staticRules) RecordHits(context.Context, map[string]int) error { return nil }
func (staticRules) ProjectFacts(context.Context, string) (ProjectFacts, error) {
	return ProjectFacts{Criticality: domain.CriticalityMedium}, nil
}

func TestApplyToProject(t *testing.T) {
	ctx := context.Background()

	t.Run("suppresses matching, leaves others", func(t *testing.T) {
		store := newRecording(
			finding.Finding{ID: "low", Severity: domain.SeverityLow, Status: domain.FindingOpen},
			finding.Finding{ID: "high", Severity: domain.SeverityHigh, Status: domain.FindingOpen},
		)
		rules := staticRules{{Name: "mute-lows", Severities: []domain.Severity{domain.SeverityLow}, Action: ActionFalsePositive}}
		changed, err := NewService(rules, store, nil).ApplyToProject(ctx, "p1")
		if err != nil {
			t.Fatalf("apply: %v", err)
		}
		if changed != 1 || store.statuses["low"] != domain.FindingFalsePositive {
			t.Errorf("changed=%d statuses=%v, want low suppressed only", changed, store.statuses)
		}
		if _, touched := store.statuses["high"]; touched {
			t.Error("high should be untouched")
		}
	})

	t.Run("first matching rule wins", func(t *testing.T) {
		store := newRecording(finding.Finding{ID: "f", Severity: domain.SeverityLow, Status: domain.FindingOpen})
		rules := staticRules{
			{Name: "first", Severities: []domain.Severity{domain.SeverityLow}, Action: ActionWontFix},
			{Name: "second", Severities: []domain.Severity{domain.SeverityLow}, Action: ActionFalsePositive},
		}
		if _, err := NewService(rules, store, nil).ApplyToProject(ctx, "p1"); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if store.statuses["f"] != domain.FindingWontFix {
			t.Errorf("status = %q, want wont_fix (first rule)", store.statuses["f"])
		}
	})

	t.Run("idempotent when already in target state", func(t *testing.T) {
		store := newRecording(finding.Finding{ID: "f", Severity: domain.SeverityLow, Status: domain.FindingFalsePositive})
		rules := staticRules{{Name: "r", Severities: []domain.Severity{domain.SeverityLow}, Action: ActionFalsePositive}}
		changed, _ := NewService(rules, store, nil).ApplyToProject(ctx, "p1")
		if changed != 0 || len(store.statuses) != 0 {
			t.Errorf("changed=%d statuses=%v, want no-op", changed, store.statuses)
		}
	})

	t.Run("set_severity downgrades", func(t *testing.T) {
		store := newRecording(finding.Finding{ID: "f", Severity: domain.SeverityHigh, Status: domain.FindingOpen})
		rules := staticRules{{Name: "downgrade", Scanner: "", Action: ActionSetSeverity, NewSeverity: domain.SeverityLow, Category: domain.CategoryIaC}}
		// finding isn't IaC -> no match
		if changed, _ := NewService(rules, store, nil).ApplyToProject(ctx, "p1"); changed != 0 {
			t.Fatalf("changed=%d, want 0 (category mismatch)", changed)
		}
		// now a matching rule
		rules = staticRules{{Name: "downgrade", Action: ActionSetSeverity, NewSeverity: domain.SeverityLow}}
		if changed, _ := NewService(rules, store, nil).ApplyToProject(ctx, "p1"); changed != 1 || store.severities["f"] != domain.SeverityLow {
			t.Errorf("severities=%v changed, want f->low", store.severities)
		}
	})
}

// TestReachabilityConditions covers the rule that removes most of a dependency
// backlog — "suppress vulnerabilities in dependencies that never ship" — and the
// guard that stops it firing on packages we know nothing about.
func TestReachabilityConditions(t *testing.T) {
	direct, transitive := true, false
	mk := func(dep *bool, scope domain.DepScope) finding.Finding {
		return finding.Finding{Severity: domain.SeverityCritical, DepDirect: dep, DepScope: scope}
	}

	devRule := Rule{Action: ActionFalsePositive, DepScope: domain.DepScopeDev}
	if !devRule.Matches(mk(&direct, domain.DepScopeDev), ProjectFacts{}) {
		t.Error("a dev-scoped dependency must match a dep_scope=dev rule")
	}
	if devRule.Matches(mk(&direct, domain.DepScopeRuntime), ProjectFacts{}) {
		t.Error("a runtime dependency must not match a dev rule")
	}
	// No SBOM data => no scope => the rule must not fire. Auto-suppressing a
	// finding because we're missing information is the one unrecoverable mistake
	// this engine could make.
	if devRule.Matches(mk(nil, domain.DepScopeUnknown), ProjectFacts{}) {
		t.Error("a finding with no reachability data must never be auto-suppressed")
	}

	transRule := Rule{Action: ActionRiskAccepted, DepTransitive: true}
	if !transRule.Matches(mk(&transitive, domain.DepScopeRuntime), ProjectFacts{}) {
		t.Error("a transitive dependency must match a dep_transitive rule")
	}
	if transRule.Matches(mk(&direct, domain.DepScopeRuntime), ProjectFacts{}) {
		t.Error("a direct dependency must not match a dep_transitive rule")
	}
	if transRule.Matches(mk(nil, domain.DepScopeUnknown), ProjectFacts{}) {
		t.Error("unknown directness must not be treated as transitive")
	}

	// Conditions compose: only transitive *and* dev.
	both := Rule{Action: ActionFalsePositive, DepScope: domain.DepScopeDev, DepTransitive: true}
	if both.Matches(mk(&direct, domain.DepScopeDev), ProjectFacts{}) {
		t.Error("a direct dev dependency must not match a transitive+dev rule")
	}
	if !both.Matches(mk(&transitive, domain.DepScopeDev), ProjectFacts{}) {
		t.Error("a transitive dev dependency must match")
	}
}

// TestExploitAndBusinessConditions covers min_epss (inclusive boundary, unknown
// EPSS never matches), kev, and project_criticality.
func TestExploitAndBusinessConditions(t *testing.T) {
	epss := func(v float64) *float64 { return &v }
	cases := []struct {
		name string
		rule Rule
		f    finding.Finding
		crit domain.Criticality
		want bool
	}{
		{"epss above", Rule{MinEPSS: epss(0.5)}, finding.Finding{EPSS: epss(0.51)}, "", true},
		{"epss equal is inclusive", Rule{MinEPSS: epss(0.5)}, finding.Finding{EPSS: epss(0.5)}, "", true},
		{"epss below", Rule{MinEPSS: epss(0.5)}, finding.Finding{EPSS: epss(0.4999)}, "", false},
		{"epss read back from REAL still meets its threshold", Rule{MinEPSS: epss(0.9)}, finding.Finding{EPSS: epss(float64(float32(0.9)))}, "", true},
		{"epss unknown never matches", Rule{MinEPSS: epss(0)}, finding.Finding{}, "", false},
		{"epss zero threshold matches scored zero", Rule{MinEPSS: epss(0)}, finding.Finding{EPSS: epss(0)}, "", true},
		{"epss one", Rule{MinEPSS: epss(1)}, finding.Finding{EPSS: epss(0.99)}, "", false},
		{"kev required and present", Rule{KEV: true}, finding.Finding{KEV: true}, "", true},
		{"kev required and absent", Rule{KEV: true}, finding.Finding{KEV: false}, "", false},
		{"kev unset matches non-kev", Rule{}, finding.Finding{KEV: false}, "", true},
		{"criticality in set", Rule{ProjectCriticality: []domain.Criticality{domain.CriticalityLow, domain.CriticalityMedium}}, finding.Finding{}, domain.CriticalityLow, true},
		{"criticality not in set", Rule{ProjectCriticality: []domain.Criticality{domain.CriticalityLow}}, finding.Finding{}, domain.CriticalityCritical, false},
		{"criticality unknown", Rule{ProjectCriticality: []domain.Criticality{domain.CriticalityLow}}, finding.Finding{}, "", false},
		{"all AND-ed true", Rule{MinEPSS: epss(0.1), KEV: true, ProjectCriticality: []domain.Criticality{domain.CriticalityHigh}},
			finding.Finding{EPSS: epss(0.2), KEV: true}, domain.CriticalityHigh, true},
		{"all AND-ed one false", Rule{MinEPSS: epss(0.1), KEV: true, ProjectCriticality: []domain.Criticality{domain.CriticalityHigh}},
			finding.Finding{EPSS: epss(0.2), KEV: false}, domain.CriticalityHigh, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.rule.Matches(tc.f, ProjectFacts{Criticality: tc.crit}); got != tc.want {
				t.Errorf("Matches = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidateNewConditions(t *testing.T) {
	v := func(f float64) *float64 { return &f }
	base := func() Rule { return Rule{Name: "r", Action: ActionFalsePositive} }
	cases := []struct {
		name string
		mod  func(*Rule)
		ok   bool
	}{
		{"min_epss 0", func(r *Rule) { r.MinEPSS = v(0) }, true},
		{"min_epss 1", func(r *Rule) { r.MinEPSS = v(1) }, true},
		{"min_epss negative", func(r *Rule) { r.MinEPSS = v(-0.01) }, false},
		{"min_epss above 1", func(r *Rule) { r.MinEPSS = v(1.01) }, false},
		{"criticality valid", func(r *Rule) { r.ProjectCriticality = []domain.Criticality{domain.CriticalityCritical} }, true},
		{"criticality invalid", func(r *Rule) { r.ProjectCriticality = []domain.Criticality{"extreme"} }, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := base()
			tc.mod(&r)
			if err := r.Validate(FindingSchema); (err == nil) != tc.ok {
				t.Errorf("Validate err = %v, want ok=%v", err, tc.ok)
			}
		})
	}
}

// countingRules records hits and criticality lookups.
type countingRules struct {
	rules   []Rule
	crit    domain.Criticality
	hits    map[string]int
	lookups int
}

func (c *countingRules) ListEnabledForProject(context.Context, string) ([]Rule, error) {
	return c.rules, nil
}
func (c *countingRules) RecordHits(_ context.Context, hits map[string]int) error {
	for k, v := range hits {
		c.hits[k] += v
	}
	return nil
}
func (c *countingRules) ProjectFacts(context.Context, string) (ProjectFacts, error) {
	c.lookups++
	return ProjectFacts{Criticality: c.crit}, nil
}

func TestHitCountsAndCriticalityLookup(t *testing.T) {
	ctx := context.Background()
	store := newRecording(
		finding.Finding{ID: "a", Severity: domain.SeverityLow, Status: domain.FindingOpen},
		finding.Finding{ID: "b", Severity: domain.SeverityLow, Status: domain.FindingOpen},
		finding.Finding{ID: "c", Severity: domain.SeverityLow, Status: domain.FindingFalsePositive}, // already there
		finding.Finding{ID: "d", Severity: domain.SeverityHigh, Status: domain.FindingOpen},
	)
	src := &countingRules{crit: domain.CriticalityLow, hits: map[string]int{}, rules: []Rule{
		{ID: "r1", Name: "mute lows in low-crit", Severities: []domain.Severity{domain.SeverityLow},
			ProjectCriticality: []domain.Criticality{domain.CriticalityLow}, Action: ActionFalsePositive},
		{ID: "r2", Name: "highs", Severities: []domain.Severity{domain.SeverityHigh}, Action: ActionSetSeverity, NewSeverity: domain.SeverityMedium},
		{ID: "r3", Name: "never", Severities: []domain.Severity{domain.SeverityCritical}, Action: ActionWontFix},
	}}
	changed, err := NewService(src, store, nil).ApplyToScan(ctx, "p1", "s1")
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	if changed != 3 {
		t.Fatalf("changed = %d, want 3", changed)
	}
	if want := map[string]int{"r1": 2, "r2": 1}; !maps.Equal(src.hits, want) {
		t.Errorf("hits = %v, want %v (only actual changes count)", src.hits, want)
	}
	if src.lookups != 1 {
		t.Errorf("criticality lookups = %d, want 1 per run", src.lookups)
	}

	// No rule conditions on criticality -> no lookup at all.
	src2 := &countingRules{hits: map[string]int{}, rules: []Rule{{ID: "x", Name: "x", Action: ActionWontFix}}}
	if _, err := NewService(src2, newRecording(), nil).ApplyToProject(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if src2.lookups != 0 {
		t.Errorf("criticality lookups = %d, want 0", src2.lookups)
	}
}

// TestPreviewMatchesApply: preview lists exactly what apply then changes, and
// mutates nothing itself.
func TestPreviewMatchesApply(t *testing.T) {
	ctx := context.Background()
	mk := func() *recordingFindings {
		return newRecording(
			finding.Finding{ID: "a", ProjectID: "p1", Title: "A", Severity: domain.SeverityLow, Status: domain.FindingOpen},
			finding.Finding{ID: "b", ProjectID: "p1", Title: "B", Severity: domain.SeverityLow, Status: domain.FindingOpen, RuleID: "taken"},
			finding.Finding{ID: "c", ProjectID: "p1", Title: "C", Severity: domain.SeverityHigh, Status: domain.FindingOpen},
		)
	}
	earlier := Rule{ID: "e", Name: "earlier", SortOrder: 0, RuleID: "taken", Action: ActionWontFix}
	candidate := Rule{Name: "draft", SortOrder: 5, Severities: []domain.Severity{domain.SeverityLow}, Action: ActionRiskAccepted}

	store := mk()
	src := &countingRules{hits: map[string]int{}, rules: []Rule{earlier}}
	pv, err := NewService(src, store, nil).Preview(ctx, candidate, "")
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if len(store.statuses) != 0 || len(store.severities) != 0 || len(src.hits) != 0 {
		t.Fatalf("preview mutated: statuses=%v severities=%v hits=%v", store.statuses, store.severities, src.hits)
	}
	want := []PreviewItem{{ID: "a", ProjectID: "p1", Title: "A", Severity: domain.SeverityLow, Status: domain.FindingOpen,
		NewSeverity: domain.SeverityLow, NewStatus: domain.FindingRiskAccepted}}
	if pv.Total != 1 || !slices.Equal(pv.Findings, want) {
		t.Fatalf("preview = %+v, want %+v (b is claimed by the earlier rule)", pv, want)
	}

	// Now make the candidate live and apply: exactly the previewed set changes.
	candidate.ID = "cand"
	applied := mk()
	src.rules = []Rule{earlier, candidate}
	if _, err := NewService(src, applied, nil).ApplyToProject(ctx, "p1"); err != nil {
		t.Fatal(err)
	}
	if src.hits["cand"] != pv.Total || applied.statuses["a"] != domain.FindingRiskAccepted {
		t.Errorf("apply hits=%v statuses=%v, want cand=%d on a", src.hits, applied.statuses, pv.Total)
	}
}

func TestPreviewScopeAndCap(t *testing.T) {
	ctx := context.Background()
	items := make([]finding.Finding, PreviewLimit+5)
	for i := range items {
		items[i] = finding.Finding{ID: string(rune('a'+i%26)) + string(rune('0'+i/26)), ProjectID: "p1", Severity: domain.SeverityLow, Status: domain.FindingOpen}
	}
	store := newRecording(items...)
	src := &countingRules{hits: map[string]int{}}
	svc := NewService(src, store, nil)
	rule := Rule{Name: "all", Action: ActionWontFix}
	pv, err := svc.Preview(ctx, rule, "")
	if err != nil {
		t.Fatal(err)
	}
	if pv.Total != PreviewLimit+5 || len(pv.Findings) != PreviewLimit {
		t.Errorf("total=%d listed=%d, want %d/%d", pv.Total, len(pv.Findings), PreviewLimit+5, PreviewLimit)
	}
	// A project-scoped rule previewed against another project sees nothing.
	other := "p2"
	rule.ProjectID = &other
	if pv, _ := svc.Preview(ctx, rule, "p1"); pv.Total != 0 || pv.Findings == nil {
		t.Errorf("disjoint scope = %+v, want empty non-nil", pv)
	}
}

func TestWithCandidateOrdering(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	live := []Rule{
		{ID: "a", SortOrder: 0, CreatedAt: t0},
		{ID: "b", SortOrder: 1, CreatedAt: t0},
		{ID: "c", SortOrder: 1, CreatedAt: t0.Add(2 * time.Hour)},
		{ID: "d", SortOrder: 2, CreatedAt: t0},
	}
	ids := func(rs []Rule) []string {
		out := []string{}
		for _, r := range rs {
			out = append(out, r.ID)
		}
		return out
	}
	// Unsaved: after its sort_order peers.
	got, at := withCandidate(live, Rule{ID: "", SortOrder: 1})
	if want := []string{"a", "b", "c", "", "d"}; !slices.Equal(ids(got), want) || at != 3 {
		t.Errorf("unsaved = %v at %d, want %v at 3", ids(got), at, want)
	}
	// Stored c, edited in place: replaces itself at its created_at position.
	got, at = withCandidate(live, Rule{ID: "b", SortOrder: 1, CreatedAt: t0})
	if want := []string{"a", "b", "c", "d"}; !slices.Equal(ids(got), want) || at != 1 {
		t.Errorf("stored = %v at %d, want %v at 1", ids(got), at, want)
	}
	if len(live) != 4 || live[1].ID != "b" {
		t.Error("withCandidate mutated live")
	}
}

// A rule's CEL expression holds together with its other conditions; an
// unknown fact (no EPSS, no dependency graph) never matches.
func TestExpressionRules(t *testing.T) {
	epss, cvss, depth := 0.9, 9.8, 3
	direct := false
	scored := finding.Finding{
		Scanner: "trivy", Category: domain.CategorySCA, Severity: domain.SeverityCritical, CVSS: &cvss,
		EPSS: new(float64(float32(epss))), // as read back from the REAL column
		Tags: []string{"internet-facing"}, DepDirect: &direct, DepDepth: &depth, PackageName: "log4j-core",
	}
	bare := finding.Finding{Scanner: "trivy", Severity: domain.SeverityCritical, PackageName: "x"}
	cases := []struct {
		src              string
		crit             domain.Criticality
		onScored, onBare bool
	}{
		{`finding.cvss >= 9 && "internet-facing" in finding.tags`, "", true, false},
		{`finding.epss >= 0.9`, "", true, false}, // float32 storage doesn't break the threshold
		{`finding.dep_direct == false && finding.dep_depth > 2`, "", true, false},
		{`finding.severity == "critical" && project.criticality == "high"`, "high", true, true},
		{`project.criticality == "high"`, "", false, false}, // unknown criticality
		{`finding.epss < 0.01`, "", false, false},           // "unlikely exploited" ≠ "not scored"
	}
	for _, c := range cases {
		r := Rule{Name: "r", Action: ActionFalsePositive, Expression: c.src}
		if err := r.Validate(FindingSchema); err != nil {
			t.Fatalf("%s: %v", c.src, err)
		}
		if got := r.Matches(scored, ProjectFacts{Criticality: c.crit}); got != c.onScored {
			t.Errorf("%s on the scored finding = %v, want %v", c.src, got, c.onScored)
		}
		if got := r.Matches(bare, ProjectFacts{Criticality: c.crit}); got != c.onBare {
			t.Errorf("%s on the bare finding = %v, want %v", c.src, got, c.onBare)
		}
	}
	// Combined with a fixed condition: both must hold.
	r := Rule{Name: "r", Action: ActionFalsePositive, Scanner: "grype", Expression: `finding.cvss >= 9`}
	if err := r.Validate(FindingSchema); err != nil || r.Matches(scored, ProjectFacts{}) {
		t.Errorf("expression + scanner mismatch matched (err %v)", err)
	}
	if err := (&Rule{Name: "r", Action: ActionFalsePositive, Expression: `finding.cvs >= 9`}).Validate(FindingSchema); err == nil {
		t.Error("a misspelled field must be rejected on save")
	}
}
