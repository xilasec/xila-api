package vulnpolicy

import (
	"context"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

func mustPolicy(t *testing.T, p Policy) Policy {
	t.Helper()
	if err := p.Validate(Schema); err != nil {
		t.Fatalf("validate: %v", err)
	}
	return p
}

func TestValidateRequiresNameConditionAndEffect(t *testing.T) {
	base := Draft()
	base.Condition = `vulnerability.kev == true`
	base.Analysis = &Analysis{State: AnalysisNotAffected}

	cases := []struct {
		name string
		mod  func(p *Policy)
	}{
		{"missing name", func(p *Policy) { p.Name = "" }},
		{"missing condition", func(p *Policy) { p.Condition = "" }},
		{"no analysis or rating", func(p *Policy) { p.Analysis, p.Rating = nil, nil }},
		{"invalid analysis state", func(p *Policy) { p.Analysis = &Analysis{State: "bogus"} }},
		{"invalid scope", func(p *Policy) { p.Scope = "bogus" }},
		{"projects scope without ids", func(p *Policy) { p.Scope = ScopeProjects }},
		{"tag scope without tag", func(p *Policy) { p.Scope = ScopeTag }},
		{"invalid mode", func(p *Policy) { p.Mode = "bogus" }},
		{"rating without severity", func(p *Policy) { p.Analysis = nil; p.Rating = &Rating{} }},
		{"misspelled fact", func(p *Policy) { p.Condition = "vulnerability.not_a_real_field == true" }},
		{"from after until", func(p *Policy) {
			from, until := time.Now(), time.Now().Add(-time.Hour)
			p.ValidFrom, p.ValidUntil = &from, &until
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := base
			p.Name = "test"
			tc.mod(&p)
			if err := p.Validate(Schema); err == nil {
				t.Errorf("expected a validation error")
			}
		})
	}
}

func TestValidateAcceptsRatingOnly(t *testing.T) {
	p := Draft()
	p.Name = "downgrade"
	p.Condition = `vulnerability.epss < 0.01`
	p.Rating = &Rating{Severity: domain.SeverityLow}
	if err := p.Validate(Schema); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestAppliesNowValidityWindow(t *testing.T) {
	now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
	from := now.Add(-time.Hour)
	until := now.Add(time.Hour)

	p := mustPolicy(t, Policy{Name: "n", Enabled: true, Scope: ScopeGlobal, Mode: ModeApply,
		Condition: "true", Analysis: &Analysis{State: AnalysisNotAffected}, ValidFrom: &from, ValidUntil: &until})
	if !p.AppliesNow(now, "proj", nil) {
		t.Error("expected policy to apply inside its window")
	}
	if p.AppliesNow(now.Add(-2*time.Hour), "proj", nil) {
		t.Error("expected policy not to apply before valid_from")
	}
	if p.AppliesNow(now.Add(2*time.Hour), "proj", nil) {
		t.Error("expected policy not to apply after valid_until (exclusive)")
	}
	if p.AppliesNow(until, "proj", nil) {
		t.Error("valid_until should be exclusive")
	}

	p.Enabled = false
	if p.AppliesNow(now, "proj", nil) {
		t.Error("a disabled policy must never apply")
	}
}

func TestAppliesNowScope(t *testing.T) {
	now := time.Now()
	global := mustPolicy(t, Policy{Name: "g", Enabled: true, Scope: ScopeGlobal, Mode: ModeApply,
		Condition: "true", Analysis: &Analysis{State: AnalysisNotAffected}})
	if !global.AppliesNow(now, "any-project", nil) {
		t.Error("global scope must cover every project")
	}

	projects := mustPolicy(t, Policy{Name: "p", Enabled: true, Scope: ScopeProjects, ProjectIDs: []string{"p1"}, Mode: ModeApply,
		Condition: "true", Analysis: &Analysis{State: AnalysisNotAffected}})
	if !projects.AppliesNow(now, "p1", nil) || projects.AppliesNow(now, "p2", nil) {
		t.Error("projects scope must cover only its listed projects")
	}

	tagged := mustPolicy(t, Policy{Name: "t", Enabled: true, Scope: ScopeTag, Tag: "pci", Mode: ModeApply,
		Condition: "true", Analysis: &Analysis{State: AnalysisNotAffected}})
	if !tagged.AppliesNow(now, "x", []string{"pci", "other"}) || tagged.AppliesNow(now, "x", []string{"other"}) {
		t.Error("tag scope must cover only projects carrying that tag")
	}
}

func TestElectPriorityResolution(t *testing.T) {
	now := time.Now()
	doc := map[string]any{
		"component":     map[string]any{"name": "x", "version": "1", "purl": nil, "group": nil, "license": nil, "scope": nil, "direct": nil},
		"vulnerability": map[string]any{"id": "CVE-1", "aliases": []any{}, "severity": "high", "cvss": nil, "epss": nil, "kev": true, "cwes": []any{}, "published": nil},
		"project":       map[string]any{"name": "p", "tags": []any{}, "criticality": nil, "custom": map[string]any{}},
	}

	low := mustPolicy(t, Policy{Name: "low", Enabled: true, Scope: ScopeGlobal, Mode: ModeApply, Priority: 1,
		Condition: "vulnerability.kev == true", Analysis: &Analysis{State: AnalysisInTriage},
		CreatedAt: now.Add(-time.Hour)})
	high := mustPolicy(t, Policy{Name: "high", Enabled: true, Scope: ScopeGlobal, Mode: ModeApply, Priority: 10,
		Condition: "vulnerability.kev == true", Analysis: &Analysis{State: AnalysisNotAffected},
		CreatedAt: now})
	logOnly := mustPolicy(t, Policy{Name: "log", Enabled: true, Scope: ScopeGlobal, Mode: ModeLog, Priority: 100,
		Condition: "vulnerability.kev == true", Analysis: &Analysis{State: AnalysisExploitable},
		CreatedAt: now})

	elected, ok := Elect(context.Background(), []Policy{low, high, logOnly}, now, "p", nil, doc)
	if !ok || elected.Name != "high" {
		t.Fatalf("expected the higher-priority apply-mode policy to win, got %+v ok=%v", elected, ok)
	}

	// Tie-break: oldest first.
	older := mustPolicy(t, Policy{Name: "older", Enabled: true, Scope: ScopeGlobal, Mode: ModeApply, Priority: 10,
		Condition: "vulnerability.kev == true", Analysis: &Analysis{State: AnalysisFalsePositive},
		CreatedAt: now.Add(-time.Minute)})
	elected, ok = Elect(context.Background(), []Policy{high, older}, now, "p", nil, doc)
	if !ok || elected.Name != "older" {
		t.Fatalf("expected the older same-priority policy to win the tie, got %+v ok=%v", elected, ok)
	}

	// No matching condition: never elected.
	none := mustPolicy(t, Policy{Name: "none", Enabled: true, Scope: ScopeGlobal, Mode: ModeApply, Priority: 1000,
		Condition: "vulnerability.kev == false", Analysis: &Analysis{State: AnalysisNotAffected}})
	if _, ok := Elect(context.Background(), []Policy{none}, now, "p", nil, doc); ok {
		t.Error("a non-matching policy must never be elected")
	}

	// Outside its validity window: never elected even though it matches.
	expiredUntil := now.Add(-time.Minute)
	expired := mustPolicy(t, Policy{Name: "expired", Enabled: true, Scope: ScopeGlobal, Mode: ModeApply, Priority: 1000,
		Condition: "vulnerability.kev == true", Analysis: &Analysis{State: AnalysisNotAffected}, ValidUntil: &expiredUntil})
	if _, ok := Elect(context.Background(), []Policy{expired}, now, "p", nil, doc); ok {
		t.Error("an expired policy must never be elected")
	}
}

func TestPairDocFacts(t *testing.T) {
	cwe, direct, cvss, epss := 79, true, 7.5, 0.42
	f := finding.Finding{
		PackageName: "core", PackageVersion: "1.2.3",
		Purl: "pkg:npm/@angular/core@1.2.3",
		CVE:  []string{"CVE-2024-1"}, RuleID: "GHSA-xxxx", CWE: &cwe, CVSS: &cvss, EPSS: &epss, KEV: true,
		Severity: domain.SeverityHigh, DepDirect: &direct, DepScope: domain.DepScope("required"),
		Metadata: map[string]any{"license": "MIT"},
	}
	doc := pairDoc(f, ProjectFacts{Name: "demo", Tags: []string{"pci"}, Criticality: domain.Criticality("high"), Custom: map[string]any{}})

	comp := doc["component"].(map[string]any)
	if comp["name"] != "core" || comp["group"] != "@angular" || comp["license"] != "MIT" || comp["direct"] != true {
		t.Errorf("component facts wrong: %+v", comp)
	}
	vuln := doc["vulnerability"].(map[string]any)
	if vuln["id"] != "CVE-2024-1" || vuln["kev"] != true || vuln["severity"] != "high" {
		t.Errorf("vulnerability facts wrong: %+v", vuln)
	}
	aliasesGot := vuln["aliases"].([]any)
	if len(aliasesGot) != 2 || aliasesGot[0] != "CVE-2024-1" || aliasesGot[1] != "GHSA-xxxx" {
		t.Errorf("aliases wrong: %+v", aliasesGot)
	}
	if vuln["published"] != nil {
		t.Errorf("published must always be unknown (nil), got %v", vuln["published"])
	}
}

func TestPurlGroupName(t *testing.T) {
	cases := []struct{ purl, group, name string }{
		{"pkg:npm/@angular/core@1.2.3", "@angular", "core"},
		{"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "org.apache.logging.log4j", "log4j-core"},
		{"pkg:npm/lodash@4.17.21", "", "lodash"},
		{"", "", ""},
		{"not-a-purl", "", ""},
	}
	for _, c := range cases {
		group, name := purlGroupName(c.purl)
		if group != c.group || name != c.name {
			t.Errorf("purlGroupName(%q) = %q, %q; want %q, %q", c.purl, group, name, c.group, c.name)
		}
	}
}

func TestUnknownFactNeverMatches(t *testing.T) {
	p := mustPolicy(t, Policy{Name: "n", Enabled: true, Scope: ScopeGlobal, Mode: ModeApply,
		Condition: "vulnerability.cvss >= 9.0", Analysis: &Analysis{State: AnalysisNotAffected}})
	f := finding.Finding{PackageName: "x", Severity: domain.SeverityHigh} // no CVSS
	doc := pairDoc(f, ProjectFacts{Custom: map[string]any{}})
	if p.Match(context.Background(), doc) {
		t.Error("an unknown CVSS fact must never satisfy a >= comparison")
	}
}
