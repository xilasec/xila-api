package vulnmatch

import (
	"context"
	"slices"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

func mustRule(t *testing.T, r FeedRule) FeedRule {
	t.Helper()
	r.Enabled = true
	if err := r.Validate(); err != nil {
		t.Fatalf("validate %q: %v", r.Name, err)
	}
	return r
}

func TestFeedRulesPrecedence(t *testing.T) {
	cvss := 9.1
	vulns := map[string][]Vuln{
		"pkg:npm/%40babel/core@7.0.0": {
			{ID: "GHSA-aaaa", Aliases: []string{"CVE-2019-1"}, Severity: domain.SeverityHigh, CVSS: &cvss, Sources: []string{SourceOSV}},
			{ID: "GHSA-bbbb", Severity: domain.SeverityLow, Sources: []string{SourceGitHub}},
		},
		"pkg:maven/org.apache/log4j@1": {{ID: "CVE-2021-44228", Sources: []string{SourcePrivate}}},
	}
	rules := []FeedRule{
		mustRule(t, FeedRule{ID: "1", Name: "mute old CVEs", IDGlob: "cve-2019-*", Action: FeedMute}),
		mustRule(t, FeedRule{ID: "2", Name: "babel critical", PackageGlob: "@babel/*", CVSSMin: new(9.0), Action: FeedSetSeverity, Severity: domain.SeverityCritical}),
		mustRule(t, FeedRule{ID: "3", Name: "npm low", Ecosystems: []string{"NPM"}, Action: FeedSetSeverity, Severity: domain.SeverityInfo}),
		mustRule(t, FeedRule{ID: "4", Name: "tag github", Sources: []string{"github"}, Action: FeedAddTags, Tags: []string{"From-GH"}}),
		mustRule(t, FeedRule{ID: "5", Name: "tag cel", Expression: `advisory.severity == null && pkg.ecosystem == "maven"`, Action: FeedAddTags, Tags: []string{"unscored"}}),
		mustRule(t, FeedRule{ID: "6", Name: "tag npm", Ecosystems: []string{"npm"}, Action: FeedAddTags, Tags: []string{"js"}}),
	}
	out := applyFeedRules(context.Background(), rules, vulns)

	babel := out["pkg:npm/%40babel/core@7.0.0"]
	// GHSA-aaaa's alias CVE-2019-1 is muted: gone for this package.
	if len(babel) != 1 || babel[0].ID != "GHSA-bbbb" {
		t.Fatalf("babel = %+v, want only GHSA-bbbb", babel)
	}
	b := babel[0]
	// No CVSS: "babel critical" can't match an unknown score; the next
	// set_severity rule decides. Tags from every add_tags rule, normalized.
	if b.Severity != domain.SeverityInfo || b.FeedSeverityFrom != domain.SeverityLow {
		t.Errorf("severity = %q (from %q)", b.Severity, b.FeedSeverityFrom)
	}
	if !slices.Equal(b.Tags, []string{"from-gh", "js"}) {
		t.Errorf("tags = %v", b.Tags)
	}
	if ids := refIDs(b.FeedRules); !slices.Equal(ids, []string{"3", "4", "6"}) {
		t.Errorf("acting rules = %v", ids)
	}
	log4j := out["pkg:maven/org.apache/log4j@1"]
	if len(log4j) != 1 || !slices.Equal(log4j[0].Tags, []string{"unscored"}) || log4j[0].Severity != "" {
		t.Errorf("log4j = %+v", log4j)
	}
	if len(vulns["pkg:npm/%40babel/core@7.0.0"]) != 2 || vulns["pkg:npm/%40babel/core@7.0.0"][1].Severity != domain.SeverityLow {
		t.Error("input map modified")
	}
}

func TestFeedRuleFirstSeverityWins(t *testing.T) {
	cvss := 9.5
	vulns := map[string][]Vuln{"pkg:npm/%40babel/core@7": {{ID: "GHSA-x", CVSS: &cvss}}}
	rules := []FeedRule{
		mustRule(t, FeedRule{ID: "a", Name: "a", PackageGlob: "@babel/*", CVSSMin: new(9.0), Action: FeedSetSeverity, Severity: domain.SeverityCritical}),
		mustRule(t, FeedRule{ID: "b", Name: "b", Action: FeedSetSeverity, Severity: domain.SeverityLow}),
	}
	got := applyFeedRules(context.Background(), rules, vulns)["pkg:npm/%40babel/core@7"][0]
	if got.Severity != domain.SeverityCritical || !slices.Equal(refIDs(got.FeedRules), []string{"a"}) {
		t.Errorf("got %q by %v", got.Severity, got.FeedRules)
	}
}

func TestFeedRuleValidation(t *testing.T) {
	bad := []FeedRule{
		{Name: "", Action: FeedMute},
		{Name: "x", Action: "delete"},
		{Name: "x", Action: FeedSetSeverity},
		{Name: "x", Action: FeedAddTags},
		{Name: "x", Action: FeedAddTags, Tags: []string{"Bad Tag!"}},
		{Name: "x", Action: FeedMute, Sources: []string{"nope"}},
		{Name: "x", Action: FeedMute, IDGlob: "[a-"},
		{Name: "x", Action: FeedMute, CVSSMin: new(8.0), CVSSMax: new(7.0)},
		{Name: "x", Action: FeedMute, Expression: "advisory.nope == 1"},
		{Name: "x", Action: FeedMute, Expression: "advisory.id"},
	}
	for i, r := range bad {
		if err := r.Validate(); err == nil {
			t.Errorf("rule %d accepted: %+v", i, r)
		}
	}
}

func refIDs(refs []FeedRuleRef) []string {
	out := []string{}
	for _, r := range refs {
		out = append(out, r.ID)
	}
	return out
}
