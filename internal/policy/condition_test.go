package policy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/license"
)

var now = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// groups is a fake license-group resolver.
func groups(ref string) ([]string, error) {
	switch ref {
	case "category:Copyleft":
		return []string{"GPL-2.0-only", "GPL-3.0-only", "GPL-3.0-or-later", "AGPL-3.0-only"}, nil
	case "approved":
		return []string{"MIT", "Apache-2.0", "BSD-3-Clause"}, nil
	case "deleted":
		return nil, errGroupGone
	}
	return nil, invalid("unknown group %q", ref)
}

// comp builds a component: lic is an SPDX expression ("" = no license).
func comp(t *testing.T, lic string, mod ...func(*Component)) *Component {
	t.Helper()
	c := &Component{
		Name: "lib", Version: "1.2.3", Purl: "pkg:npm/lib@1.2.3", Hashes: map[string]string{}}
	if lic != "" {
		e, err := license.ParseExpression(lic)
		if err != nil {
			t.Fatalf("parse %q: %v", lic, err)
		}
		c.License = e
		c.LicenseExpression = e.String()
		c.LicenseResolved = new(e.Resolved())
	}
	for _, m := range mod {
		m(c)
	}
	return c
}

func cond(subject Subject, op Operator, value string) Condition {
	return Condition{Subject: subject, Operator: op, Value: json.RawMessage(value)}
}

func TestConditions(t *testing.T) {
	sev := func(s domain.Severity) func(*Component) {
		return func(c *Component) { c.MaxSeverity = &s }
	}
	meta := func(m PackageInfo) func(*Component) {
		return func(c *Component) { c.Meta = &m }
	}
	daysAgo := func(n int) *time.Time { return new(now.AddDate(0, 0, -n)) }

	cases := []struct {
		name string
		cond Condition
		c    *Component
		want bool
	}{
		// security
		{"severity at threshold", cond(SubjectSeverity, OpGTE, `"high"`), comp(t, "", sev(domain.SeverityHigh)), true},
		{"severity above threshold", cond(SubjectSeverity, OpGTE, `"high"`), comp(t, "", sev(domain.SeverityCritical)), true},
		{"severity below threshold", cond(SubjectSeverity, OpGTE, `"high"`), comp(t, "", sev(domain.SeverityMedium)), false},
		{"severity without vulnerabilities", cond(SubjectSeverity, OpGTE, `"low"`), comp(t, ""), false},
		{"vulnerability id is (case-insensitive)", cond(SubjectVulnerabilityID, OpIs, `["cve-2021-44228"]`),
			comp(t, "", func(c *Component) { c.VulnIDs = []string{"GHSA-jfh8", "CVE-2021-44228"} }), true},
		{"vulnerability id is: other", cond(SubjectVulnerabilityID, OpIs, `"CVE-2020-1"`),
			comp(t, "", func(c *Component) { c.VulnIDs = []string{"CVE-2021-44228"} }), false},
		{"vulnerability id matches glob", cond(SubjectVulnerabilityID, OpMatches, `"GHSA-*"`),
			comp(t, "", func(c *Component) { c.VulnIDs = []string{"GHSA-jfh8"} }), true},
		{"kev true", cond(SubjectKEV, OpIs, `true`), comp(t, "", func(c *Component) { c.KEV = true }), true},
		{"kev true on non-KEV", cond(SubjectKEV, OpIs, `true`), comp(t, ""), false},
		{"kev_source in, asserted", cond(SubjectKEVSource, OpIn, `["enisa"]`),
			comp(t, "", func(c *Component) { c.KEV, c.KEVSources = true, []string{"cisa", "enisa"} }), true},
		{"kev_source in, other catalog", cond(SubjectKEVSource, OpIn, `"vulncheck"`),
			comp(t, "", func(c *Component) { c.KEV, c.KEVSources = true, []string{"cisa"} }), false},
		{"kev_source on non-KEV", cond(SubjectKEVSource, OpIn, `["cisa"]`), comp(t, ""), false},
		{"epss at threshold", cond(SubjectEPSS, OpGTE, `0.5`), comp(t, "", func(c *Component) { c.EPSS = new(0.5) }), true},
		{"epss below", cond(SubjectEPSS, OpGTE, `0.5`), comp(t, "", func(c *Component) { c.EPSS = new(0.49) }), false},
		{"epss unknown", cond(SubjectEPSS, OpGTE, `0`), comp(t, ""), false},
		{"cwe in", cond(SubjectCWE, OpIn, `[79, 89]`), comp(t, "", func(c *Component) { c.CWEs = []int{89} }), true},
		{"cwe single value", cond(SubjectCWE, OpIn, `502`), comp(t, "", func(c *Component) { c.CWEs = []int{89} }), false},

		// license: `is` denies, judged on the expression's satisfiability
		{"license is: exact id", cond(SubjectLicense, OpIs, `["GPL-3.0-only"]`), comp(t, "GPL-3.0-only"), true},
		{"license is: glob covers or-later", cond(SubjectLicense, OpIs, `["GPL-3.0*"]`), comp(t, "GPL-3.0-or-later"), true},
		{"license is: LGPL is not GPL", cond(SubjectLicense, OpIs, `["GPL-3.0*"]`), comp(t, "LGPL-3.0-only"), false},
		{"license is: OR offers a way out", cond(SubjectLicense, OpIs, `["GPL-3.0*"]`), comp(t, "MIT OR GPL-3.0-only"), false},
		{"license is: AND needs both", cond(SubjectLicense, OpIs, `["GPL-3.0*"]`), comp(t, "MIT AND GPL-3.0-only"), true},
		{"license is: WITH judged by license", cond(SubjectLicense, OpIs, `["GPL-2.0*"]`), comp(t, "GPL-2.0-only WITH Classpath-exception-2.0"), true},
		{"license is: no license is unknown", cond(SubjectLicense, OpIs, `["GPL-3.0*"]`), comp(t, ""), false},
		{"license is_not: allowlist hit", cond(SubjectLicense, OpIsNot, `["MIT", "Apache-2.0"]`), comp(t, "Apache-2.0"), false},
		{"license is_not: allowlist miss", cond(SubjectLicense, OpIsNot, `["MIT", "Apache-2.0"]`), comp(t, "GPL-3.0-only"), true},
		{"license is_not: OR with an allowed branch", cond(SubjectLicense, OpIsNot, `["MIT"]`), comp(t, "MIT OR GPL-3.0-only"), false},
		{"license is_not: AND with a disallowed part", cond(SubjectLicense, OpIsNot, `["MIT"]`), comp(t, "MIT AND GPL-3.0-only"), true},
		{"license_group in category", cond(SubjectLicenseGroup, OpIn, `["category:Copyleft"]`), comp(t, "AGPL-3.0-only"), true},
		{"license_group in: OR way out", cond(SubjectLicenseGroup, OpIn, `"category:Copyleft"`), comp(t, "GPL-2.0-only OR MIT"), false},
		{"license_group not_in approved: yes", cond(SubjectLicenseGroup, OpNotIn, `["approved"]`), comp(t, "BSD-3-Clause"), false},
		{"license_group not_in approved: no", cond(SubjectLicenseGroup, OpNotIn, `["approved"]`), comp(t, "MPL-2.0"), true},
		{"license_group deleted never matches", cond(SubjectLicenseGroup, OpNotIn, `["deleted"]`), comp(t, "MPL-2.0"), false},
		{"license unresolved: unknown id", cond(SubjectLicenseUnresolved, OpIs, `true`),
			comp(t, "", func(c *Component) { c.LicenseResolved = new(false); c.InventoryComponent.License = "Some EULA" }), true},
		{"license unresolved: resolved", cond(SubjectLicenseUnresolved, OpIs, `true`), comp(t, "MIT"), false},
		{"license unresolved: not computed yet", cond(SubjectLicenseUnresolved, OpIs, `true`), comp(t, ""), false},

		// operational
		{"outdated", cond(SubjectOutdated, OpIs, `true`), comp(t, "", meta(PackageInfo{Latest: "2.0.0", Outdated: true})), true},
		{"outdated: up to date", cond(SubjectOutdated, OpIs, `true`), comp(t, "", meta(PackageInfo{Latest: "1.2.3"})), false},
		{"outdated=false: up to date", cond(SubjectOutdated, OpIs, `false`), comp(t, "", meta(PackageInfo{Latest: "1.2.3"})), true},
		{"outdated=false: unknown is not up to date", cond(SubjectOutdated, OpIs, `false`), comp(t, ""), false},
		{"outdated: unknown is not outdated either", cond(SubjectOutdated, OpIs, `true`), comp(t, ""), false},
		{"versions behind at threshold", cond(SubjectVersionsBehind, OpGTE, `3`), comp(t, "", meta(PackageInfo{VersionsBehind: new(3)})), true},
		{"versions behind below", cond(SubjectVersionsBehind, OpGTE, `3`), comp(t, "", meta(PackageInfo{VersionsBehind: new(2)})), false},
		{"versions behind unknown", cond(SubjectVersionsBehind, OpGTE, `1`), comp(t, "", meta(PackageInfo{Outdated: true})), false},
		{"age old", cond(SubjectAge, OpGTE, `365`), comp(t, "", meta(PackageInfo{Published: daysAgo(400)})), true},
		{"age recent", cond(SubjectAge, OpGTE, `365`), comp(t, "", meta(PackageInfo{Published: daysAgo(30)})), false},
		{"age unknown", cond(SubjectAge, OpGTE, `1`), comp(t, "", meta(PackageInfo{})), false},
		{"missing hash any: none", cond(SubjectMissingHash, OpIs, `"any"`), comp(t, ""), true},
		{"missing hash any: has md5", cond(SubjectMissingHash, OpIs, `"any"`),
			comp(t, "", func(c *Component) { c.Hashes = map[string]string{"MD5": "abc"} }), false},
		{"missing hash strong: only sha1", cond(SubjectMissingHash, OpIs, `"strong"`),
			comp(t, "", func(c *Component) { c.Hashes = map[string]string{"SHA-1": "abc"} }), true},
		{"missing hash strong: cyclonedx SHA-256", cond(SubjectMissingHash, OpIs, `"strong"`),
			comp(t, "", func(c *Component) { c.Hashes = map[string]string{"SHA-256": "abc"} }), false},
		{"missing hash strong: spdx SHA512", cond(SubjectMissingHash, OpIs, `"strong"`),
			comp(t, "", func(c *Component) { c.Hashes = map[string]string{"SHA512": "abc"} }), false},
		{"integrity mismatch", cond(SubjectIntegrity, OpIs, `"mismatch"`),
			comp(t, "", func(c *Component) { c.Integrity = "mismatch" }), true},
		{"integrity verified isn't a mismatch", cond(SubjectIntegrity, OpIs, `"mismatch"`),
			comp(t, "", func(c *Component) { c.Integrity = "verified" }), false},
		{"integrity unknown matches neither", cond(SubjectIntegrity, OpIs, `"mismatch"`), comp(t, ""), false},
		{"integrity unknown isn't verified", cond(SubjectIntegrity, OpIs, `"verified"`), comp(t, ""), false},
		{"coordinates name glob", cond(SubjectCoordinates, OpMatches, `{"name":"li*"}`), comp(t, ""), true},
		{"coordinates group+name", cond(SubjectCoordinates, OpMatches, `{"group":"org.apache.*","name":"lib"}`),
			comp(t, "", func(c *Component) { c.Group = "org.apache.logging" }), true},
		{"coordinates group mismatch", cond(SubjectCoordinates, OpMatches, `{"group":"org.apache.*","name":"lib"}`), comp(t, ""), false},
		{"coordinates version range inside", cond(SubjectCoordinates, OpMatches, `{"name":"lib","version":">=1.2.0, <1.10.0"}`), comp(t, ""), true},
		{"coordinates version range numeric order", cond(SubjectCoordinates, OpMatches, `{"version":"<1.10"}`),
			comp(t, "", func(c *Component) { c.Version = "1.9.1" }), true},
		{"coordinates version range outside", cond(SubjectCoordinates, OpMatches, `{"version":">=2.0.0"}`), comp(t, ""), false},
		{"coordinates no_match", cond(SubjectCoordinates, OpNoMatch, `{"name":"other"}`), comp(t, ""), true},
		{"purl glob", cond(SubjectPurl, OpMatches, `["pkg:npm/*"]`), comp(t, ""), true},
		{"purl glob other type", cond(SubjectPurl, OpMatches, `"pkg:maven/*"`), comp(t, ""), false},
		{"purl no_match", cond(SubjectPurl, OpNoMatch, `["pkg:maven/*"]`), comp(t, ""), true},
		{"purl absent is never judged", cond(SubjectPurl, OpNoMatch, `["pkg:maven/*"]`),
			comp(t, "", func(c *Component) { c.Purl = "" }), false},
		{"package type in", cond(SubjectPackageType, OpIn, `["NPM", "pypi"]`), comp(t, ""), true},
		{"package type not_in", cond(SubjectPackageType, OpNotIn, `["npm"]`), comp(t, ""), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cc, err := compile(tc.cond, groups, ComponentSchema)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if got, _ := cc.match(tc.c, now); got != tc.want {
				t.Errorf("match = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestConditionValidation(t *testing.T) {
	bad := []Condition{
		cond("bogus", OpIs, `true`),
		cond(SubjectSeverity, OpIs, `"high"`), // wrong operator
		cond(SubjectSeverity, OpGTE, `"severe"`),
		cond(SubjectSeverity, OpGTE, ``),
		cond(SubjectEPSS, OpGTE, `1.5`),
		cond(SubjectEPSS, OpGTE, `"high"`),
		cond(SubjectCWE, OpIn, `[]`),
		cond(SubjectCWE, OpIn, `[-1]`),
		cond(SubjectLicense, OpIs, `[]`),
		cond(SubjectLicense, OpIs, `[" "]`),
		cond(SubjectLicenseGroup, OpIn, `["no-such-group"]`),
		cond(SubjectKEV, OpIs, `"yes"`),
		cond(SubjectKEVSource, OpIn, `["nvd"]`),
		cond(SubjectKEVSource, OpIn, `[]`),
		cond(SubjectVersionsBehind, OpGTE, `0`),
		cond(SubjectAge, OpGTE, `-3`),
		cond(SubjectMissingHash, OpIs, `"md5"`),
		cond(SubjectIntegrity, OpIs, `"unknown"`),
		cond(SubjectCoordinates, OpMatches, `{}`),
		cond(SubjectCoordinates, OpMatches, `{"version":">="}`),
		cond(SubjectPurl, OpIn, `["pkg:*"]`),
	}
	for _, c := range bad {
		_, err := compile(c, groups, ComponentSchema)
		if _, ok := errors.AsType[*ValidationError](err); !ok {
			t.Errorf("compile(%s %s %s) = %v, want a validation error", c.Subject, c.Operator, c.Value, err)
		}
	}
	// Values are normalized for storage: a single string becomes a list.
	cc, err := compile(cond(SubjectLicense, OpIs, `" GPL-3.0* "`), groups, ComponentSchema)
	if err != nil || string(cc.Value) != `["GPL-3.0*"]` {
		t.Errorf("normalized value = %s (%v), want [\"GPL-3.0*\"]", cc.Value, err)
	}
}

func TestPolicyValidation(t *testing.T) {
	valid := func() Policy {
		p := Draft()
		p.Name = "p"
		p.Conditions = []Condition{cond(SubjectKEV, OpIs, `true`)}
		return p
	}
	for name, mod := range map[string]func(*Policy){
		"no name":            func(p *Policy) { p.Name = " " },
		"no conditions":      func(p *Policy) { p.Conditions = nil },
		"bad operator":       func(p *Policy) { p.Operator = "some" },
		"bad state":          func(p *Policy) { p.ViolationState = "error" },
		"bad versions":       func(p *Policy) { p.Versions = "latest" },
		"bad scope":          func(p *Policy) { p.Scope = "team" },
		"projects but none":  func(p *Policy) { p.Scope = ScopeProjects },
		"projects not uuids": func(p *Policy) { p.Scope, p.ProjectIDs = ScopeProjects, []string{"x"} },
	} {
		p := valid()
		mod(&p)
		if _, err := validate(&p, groups, ComponentSchema); err == nil {
			t.Errorf("%s: validate accepted %+v", name, p)
		}
	}
	p := valid()
	p.ProjectIDs = []string{"0b4f9e5e-0000-4000-8000-000000000001"}
	if _, err := validate(&p, groups, ComponentSchema); err != nil || len(p.ProjectIDs) != 0 {
		t.Errorf("global policy: err %v, project_ids %v — want ok and cleared", err, p.ProjectIDs)
	}
}

func TestPolicyOperatorAndFinding(t *testing.T) {
	p := Draft()
	p.ID, p.Name = "11111111-1111-4111-8111-111111111111", "No risky GPL"
	p.Conditions = []Condition{
		cond(SubjectLicense, OpIs, `["GPL-3.0*"]`),
		cond(SubjectSeverity, OpGTE, `"high"`),
	}
	high := domain.SeverityHigh
	gpl := comp(t, "GPL-3.0-only")
	gplVulnerable := comp(t, "GPL-3.0-only", func(c *Component) { c.MaxSeverity = &high })

	p.Operator = CombineAll
	cp, err := validate(&p, groups, ComponentSchema)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, ok := cp.evaluate(gpl, now); ok {
		t.Error("all: one matching condition of two must not violate")
	}
	matches, ok := cp.evaluate(gplVulnerable, now)
	if !ok || len(matches) != 2 {
		t.Fatalf("all: both match = %v %v, want a violation with 2 matches", ok, matches)
	}
	f := toFinding(cp.Policy, gplVulnerable, matches)
	if f.Category != domain.CategorySCA {
		t.Errorf("mixed license+security violation category = %s, want sca", f.Category)
	}

	p.Operator, p.ViolationState = CombineAny, StateWarn
	cp, _ = validate(&p, groups, ComponentSchema)
	matches, ok = cp.evaluate(gpl, now)
	if !ok || len(matches) != 1 {
		t.Fatalf("any: = %v %v, want a violation with 1 match", ok, matches)
	}
	f = toFinding(cp.Policy, gpl, matches)
	if f.Category != domain.CategoryLicense || f.Severity != domain.SeverityMedium || f.RuleID != p.ID {
		t.Errorf("finding = category %s severity %s rule %s, want license/medium/policy id", f.Category, f.Severity, f.RuleID)
	}
	if f.Title != `Policy "No risky GPL" violated by lib@1.2.3` || f.Purl != gpl.Purl || f.PackageName != "lib" {
		t.Errorf("finding title/package = %q %q %q", f.Title, f.Purl, f.PackageName)
	}
	if !strings.Contains(f.Description, "license GPL-3.0-only") {
		t.Errorf("description %q does not state the license fact", f.Description)
	}
	// Fingerprints are stable per (policy, component version): another version
	// is another violation, a re-evaluation the same one.
	if f.Fingerprint != fingerprint(p.ID, "pkg:npm/lib@1.2.3") ||
		f.Fingerprint == toFinding(cp.Policy, comp(t, "GPL-3.0-only", func(c *Component) { c.Purl = "pkg:npm/lib@2.0.0" }), matches).Fingerprint {
		t.Error("fingerprint is not per (policy, purl)")
	}
	if StateFail.Severity() != domain.SeverityHigh || StateInfo.Severity() != domain.SeverityLow {
		t.Error("violation state → severity mapping changed")
	}
}

// A policy covers a project when its scope does, the project has an included
// tag (when any are set), and none of the excluded ones.
func TestPolicyTagScope(t *testing.T) {
	global := Policy{Enabled: true, Scope: ScopeGlobal}
	listed := Policy{Enabled: true, Scope: ScopeProjects, ProjectIDs: []string{"a"}}
	with := func(p Policy, include, exclude []string) Policy {
		p.IncludeTags, p.ExcludeTags = include, exclude
		return p
	}
	for _, tc := range []struct {
		name    string
		p       Policy
		project string
		tags    []string
		want    bool
	}{
		{"global, no tags set", global, "x", nil, true},
		{"every project except internal-tool", with(global, nil, []string{"internal-tool"}), "x", []string{"web"}, true},
		{"…not the internal tool", with(global, nil, []string{"internal-tool"}), "x", []string{"web", "internal-tool"}, false},
		{"include: has one", with(global, []string{"pci", "sox"}, nil), "x", []string{"sox"}, true},
		{"include: has none", with(global, []string{"pci"}, nil), "x", []string{"web"}, false},
		{"include: untagged project", with(global, []string{"pci"}, nil), "x", nil, false},
		{"include and exclude", with(global, []string{"pci"}, []string{"legacy"}), "x", []string{"pci", "legacy"}, false},
		{"project list still applies", with(listed, []string{"pci"}, nil), "b", []string{"pci"}, false},
		{"listed and tagged", with(listed, []string{"pci"}, nil), "a", []string{"pci"}, true},
		{"disabled", Policy{Scope: ScopeGlobal}, "x", nil, false},
	} {
		if got := tc.p.AppliesTo(tc.project, tc.tags); got != tc.want {
			t.Errorf("%s: AppliesTo = %v, want %v", tc.name, got, tc.want)
		}
	}
}
