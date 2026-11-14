package fixplan

import (
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

func TestTarget(t *testing.T) {
	cases := []struct {
		eco, installed, fixed, want string
	}{
		{"maven", "2.14.1", "2.15.0", "2.15.0"},
		// Trivy lists one fix per release line: the smallest newer one wins.
		{"maven", "2.14.1", "2.3.1, 2.12.2, 2.15.0", "2.15.0"},
		{"maven", "2.11.0", "2.3.1, 2.12.2, 2.15.0", "2.12.2"},
		// Constraint syntax and stray separators.
		{"npm", "4.17.15", ">=4.17.21", "4.17.21"},
		{"npm", "1.2.3", "1.2.10 || 2.0.1", "1.2.10"}, // numeric, not lexical: 1.2.10 > 1.2.9
		{"pypi", "1.0", "1.0.post1", "1.0.post1"},
		{"pypi", "2.0", "2.0rc1", ""}, // a pre-release of what's installed isn't an upgrade
		// Nothing newer, or nothing at all.
		{"npm", "3.0.0", "2.5.1", ""},
		{"npm", "1.0.0", "", ""},
		{"npm", "1.0.0", "not fixed", ""},
		// No installed version known: the smallest listed fix.
		{"npm", "", "2.0.0, 1.5.0", "1.5.0"},
	}
	for _, c := range cases {
		if got := Target(c.eco, c.installed, c.fixed); got != c.want {
			t.Errorf("Target(%s, %q, %q) = %q, want %q", c.eco, c.installed, c.fixed, got, c.want)
		}
	}
}

func TestPlan(t *testing.T) {
	epss := func(f float64) *float64 { return &f }
	direct := true
	cands := []finding.FixCandidate{
		// log4j: two findings on one version; the upgrade must fix both.
		{ID: "a", ProjectID: "p", PackageName: "log4j-core", PackageVersion: "2.14.1", FixedVersion: "2.15.0",
			Purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", Severity: domain.SeverityCritical, Priority: 90, KEV: true, EPSS: epss(0.97), DepDirect: &direct},
		{ID: "b", ProjectID: "p", PackageName: "log4j-core", PackageVersion: "2.14.1", FixedVersion: "2.12.4, 2.17.1",
			Purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", Severity: domain.SeverityHigh, Priority: 40, EPSS: epss(0.2)},
		// lodash: one cheap fix.
		{ID: "c", ProjectID: "p", PackageName: "lodash", PackageVersion: "4.17.15", FixedVersion: "4.17.21",
			Purl: "pkg:npm/lodash@4.17.15", Severity: domain.SeverityMedium, Priority: 10},
		// The same lodash version in another project is a separate upgrade.
		{ID: "d", ProjectID: "q", PackageName: "lodash", PackageVersion: "4.17.15", FixedVersion: "4.17.21",
			Purl: "pkg:npm/lodash@4.17.15", Severity: domain.SeverityMedium, Priority: 12},
		// No fix published.
		{ID: "e", ProjectID: "p", PackageName: "jq", PackageVersion: "1.6", Severity: domain.SeverityLow, Priority: 2},
		{ID: "f", ProjectID: "p", PackageName: "jq", PackageVersion: "1.6", FixedVersion: "1.5", Severity: domain.SeverityLow, Priority: 2},
	}
	fixes, noFix := Plan(cands)
	if len(fixes) != 3 {
		t.Fatalf("fixes = %+v", fixes)
	}
	log4j := fixes[0]
	if log4j.Package != "log4j-core" || log4j.UpgradeTo != "2.17.1" || log4j.Closes != 2 || log4j.KEV != 1 ||
		log4j.PriorityRemoved != 130 || *log4j.MaxEPSS != 0.97 || log4j.Ecosystem != "maven" ||
		log4j.BySeverity[domain.SeverityCritical] != 1 || log4j.BySeverity[domain.SeverityHigh] != 1 {
		t.Errorf("log4j fix = %+v", log4j)
	}
	if fixes[1].ProjectID != "q" || fixes[2].ProjectID != "p" || fixes[2].UpgradeTo != "4.17.21" {
		t.Errorf("lodash fixes not ranked by priority removed / kept per project: %+v %+v", fixes[1], fixes[2])
	}
	if noFix.Findings != 2 || noFix.Packages != 1 || noFix.BySeverity[domain.SeverityLow] != 2 {
		t.Errorf("no_fix = %+v", noFix)
	}
}

func TestChangesGroupsEveryKind(t *testing.T) {
	cands := []finding.FixCandidate{
		// Distro packages of one image: one rebuild with BaseImages, upgrades without.
		{ID: "os1", ProjectID: "p", PackageName: "libc6", PackageVersion: "2.36-9+deb12u1", FixedVersion: "2.36-9+deb12u3",
			Purl: "pkg:deb/debian/libc6@2.36-9+deb12u1", Image: "python:3.11-slim", PkgClass: "os-pkgs", OS: "debian 12.5",
			Severity: domain.SeverityHigh, Priority: 7},
		{ID: "os2", ProjectID: "p", PackageName: "libssl3", PackageVersion: "3.0.11-1~deb12u2", FixedVersion: "3.0.13-1~deb12u1",
			Purl: "pkg:deb/debian/libssl3@3.0.11-1~deb12u2", Image: "python:3.11-slim", OS: "debian 12.5",
			Severity: domain.SeverityMedium, Priority: 3},
		// A language package in the same image is still an upgrade.
		{ID: "py", ProjectID: "p", PackageName: "pip", PackageVersion: "23.2.1", FixedVersion: "23.3",
			Purl: "pkg:pypi/pip@23.2.1", Image: "python:3.11-slim", PkgClass: "lang-pkgs", Severity: domain.SeverityMedium, Priority: 3},
		// IaC: same rule + file groups; another file doesn't.
		{ID: "k1", ProjectID: "p", Category: domain.CategoryIaC, RuleID: "r1", Title: "RBAC Wildcard", FilePath: "rbac.yaml", Severity: domain.SeverityMedium},
		{ID: "k2", ProjectID: "p", Category: domain.CategoryIaC, RuleID: "r1", Title: "RBAC Wildcard", FilePath: "rbac.yaml", Severity: domain.SeverityHigh},
		{ID: "k3", ProjectID: "p", Category: domain.CategoryIaC, RuleID: "r1", Title: "RBAC Wildcard", FilePath: "other.yaml", Severity: domain.SeverityLow},
		// Cloud with a named resource.
		{ID: "c1", ProjectID: "p", Category: domain.CategoryCloud, RuleID: "s3_encryption", Title: "S3 not encrypted",
			FilePath: "main.tf", Resource: "aws_s3_bucket.logs", Severity: domain.SeverityHigh},
		// SAST + secret in one file: one fix per file.
		{ID: "s1", ProjectID: "p", Category: domain.CategorySAST, RuleID: "a", FilePath: "app.py", Severity: domain.SeverityHigh},
		{ID: "s2", ProjectID: "p", Category: domain.CategorySecret, RuleID: "b", FilePath: "app.py", Severity: domain.SeverityCritical},
		{ID: "s3", ProjectID: "p", Category: domain.CategorySAST, RuleID: "a", FilePath: "db.py", Severity: domain.SeverityLow},
		// DAST: per rule.
		{ID: "d1", ProjectID: "p", Category: domain.CategoryDAST, RuleID: "hsts", Title: "HSTS missing", FilePath: "https://a/x", Severity: domain.SeverityLow},
		{ID: "d2", ProjectID: "p", Category: domain.CategoryDAST, RuleID: "hsts", Title: "HSTS missing", FilePath: "https://a/y", Severity: domain.SeverityLow},
		// Left out: licence findings, SAST without a file.
		{ID: "l1", ProjectID: "p", Category: domain.CategoryLicense, RuleID: "GPL"},
		{ID: "x1", ProjectID: "p", Category: domain.CategorySAST, RuleID: "a"},
	}
	byKind := func(cs []Change) map[Kind][]Change {
		m := map[Kind][]Change{}
		for _, c := range cs {
			m[c.Kind] = append(m[c.Kind], c)
		}
		return m
	}
	got := byKind(must(Changes(cands, Options{BaseImages: true})))
	if bi := got[KindBaseImage]; len(bi) != 1 || bi[0].Closes != 2 || bi[0].Key != "python:3.11-slim|debian 12.5" ||
		bi[0].Title != "Rebuild python:3.11-slim on a patched base image (debian 12.5)" || bi[0].MaxSeverity != domain.SeverityHigh {
		t.Errorf("base image changes = %+v", bi)
	}
	if pu := got[KindPackageUpgrade]; len(pu) != 1 || pu[0].Package != "pip" || pu[0].Target != "23.3" {
		t.Errorf("package upgrades = %+v", pu)
	}
	iac := got[KindIaCRule]
	if len(iac) != 3 {
		t.Fatalf("iac changes = %+v", iac)
	}
	closes := map[string]int{}
	for _, c := range iac {
		closes[c.Key] = c.Closes
	}
	if closes["r1|rbac.yaml|"] != 2 || closes["r1|other.yaml|"] != 1 || closes["s3_encryption|main.tf|aws_s3_bucket.logs"] != 1 {
		t.Errorf("iac grouping = %v", closes)
	}
	code := got[KindCodeLocation]
	if len(code) != 2 || code[0].Key != "app.py" || code[0].Closes != 2 || code[0].MaxSeverity != domain.SeverityCritical {
		t.Errorf("code changes = %+v", code)
	}
	if cfg := got[KindConfig]; len(cfg) != 1 || cfg[0].Key != "hsts" || cfg[0].Closes != 2 {
		t.Errorf("config changes = %+v", cfg)
	}

	// Without BaseImages (the fix plan) the distro packages are upgrades —
	// where their versions order (libssl3; libc6's "+deb12u" suffix doesn't).
	plain := byKind(must(Changes(cands, Options{})))
	if len(plain[KindBaseImage]) != 0 || len(plain[KindPackageUpgrade]) != 2 {
		t.Errorf("fix-plan grouping = %+v", plain)
	}
}

func must(cs []Change, _ NoFix) []Change { return cs }
