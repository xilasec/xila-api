package scanner

import (
	"slices"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures from DefectDojo unittests/scans/sonarqube:
//
//	sonarqube_issues.json   ← findings_over_api.json
//	sonarqube_hotspots.json ← findings_over_api_hotspots.json
//	sonarqube_empty.json    ← findings_over_api_empty.json

func TestSonarQubeIssues(t *testing.T) {
	out := parseFixture(t, NewSonarQube(), "sonarqube_issues.json")
	// 5 issues: one BUG and one CODE_SMELL are skipped; of the 3 VULNERABILITY
	// issues, two are the same rule on the same package (package:1.1.2) and fold.
	if len(out) != 2 {
		t.Fatalf("findings = %d, want 2: %+v", len(out), out)
	}
	for _, f := range out {
		if f.RuleID != "OWASP:UsingComponentWithKnownVulnerability" {
			t.Errorf("non-security issue imported: %s", f.RuleID)
		}
	}
	pkg := out[0]
	if pkg.Package != "package:1.1.2" || pkg.Severity != domain.SeverityMedium ||
		!slices.Equal(pkg.CVE, []string{"CVE-2024-2529"}) || pkg.CWE == nil || *pkg.CWE != 120 ||
		pkg.CVSS == nil || *pkg.CVSS != 6.4 || pkg.FilePath != "" || pkg.Category != domain.CategorySCA {
		t.Errorf("package finding = %+v", pkg)
	}
	if !strings.Contains(pkg.Description, "GHSA-frr2-c345-p7c2") || pkg.Metadata["occurrences"] != 2 {
		t.Errorf("folded GHSA issue missing: %q %v", pkg.Description, pkg.Metadata)
	}
	nimbus := out[1]
	if nimbus.Package != "nimbus-jose-jwt-9.24.4.jar" || nimbus.Severity != domain.SeverityHigh ||
		!slices.Equal(nimbus.CVE, []string{"CVE-2023-52428"}) || nimbus.CVSS == nil || *nimbus.CVSS != 7.5 {
		t.Errorf("nimbus finding = %+v", nimbus)
	}
}

func TestSonarQubeHotspots(t *testing.T) {
	out := parseFixture(t, NewSonarQube(), "sonarqube_hotspots.json")
	if len(out) != 4 {
		t.Fatalf("findings = %d, want 4", len(out))
	}
	xss := findRule(t, out, "typescript:7777")
	if xss.Severity != domain.SeverityHigh || xss.FilePath != "src/app/component.asdf" || xss.Line == nil || *xss.Line != 47 ||
		xss.Title != "Make sure disabling asdfbuilt-in sanitization is safe here." || xss.Category != domain.CategorySAST ||
		xss.Metadata["security_category"] != "xss" {
		t.Errorf("xss hotspot = %+v", xss)
	}
	// A component key without the "project:" prefix resolves through components.
	footer := findRule(t, out, "Web:1222")
	if footer.Severity != domain.SeverityLow || footer.FilePath != "src/app/2389479284379021-footer.component.html" || *footer.Line != 5 {
		t.Errorf("footer hotspot = %+v", footer)
	}
	if f := findRule(t, out, "Web:12345"); f.FilePath != "src/path/to//1231235/ccommp.html" || *f.Line != 3 {
		t.Errorf("ccommp hotspot = %+v", f)
	}
	if _, ok := xss.Metadata[metaRemoteTriage]; ok {
		t.Errorf("TO_REVIEW hotspot carries triage: %v", xss.Metadata)
	}
}

func TestSonarQubeEmpty(t *testing.T) {
	out := parseFixture(t, NewSonarQube(), "sonarqube_empty.json")
	if out == nil || len(out) != 0 {
		t.Fatalf("empty report = %#v, want empty non-nil slice", out)
	}
}

func TestSonarQubeTriage(t *testing.T) {
	doc := `{"issues":[
	{"key":"a","rule":"java:S2076","severity":"BLOCKER","component":"p:src/A.java","project":"p","line":3,"status":"RESOLVED","resolution":"FALSE-POSITIVE","message":"m","type":"VULNERABILITY"},
	{"key":"b","rule":"java:S2077","severity":"MAJOR","component":"p:src/B.java","project":"p","line":4,"status":"RESOLVED","resolution":"WONTFIX","message":"m","type":"VULNERABILITY"},
	{"key":"c","rule":"java:S2078","severity":"MAJOR","component":"p:src/C.java","project":"p","line":5,"status":"CLOSED","resolution":"FIXED","message":"m","type":"VULNERABILITY"}],
	"hotspots":[{"key":"h","component":"p:src/H.java","project":"p","vulnerabilityProbability":"MEDIUM","status":"REVIEWED","resolution":"SAFE","line":9,"message":"m","ruleKey":"java:S4790"}]}`
	out, err := NewSonarQube().Parse(strings.NewReader(doc))
	if err != nil || len(out) != 3 {
		t.Fatalf("parse = %d findings, %v", len(out), err)
	}
	if f := findRule(t, out, "java:S2076"); f.Metadata[metaRemoteTriage] != "false_positive" || f.Severity != domain.SeverityCritical || f.FilePath != "src/A.java" {
		t.Errorf("false positive = %+v", f)
	}
	if f := findRule(t, out, "java:S2077"); f.Metadata[metaRemoteTriage] != "wont_fix" {
		t.Errorf("won't fix = %+v", f)
	}
	if f := findRule(t, out, "java:S4790"); f.Metadata[metaRemoteTriage] != "false_positive" {
		t.Errorf("safe hotspot = %+v", f)
	}
}

func TestSonarQubeRejectsOtherJSON(t *testing.T) {
	if _, err := NewSonarQube().Parse(strings.NewReader(`{"results":[]}`)); err == nil {
		t.Error("want error for non-SonarQube JSON")
	}
}
