package scanner

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures (DefectDojo unit-test scans, BSD-3-Clause):
//
//	yarn_audit_v1.json     ← unittests/scans/yarn_audit/yarn_audit_many_vul.json (Yarn 1 NDJSON)
//	yarn_audit_zero.json   ← unittests/scans/yarn_audit/yarn_audit_zero_vul.json
//	yarn_audit_error.json  ← unittests/scans/yarn_audit/empty_with_error.json
//	yarn_audit_berry.json  ← unittests/scans/yarn_audit/issue_6495.json (Berry 2/3, npm v6 shape)
//	yarn_audit_berry4.json ← unittests/scans/yarn_audit/yarn2_audit_issue9911.json (Berry 4 NDJSON)

func yarnFind(t *testing.T, out []ParsedFinding, pkg string) ParsedFinding {
	t.Helper()
	for _, f := range out {
		if f.Package == pkg {
			return f
		}
	}
	t.Fatalf("no finding for %s", pkg)
	return ParsedFinding{}
}

func TestYarnAuditV1(t *testing.T) {
	out := parseFixture(t, NewYarnAudit(), "yarn_audit_v1.json")
	if len(out) != 3 {
		t.Fatalf("got %d findings, want 3", len(out))
	}
	mini := yarnFind(t, out, "minimist")
	if mini.RuleID != "NPM-1179" || mini.Title != "minimist: Prototype Pollution" || mini.Severity != domain.SeverityLow ||
		mini.PackageVersion != "0.0.10" || mini.FixedVersion != "0.2.1" || mini.CWE == nil || *mini.CWE != 471 ||
		mini.Purl != "pkg:npm/minimist@0.0.10" || mini.Category != domain.CategorySCA {
		t.Errorf("minimist = %+v", mini)
	}
	if !slices.Equal(mini.Metadata["paths"].([]string), []string{"handlebars>optimist>minimist"}) ||
		mini.Metadata["mitigation"] != "Upgrade to versions 0.2.1, 1.2.3 or later." {
		t.Errorf("minimist metadata = %v", mini.Metadata)
	}
	var ace ParsedFinding
	for _, f := range out {
		if f.RuleID == "NPM-1324" {
			ace = f
		}
	}
	if ace.Title != "handlebars: Arbitrary Code Execution" || ace.Severity != domain.SeverityHigh ||
		ace.PackageVersion != "4.5.2" || ace.FixedVersion != "4.5.3" || *ace.CWE != 79 {
		t.Errorf("handlebars 1324 = %+v", ace)
	}

	if zero := parseFixture(t, NewYarnAudit(), "yarn_audit_zero.json"); zero == nil || len(zero) != 0 {
		t.Errorf("zero: got %v", zero)
	}
}

func TestYarnAuditRejectsFailedRun(t *testing.T) {
	f := strings.NewReader(`{"type":"error","data":"An unexpected error occurred"}`)
	if _, err := NewYarnAudit().Parse(f); err == nil {
		t.Error("expected error for an error event")
	}
	fx, err := os.Open("testdata/yarn_audit_error.json")
	if err != nil {
		t.Fatal(err)
	}
	defer fx.Close()
	if out, err := NewYarnAudit().Parse(fx); err == nil {
		t.Errorf("empty_with_error: expected an error, got %v", out)
	}
	for _, in := range []string{``, `{"auditReportVersion":2,"vulnerabilities":{}}`, `[1,2]`} {
		if _, err := NewYarnAudit().Parse(strings.NewReader(in)); err == nil {
			t.Errorf("expected error for %q", in)
		}
	}
}

func TestYarnAuditBerry(t *testing.T) {
	out := parseFixture(t, NewYarnAudit(), "yarn_audit_berry.json")
	if len(out) != 3 {
		t.Fatalf("got %d findings, want 3", len(out))
	}
	ini := yarnFind(t, out, "ini")
	if ini.RuleID != "GHSA-qqgx-2p2h-9c37" || !slices.Equal(ini.CVE, []string{"CVE-2020-7788"}) ||
		ini.CWE == nil || *ini.CWE != 1321 || ini.Severity != domain.SeverityHigh ||
		ini.PackageVersion != "1.3.5" || ini.FixedVersion != "1.3.6" || ini.CVSS == nil || *ini.CVSS != 7.3 ||
		ini.URL != "https://github.com/advisories/GHSA-qqgx-2p2h-9c37" {
		t.Errorf("ini = %+v", ini)
	}
	if paths := ini.Metadata["paths"].([]string); len(paths) != 8 {
		t.Errorf("ini paths = %v", paths)
	}
	got := yarnFind(t, out, "got")
	if got.RuleID != "GHSA-pfrx-2q88-qq97" || !slices.Equal(got.CVE, []string{"CVE-2022-33987"}) ||
		got.Severity != domain.SeverityMedium || got.PackageVersion != "9.6.0" || got.FixedVersion != "11.8.5" ||
		got.CWE != nil || got.CVSS != nil {
		t.Errorf("got = %+v", got)
	}
}

func TestYarnAuditBerry4(t *testing.T) {
	out := parseFixture(t, NewYarnAudit(), "yarn_audit_berry4.json")
	if len(out) != 4 {
		t.Fatalf("got %d findings, want 4", len(out))
	}
	tr := yarnFind(t, out, "transformers")
	if tr.RuleID != "GHSA-37q5-v5qm-c9v8" || tr.Severity != domain.SeverityLow || tr.PackageVersion != "4.38" ||
		tr.FixedVersion != "4.38.0" || tr.Title != "transformers: Transformers Deserialization of Untrusted Data vulnerability" ||
		tr.Metadata["advisory_id"] != "1096536" {
		t.Errorf("transformers = %+v", tr)
	}
	dep := yarnFind(t, out, "@babel/plugin-proposal-class-properties")
	if dep.RuleID != "@babel/plugin-proposal-class-properties (deprecation)" || dep.Severity != domain.SeverityMedium ||
		dep.PackageVersion != "7.18.6" || dep.FixedVersion != "" ||
		dep.Purl != "pkg:npm/%40babel/plugin-proposal-class-properties@7.18.6" {
		t.Errorf("deprecation = %+v", dep)
	}
}
