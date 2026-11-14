package scanner

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Application-security and import-format fixtures under testdata/ are real
// output, trimmed (entries dropped, long descriptions shortened), never
// invented. Sources:
//
//   - DefectDojo docs + unit-test scans (BSD-3-Clause),
//     https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans:
//     defectdojo_generic_docs.json        ← example JSON, docs.defectdojo.com/supported_tools/parsers/file/generic/
//     defectdojo_generic_import.json      ← generic/test_import_report1.json
//     defectdojo_generic_vuln_ids.json    ← generic/generic_report4.json
//     defectdojo_generic_loose_types.json ← generic/generic_non_numeric_fields.json
//     defectdojo_generic_nested_ids.json  ← generic/generic_non_string_vulnerability_ids.json
//     snyk_single.json, snyk_no_vulns.json ← snyk/single_project_one_vuln.json, single_project_no_vulns.json
//     snyk_all_projects.json              ← snyk/all_projects_issue4277.json (`snyk test --all-projects --json`)
//     pip_audit_legacy.json               ← pip_audit/many_vulns.json (pip-audit < 2.5, bare array)
//     safety_ignored.json                 ← safety/many_findings.json
//     cargo_audit_cvss.json               ← cargo_audit/many_findings_cvss.json
//     cargo_audit_warnings.json           ← cargo_audit/many_findings.json
//     cargo_audit_no_findings.json        ← cargo_audit/no_findings.json
//     retirejs.json                       ← retirejs/latest.json
//     bundler_audit.json                  ← bundler_audit/version_9.0.json
//     semgrep.json, semgrep_cwe_list.json, semgrep_empty.json ← semgrep/many_findings.json, cwe_list.json, empty.json
//     brakeman.json, brakeman_render.json ← brakeman/many_findings.json, two_findings.json
//     detect_secrets_audited.json         ← detect_secrets/many_findings.json
//     ggshield.json, ggshield_no_finding.json ← ggshield/many_findings.json, no_finding.json
//   - SecObserve (BSD-3-Clause), https://github.com/SecObserve/SecObserve:
//     secobserve_import.json ← backend/unittests/import_observations/parsers/secobserve/files/multiple_observations.json
//     secobserve_api.json    ← the GET /api/observations/ response asserted in
//     backend/unittests/authorization/api/test_authorization_observations.py (product_data trimmed)
//   - safety_recommended_fix.json: Safety's tests/test_db/report_with_recommended_fix.json
//     (MIT), https://github.com/pyupio/safety
//   - semgrep_supply_chain.json: Semgrep's e2e snapshot (LGPL-2.1, test data),
//     https://github.com/semgrep/semgrep/tree/develop/cli/tests/default/e2e-other/snapshots/test_ssc
//     (rulesdependency_awarepython-requirements-sca.yaml-dependency_awarerequirements/results.txt)
//   - Generated for this repo by running the tool on a small deliberately
//     vulnerable sample app: bandit.json (bandit 1.9.4 -f json), gosec.json
//     (gosec -fmt json -track-suppressions), pip_audit.json (pip-audit 2.x
//     --format json --aliases on --desc on), detect_secrets.json
//     (detect-secrets 1.5.47 scan). gosec_ranges.json ← DefectDojo gosec/many_vulns.json.

func TestDefectDojoGenericDocsExample(t *testing.T) {
	out := parseFixture(t, NewDefectDojoGeneric(), "defectdojo_generic_docs.json")
	// Four findings; the mitigated XSS is history in DefectDojo, not work here.
	if len(out) != 3 {
		t.Fatalf("got %d findings %v, want 3 (mitigated one skipped)", len(out), ruleIDs(out))
	}

	xz := findRule(t, out, "CVE-2024-3094")
	if xz.Category != domain.CategorySCA || xz.Package != "xz-utils" || xz.PackageVersion != "5.6.0" ||
		xz.FixedVersion != "5.6.2" || xz.Severity != domain.SeverityCritical {
		t.Errorf("component finding = %+v", xz)
	}
	if !slices.Equal(xz.CVE, []string{"CVE-2024-3094"}) || xz.CVSS == nil || *xz.CVSS != 10.0 {
		t.Errorf("xz CVE/CVSS = %v / %v, want CVE-2024-3094 and the v3 vector's 10.0", xz.CVE, xz.CVSS)
	}

	// A finding proven on an endpoint is DAST, located at that URL; its score is
	// derived from the CVSS v3 vector (the report gives no number).
	sqli := findRule(t, out, "SQL Injection in login form")
	if sqli.Category != domain.CategoryDAST || sqli.URL != "https://app.example.com/login" ||
		sqli.CWE == nil || *sqli.CWE != 89 || sqli.CVSS == nil || *sqli.CVSS != 9.8 {
		t.Errorf("endpoint finding = %+v", sqli)
	}

	// vuln_id_from_tool is the stable rule; "cwes" supplies the CWE.
	cred := findRule(t, out, "generic.secrets.password")
	if cred.Category != domain.CategorySAST || cred.FilePath != "src/settings.py" || cred.Line == nil || *cred.Line != 42 ||
		cred.CWE == nil || *cred.CWE != 798 {
		t.Errorf("code finding = %+v", cred)
	}
}

func TestDefectDojoGenericCarriesTriage(t *testing.T) {
	out := parseFixture(t, NewDefectDojoGeneric(), "defectdojo_generic_import.json")
	// Three of the four are inactive+mitigated; the active, verified one stays and
	// carries DefectDojo's verdict.
	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1", len(out))
	}
	if got := out[0].Metadata[metaRemoteTriage]; got != "confirmed" {
		t.Errorf("verified finding carries %v, want confirmed", got)
	}
	if out[0].Metadata["source_tool"] != "Unicorn" {
		t.Errorf("source tool = %v", out[0].Metadata["source_tool"])
	}

	// Every DefectDojo triage flag maps to a verdict, and closed findings drop.
	no := false
	cases := []struct {
		f    ddGenericFinding
		want domain.FindingStatus
		keep bool
	}{
		{ddGenericFinding{FalseP: true, Active: &no}, domain.FindingFalsePositive, true},
		{ddGenericFinding{RiskAccepted: true, Active: &no}, domain.FindingRiskAccepted, true},
		{ddGenericFinding{OutOfScope: true}, domain.FindingWontFix, true},
		{ddGenericFinding{Verified: true}, domain.FindingConfirmed, true},
		{ddGenericFinding{}, domain.FindingOpen, true},
		{ddGenericFinding{IsMitigated: true, Verified: true}, "", false},
		{ddGenericFinding{Active: &no}, "", false},
	}
	for _, c := range cases {
		got, keep := ddGenericStatus(c.f)
		if got != c.want || keep != c.keep {
			t.Errorf("ddGenericStatus(%+v) = %q,%v want %q,%v", c.f, got, keep, c.want, c.keep)
		}
	}
}

func TestDefectDojoGenericToleratesLooseTypes(t *testing.T) {
	// GHSA first, CVE second: the CVE is still lifted; the GHSA is the rule.
	ids := parseFixture(t, NewDefectDojoGeneric(), "defectdojo_generic_vuln_ids.json")
	if len(ids) != 1 || ids[0].RuleID != "GHSA-5mrr-rgp6-x4gr" || !slices.Equal(ids[0].CVE, []string{"CVE-2015-9235"}) {
		t.Fatalf("vulnerability_ids finding = %+v", ids)
	}

	// Ids nested in objects are found too.
	nested := parseFixture(t, NewDefectDojoGeneric(), "defectdojo_generic_nested_ids.json")
	if len(nested) != 1 || !slices.Equal(nested[0].CVE, []string{"CVE-2021-1234", "CVE-2021-5678", "CVE-2021-9999"}) {
		t.Fatalf("nested ids = %+v", nested)
	}

	// "N/A" placeholders are dropped, quoted numbers are kept.
	loose := parseFixture(t, NewDefectDojoGeneric(), "defectdojo_generic_loose_types.json")
	if len(loose) != 3 {
		t.Fatalf("got %d findings, want 3", len(loose))
	}
	if loose[0].CWE != nil || loose[0].Line != nil {
		t.Errorf("placeholder numbers became %v/%v", loose[0].CWE, loose[0].Line)
	}
	for _, f := range loose[1:] {
		if f.CWE == nil || *f.CWE != 79 || f.Line == nil || *f.Line != 42 {
			t.Errorf("%q: cwe/line = %v/%v, want 79/42", f.Title, f.CWE, f.Line)
		}
	}
}

func TestSecObserveImportFormat(t *testing.T) {
	out := parseFixture(t, NewSecObserve(), "secobserve_import.json")
	if len(out) != 2 {
		t.Fatalf("got %d findings, want 2", len(out))
	}
	f := findRule(t, out, "vulnerability_id_1")
	if f.Title != "title_1" || f.Severity != domain.SeverityCritical || f.Package != "origin_component_name_1" ||
		f.PackageVersion != "origin_component_version_1" || f.Purl != "origin_component_purl_1" ||
		f.FilePath != "origin_source_file_1" || f.Line == nil || *f.Line != 10 ||
		f.CWE == nil || *f.CWE != 1 || f.CVSS == nil || *f.CVSS != 1.1 || f.Category != domain.CategorySCA {
		t.Errorf("observation = %+v", f)
	}
	if !strings.Contains(f.Description, "recommendation_1") {
		t.Errorf("recommendation dropped: %q", f.Description)
	}
	// Severity absent → unranked (medium), never silently info.
	if g := findRule(t, out, "title_2"); g.Severity != domain.SeverityMedium || g.URL != "https://example.com" {
		t.Errorf("minimal observation = %+v", g)
	}
}

func TestSecObserveAPIListCarriesAssessment(t *testing.T) {
	out := parseFixture(t, NewSecObserve(), "secobserve_api.json")
	// Four observations: the Duplicate is dropped (its primary is in the export).
	if len(out) != 3 {
		t.Fatalf("got %d findings, want 3", len(out))
	}
	var fp, open int
	for _, f := range out {
		if f.Category != domain.CategoryDAST {
			t.Errorf("%q category = %s, want dast (parser type)", f.Title, f.Category)
		}
		switch f.Metadata[metaRemoteTriage] {
		case "false_positive":
			fp++
		case nil:
			open++
		}
	}
	if fp != 1 || open != 2 {
		t.Errorf("false positive / open = %d/%d, want 1/2", fp, open)
	}
	if s := findRule(t, out, "db_observation_external_active"); s.Severity != domain.SeverityHigh {
		t.Errorf("current_severity not used: %s", s.Severity)
	}

	cases := map[string]domain.FindingStatus{
		"Affected": domain.FindingConfirmed, "Not affected": domain.FindingFalsePositive,
		"Not security": domain.FindingFalsePositive, "Risk accepted": domain.FindingRiskAccepted,
		"In review": domain.FindingOpen, "Open": domain.FindingOpen,
	}
	for in, want := range cases {
		if got, keep := secObserveStatus(in); got != want || !keep {
			t.Errorf("secObserveStatus(%q) = %q,%v want %q", in, got, keep, want)
		}
	}
	if _, keep := secObserveStatus("Resolved"); keep {
		t.Error("resolved observations must not be imported")
	}
}

func TestSnykSingleProject(t *testing.T) {
	out := parseFixture(t, NewSnyk(), "snyk_single.json")
	f := findRule(t, out, "SNYK-JAVA-ORGAPACHESANTUARIO-460281")
	if !slices.Equal(f.CVE, []string{"CVE-2019-12400"}) || f.CWE == nil || *f.CWE != 611 ||
		f.Severity != domain.SeverityMedium || f.Package != "org.apache.santuario:xmlsec" || f.PackageVersion != "2.1.1" ||
		f.FixedVersion != "2.1.4" || f.Purl != "pkg:maven/org.apache.santuario/xmlsec@2.1.1" || f.FilePath != "pom.xml" ||
		f.CVSS == nil || *f.CVSS != 6.5 {
		t.Errorf("finding = %+v", f)
	}
	if empty := parseFixture(t, NewSnyk(), "snyk_no_vulns.json"); len(empty) != 0 {
		t.Errorf("clean project yielded %d findings", len(empty))
	}
}

func TestSnykAllProjects(t *testing.T) {
	out := parseFixture(t, NewSnyk(), "snyk_all_projects.json")
	// 8 issue rows across two manifests; the repeats are the same advisory on
	// another dependency path, which is one finding with both paths.
	if len(out) != 5 {
		t.Fatalf("got %d findings %v, want 5", len(out), ruleIDs(out))
	}
	ws := findRule(t, out, "SNYK-DOTNET-MICROSOFTASPNETCOREWEBSOCKETS-72891")
	if paths := ws.Metadata["paths"].([]string); len(paths) != 2 {
		t.Errorf("paths = %v, want both dependency paths", paths)
	}
	// fixedIn lists every maintained branch; 2.2.0 upgrades to 2.2.1, not 2.1.7.
	if ws.FixedVersion != "2.2.1" || ws.Purl != "pkg:nuget/Microsoft.AspNetCore.WebSockets@2.2.0" ||
		ws.FilePath != `company.Api.project\src\obj\project.assets.json` {
		t.Errorf("nuget finding = %+v", ws)
	}
	if l := findRule(t, out, "SNYK-JS-LODASH-1018905"); l.Purl != "pkg:npm/lodash@4.17.11" || !slices.Equal(l.CVE, []string{"CVE-2020-28500"}) {
		t.Errorf("npm finding = %+v", l)
	}
	if lic := findRule(t, out, "snyk:lic:npm:tinymce:LGPL-2.1"); lic.Category != domain.CategoryLicense || lic.Metadata["license"] != "LGPL-2.1" {
		t.Errorf("license issue = %+v", lic)
	}
}

func TestPipAudit(t *testing.T) {
	out := parseFixture(t, NewPipAudit(), "pip_audit.json")
	// pip-audit repeats each advisory per source; one finding per package+advisory.
	if len(out) != 5 {
		t.Fatalf("got %d findings %v, want 5", len(out), ruleIDs(out))
	}
	f := findRule(t, out, "PYSEC-2022-2")
	// The PYSEC id is the rule; the CVE is lifted from the aliases. The fix is
	// the nearest one above 3.2.9 among 2.2.26 / 3.2.11 / 4.0.1.
	if !slices.Equal(f.CVE, []string{"CVE-2021-45116"}) || f.Package != "django" || f.PackageVersion != "3.2.9" ||
		f.FixedVersion != "3.2.11" || f.Purl != "pkg:pypi/django@3.2.9" || f.Severity != domain.SeverityMedium {
		t.Errorf("finding = %+v", f)
	}

	legacy := parseFixture(t, NewPipAudit(), "pip_audit_legacy.json")
	// adal is clean and azure-devops was skipped; aiohttp has one, twisted four.
	if len(legacy) != 5 || findRule(t, legacy, "PYSEC-2021-76").FixedVersion != "3.7.4" {
		t.Errorf("legacy array = %v", ruleIDs(legacy))
	}
}

func TestSafety(t *testing.T) {
	out := parseFixture(t, NewSafety(), "safety_recommended_fix.json")
	if len(out) != 3 {
		t.Fatalf("got %d findings, want 3", len(out))
	}
	// The CVE comes either as a bare id or as an object with its CVSS.
	a := findRule(t, out, "PYUP-44742")
	if !slices.Equal(a.CVE, []string{"CVE-2022-22818"}) || a.Severity != domain.SeverityMedium ||
		a.CVSS == nil || *a.CVSS != 6.1 || a.FixedVersion != "4.0.2" || a.Purl != "pkg:pypi/django@4.0.1" {
		t.Errorf("finding = %+v", a)
	}
	b := findRule(t, out, "PYUP-48041")
	if !slices.Equal(b.CVE, []string{"CVE-2022-28346"}) || b.Severity != domain.SeverityCritical || b.FixedVersion != "4.0.4" {
		t.Errorf("object-CVE finding = %+v", b)
	}

	// A vulnerability ignored by the Safety policy keeps that decision.
	ign := parseFixture(t, NewSafety(), "safety_ignored.json")
	accepted := findRule(t, ign, "PYUP-11111")
	if accepted.Metadata[metaRemoteTriage] != "risk_accepted" ||
		!strings.Contains(accepted.Metadata[metaRemoteTriageReason].(string), "accepted risk") {
		t.Errorf("ignored vuln metadata = %v", accepted.Metadata)
	}
	if hi := findRule(t, ign, "PYUP-38765"); hi.Severity != domain.SeverityHigh || hi.Metadata[metaRemoteTriage] != nil {
		t.Errorf("rated vuln = %+v", hi)
	}
}

func TestCargoAudit(t *testing.T) {
	out := parseFixture(t, NewCargoAudit(), "cargo_audit_cvss.json")
	if len(out) != 3 {
		t.Fatalf("got %d findings, want 3", len(out))
	}
	// v3 vector → score and severity; the GHSAs among the aliases aren't CVEs.
	f := findRule(t, out, "RUSTSEC-2026-0047")
	if !slices.Equal(f.CVE, []string{"CVE-2026-3338"}) || f.CVSS == nil || *f.CVSS != 7.5 || f.Severity != domain.SeverityHigh ||
		f.Purl != "pkg:cargo/aws-lc-sys@0.36.0" || f.FixedVersion != ">=0.38.0" {
		t.Errorf("finding = %+v", f)
	}
	// No vector, or a v4 one we don't score: unranked, not guessed.
	for _, id := range []string{"RUSTSEC-2026-0044", "RUSTSEC-2026-0141"} {
		if g := findRule(t, out, id); g.Severity != domain.SeverityMedium || g.CVSS != nil {
			t.Errorf("%s = %s / %v, want medium and no score", id, g.Severity, g.CVSS)
		}
	}

	warn := parseFixture(t, NewCargoAudit(), "cargo_audit_warnings.json")
	// Unmaintained advisories are kept (low); yanked crates carry no advisory.
	if u := findRule(t, warn, "RUSTSEC-2021-0064"); u.Severity != domain.SeverityLow || u.Metadata["warning"] != "unmaintained" {
		t.Errorf("unmaintained = %+v", u)
	}
	if len(warn) != 3 {
		t.Errorf("got %v, want hyper + smallvec (two versions, one identity) + the unmaintained crate", ruleIDs(warn))
	}
	if empty := parseFixture(t, NewCargoAudit(), "cargo_audit_no_findings.json"); len(empty) != 0 {
		t.Errorf("clean lockfile yielded %d findings", len(empty))
	}
}

func TestRetireJS(t *testing.T) {
	out := parseFixture(t, NewRetireJS(), "retirejs.json")
	// handlebars: three advisories without a CVE; jquery: five advisories, two
	// of which name CVE-2015-9251 and collapse into one.
	if len(out) != 7 {
		t.Fatalf("got %d findings %v, want 7", len(out), ruleIDs(out))
	}
	j := findRule(t, out, "CVE-2015-9251")
	if j.Package != "jquery" || j.PackageVersion != "1.11.2" || j.Purl != "pkg:npm/jquery@1.11.2" ||
		!strings.HasSuffix(j.FilePath, "jquery-1.11.2.min.js") || j.FixedVersion != "1.12.0" ||
		!strings.Contains(j.Description, "parseHTML()") {
		t.Errorf("merged jquery finding = %+v", j)
	}
	if h := findRule(t, out, "retire:handlebars:below-4.3.0"); h.Severity != domain.SeverityLow || len(h.CVE) != 0 {
		t.Errorf("handlebars finding = %+v", h)
	}
}

func TestBundlerAudit(t *testing.T) {
	out := parseFixture(t, NewBundlerAudit(), "bundler_audit.json")
	if len(out) != 4 {
		t.Fatalf("got %d findings, want 4", len(out))
	}
	r := findRule(t, out, "CVE-2020-8161")
	if r.Package != "rack" || r.PackageVersion != "1.6.13" || r.Purl != "pkg:gem/rack@1.6.13" ||
		!slices.Equal(r.CVE, []string{"CVE-2020-8161"}) || r.FixedVersion != "~> 2.1.3, >= 2.2.0" ||
		r.Metadata["ghsa"] != "GHSA-5f9h-9pjv-v6j7" {
		t.Errorf("finding = %+v", r)
	}
	// An advisory with only a GHSA keys on it and lifts no CVE.
	if n := findRule(t, out, "GHSA-xc9x-jj77-9p9j"); len(n.CVE) != 0 || n.Package != "nokogiri" {
		t.Errorf("GHSA-only finding = %+v", n)
	}
}

func TestSemgrep(t *testing.T) {
	out := parseFixture(t, NewSemgrep(), "semgrep.json")
	if len(out) != 2 {
		t.Fatalf("got %d findings, want 2", len(out))
	}
	f := out[0]
	if f.RuleID != "java.lang.security.audit.cbc-padding-oracle.cbc-padding-oracle" || f.Severity != domain.SeverityMedium ||
		f.CWE == nil || *f.CWE != 696 || f.Line == nil || *f.Line != 64 || f.Category != domain.CategorySAST ||
		!strings.HasSuffix(f.FilePath, "BenchmarkTest02194.java") || f.Metadata["fix"] == nil {
		t.Errorf("finding = %+v", f)
	}
	// CWE given as a list; INFO is Semgrep's lowest *security* rating → low.
	c := parseFixture(t, NewSemgrep(), "semgrep_cwe_list.json")
	if len(c) != 1 || c[0].CWE == nil || *c[0].CWE != 352 || c[0].Severity != domain.SeverityLow {
		t.Errorf("cwe list finding = %+v", c)
	}
	if empty := parseFixture(t, NewSemgrep(), "semgrep_empty.json"); len(empty) != 0 {
		t.Errorf("empty report yielded %d findings", len(empty))
	}
}

func TestSemgrepSupplyChain(t *testing.T) {
	out := parseFixture(t, NewSemgrep(), "semgrep_supply_chain.json")
	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1", len(out))
	}
	f := out[0]
	if f.Category != domain.CategorySCA || f.Package != "pandas" || f.PackageVersion != "1.4.2" ||
		f.Purl != "pkg:pypi/pandas@1.4.2" || f.Metadata["reachable"] != true || f.Metadata["transitivity"] != "direct" {
		t.Errorf("supply-chain finding = %+v", f)
	}
}

func TestBandit(t *testing.T) {
	out := parseFixture(t, NewBandit(), "bandit.json")
	if len(out) != 5 {
		t.Fatalf("got %d findings %v, want 5", len(out), ruleIDs(out))
	}
	shell := findRule(t, out, "B602")
	if shell.Severity != domain.SeverityHigh || shell.CWE == nil || *shell.CWE != 78 || shell.FilePath != "app/views.py" ||
		shell.Line == nil || *shell.Line != 14 || shell.Metadata["confidence"] != "high" {
		t.Errorf("finding = %+v", shell)
	}
	// Confidence is reported, not folded into severity.
	if pw := findRule(t, out, "B105"); pw.Severity != domain.SeverityLow || pw.Metadata["confidence"] != "medium" {
		t.Errorf("hardcoded password = %+v", pw)
	}
}

func TestGosec(t *testing.T) {
	out := parseFixture(t, NewGosec(), "gosec.json")
	if len(out) != 9 {
		t.Fatalf("got %d findings %v, want 9", len(out), ruleIDs(out))
	}
	sqli := findRule(t, out, "G701")
	if sqli.Severity != domain.SeverityHigh || sqli.CWE == nil || *sqli.CWE != 89 || sqli.Line == nil || *sqli.Line != 13 {
		t.Errorf("finding = %+v", sqli)
	}
	// The #nosec'd G204 arrives as a false positive with the justification.
	nosec := findRule(t, out, "G204")
	if nosec.Metadata[metaRemoteTriage] != "false_positive" ||
		!strings.Contains(nosec.Metadata[metaRemoteTriageReason].(string), "input is allow-listed upstream") {
		t.Errorf("suppressed finding metadata = %v", nosec.Metadata)
	}
	for _, f := range out {
		if f.RuleID != "G204" && f.Metadata[metaRemoteTriage] != nil {
			t.Errorf("%s carries a verdict it was never given", f.RuleID)
		}
	}
	// A multi-line match ("36-39") is located at its first line.
	ranges := parseFixture(t, NewGosec(), "gosec_ranges.json")
	if g := findRule(t, ranges, "G201"); g.Line == nil || *g.Line != 36 {
		t.Errorf("range line = %v, want 36", g.Line)
	}
}

func TestBrakeman(t *testing.T) {
	out := parseFixture(t, NewBrakeman(), "brakeman.json")
	if len(out) != 4 {
		t.Fatalf("got %d findings, want 4", len(out))
	}
	f := findRule(t, out, "SQLCVEs/69")
	if !slices.Equal(f.CVE, []string{"CVE-2013-6417"}) || f.Severity != domain.SeverityHigh ||
		f.FilePath != "Gemfile.lock" || f.Line == nil || *f.Line != 64 {
		t.Errorf("finding = %+v", f)
	}
	// Two render-path warnings of one check in different templates stay apart;
	// "Weak" confidence ranks low.
	r := parseFixture(t, NewBrakeman(), "brakeman_render.json")
	if len(r) != 2 || r[0].Severity != domain.SeverityLow || r[0].FilePath == r[1].FilePath {
		t.Errorf("render warnings = %+v", r)
	}

	// A warning listed in brakeman.ignore lands in ignored_warnings with the same
	// shape (report_json.rb serializes both through Warning#to_hash).
	var doc map[string]json.RawMessage
	raw, err := os.ReadFile("testdata/brakeman_render.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["ignored_warnings"], doc["warnings"] = doc["warnings"], json.RawMessage("[]")
	moved, _ := json.Marshal(doc)
	ign, err := NewBrakeman().Parse(strings.NewReader(string(moved)))
	if err != nil || len(ign) != 2 {
		t.Fatalf("ignored parse = %v, %v", ign, err)
	}
	for _, f := range ign {
		if f.Metadata[metaRemoteTriage] != "false_positive" {
			t.Errorf("ignored warning carries %v, want false_positive", f.Metadata[metaRemoteTriage])
		}
	}
}

func TestDetectSecrets(t *testing.T) {
	out := parseFixture(t, NewDetectSecrets(), "detect_secrets.json")
	// Line 2 holds one GitHub token that three plugins flagged: one finding,
	// named by the specific detector.
	if len(out) != 3 {
		t.Fatalf("got %d findings %v, want 3", len(out), ruleIDs(out))
	}
	gh := findRule(t, out, "github-token")
	if gh.Category != domain.CategorySecret || gh.Severity != domain.SeverityHigh || gh.FilePath != "app/settings.py" ||
		gh.Line == nil || *gh.Line != 2 || len(gh.Metadata["detectors"].([]string)) != 3 {
		t.Errorf("finding = %+v", gh)
	}
	findRule(t, out, "aws-access-key")

	// An audited baseline carries its verdicts.
	aud := parseFixture(t, NewDetectSecrets(), "detect_secrets_audited.json")
	verdicts := map[int]any{}
	for _, f := range aud {
		verdicts[*f.Line] = f.Metadata[metaRemoteTriage]
	}
	if verdicts[156] != "confirmed" || verdicts[112] != "false_positive" || verdicts[151] != nil {
		t.Errorf("audit verdicts by line = %v", verdicts)
	}
}

func TestGGShield(t *testing.T) {
	out := parseFixture(t, NewGGShield(), "ggshield.json")
	// The same Django key in two commits is one incident.
	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1", len(out))
	}
	f := out[0]
	if f.RuleID != "django-secret-key" || f.FilePath != "wapf/settings.py" || f.Line == nil || *f.Line != 23 ||
		f.Severity != domain.SeverityHigh || len(f.Metadata["commits"].([]string)) != 2 {
		t.Errorf("finding = %+v", f)
	}
	if empty := parseFixture(t, NewGGShield(), "ggshield_no_finding.json"); len(empty) != 0 {
		t.Errorf("clean scan yielded %d findings", len(empty))
	}
}

// Uploading the wrong tool's report must fail, not import nothing: `{}` and a
// different tool's JSON are both rejected.
func TestAppSecParsersRejectWrongInput(t *testing.T) {
	trivy, err := os.ReadFile("testdata/bundler_audit.json")
	if err != nil {
		t.Fatal(err)
	}
	parsers := []Parser{
		NewDefectDojoGeneric(), NewSecObserve(), NewSnyk(), NewPipAudit(), NewSafety(), NewCargoAudit(),
		NewRetireJS(), NewSemgrep(), NewBandit(), NewGosec(), NewBrakeman(), NewDetectSecrets(), NewGGShield(),
	}
	for _, p := range parsers {
		for _, in := range []string{"this is not json", "{}", string(trivy)} {
			if _, err := p.Parse(strings.NewReader(in)); err == nil {
				t.Errorf("%s accepted %.20q", p.Scanner(), in)
			}
		}
	}
	for _, in := range []string{"this is not json", "{}"} {
		if _, err := NewBundlerAudit().Parse(strings.NewReader(in)); err == nil {
			t.Errorf("bundler-audit accepted %q", in)
		}
	}
}

func TestCVSS3BaseScore(t *testing.T) {
	// Cross-check against the scores tools publish alongside the vector.
	raw, err := os.ReadFile("testdata/safety_recommended_fix.json")
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Vulnerabilities []struct {
			CVE      json.RawMessage `json:"CVE"`
			Severity json.RawMessage `json:"severity"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, v := range report.Vulnerabilities {
		for _, blob := range []json.RawMessage{v.CVE, v.Severity} {
			var s struct {
				CVSSv3 *struct {
					BaseScore float64 `json:"base_score"`
					Vector    string  `json:"vector_string"`
				} `json:"cvssv3"`
			}
			if json.Unmarshal(blob, &s) != nil || s.CVSSv3 == nil {
				continue
			}
			got, ok := cvss3BaseScore(s.CVSSv3.Vector)
			if !ok || got != s.CVSSv3.BaseScore {
				t.Errorf("cvss3BaseScore(%s) = %v,%v want %v", s.CVSSv3.Vector, got, ok, s.CVSSv3.BaseScore)
			}
			checked++
		}
	}
	if checked != 3 {
		t.Fatalf("cross-checked %d vectors, want 3", checked)
	}
	for vec, want := range map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N": 5.9,
		"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H": 7.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0,
	} {
		if got, ok := cvss3BaseScore(vec); !ok || got != want {
			t.Errorf("cvss3BaseScore(%s) = %v,%v want %v", vec, got, ok, want)
		}
	}
	for _, bad := range []string{"", "AV:N/AC:M/Au:N/C:P/I:P/A:P", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "CVSS:3.1/AV:N/AC:L"} {
		if _, ok := cvss3BaseScore(bad); ok {
			t.Errorf("cvss3BaseScore(%q) should not score", bad)
		}
	}
}

func TestNearestFix(t *testing.T) {
	cases := []struct {
		installed string
		fixes     []string
		want      string
	}{
		{"3.2.9", []string{"2.2.26", "3.2.11", "4.0.1"}, "3.2.11"},
		{"4.0.1", []string{"2.2.28", "3.2.13", "4.0.4"}, "4.0.4"},
		{"18.9.0", []string{"20.3.0rc1"}, "20.3.0rc1"},
		{"1.26.4", []string{"2.2.2", "1.26.19"}, "1.26.19"},
		{"1.0", nil, ""},
		{"weird", []string{"x", "y"}, "x"}, // incomparable: first listed
	}
	for _, c := range cases {
		if got := nearestFix(c.installed, c.fixes); got != c.want {
			t.Errorf("nearestFix(%s, %v) = %q want %q", c.installed, c.fixes, got, c.want)
		}
	}
}

func TestEcosystemPurl(t *testing.T) {
	cases := map[[3]string]string{
		{"npm", "@angular/core", "8.0.0"}:                 "pkg:npm/%40angular/core@8.0.0",
		{"maven", "org.apache.santuario:xmlsec", "2.1.1"}: "pkg:maven/org.apache.santuario/xmlsec@2.1.1",
		{"pip", "Django_Rest.framework", "3.0"}:           "pkg:pypi/django-rest-framework@3.0",
		{"rubygems", "rack", "1.6.13"}:                    "pkg:gem/rack@1.6.13",
		{"deb", "openssl", "1.1"}:                         "",
		{"maven", "no-group", "1"}:                        "",
	}
	for in, want := range cases {
		if got := ecosystemPurl(in[0], in[1], in[2]); got != want {
			t.Errorf("ecosystemPurl%v = %q want %q", in, got, want)
		}
	}
}
