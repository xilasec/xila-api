package scanner

import (
	"slices"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures (DefectDojo unit-test scans, BSD-3-Clause,
// https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans):
//
//	acunetix_example.xml            ← acunetix/XML_http_example_co_id_.xml
//	acunetix_360_multiple_cwe.json  ← acunetix/acunetix360_multiple_cwe.json
//	acunetix_360_false_positive.json← acunetix/acunetix360_one_finding_false_positive.json
//	acunetix_360_empty.json         ← acunetix/acunetix360_zero_finding.json

func acunetixByPath(t *testing.T, fs []ParsedFinding, rule, path string) ParsedFinding {
	t.Helper()
	for _, f := range fs {
		if f.RuleID == rule && f.FilePath == path {
			return f
		}
	}
	t.Fatalf("no finding %s at %s in %v", rule, path, ruleIDs(fs))
	return ParsedFinding{}
}

func TestAcunetixXML(t *testing.T) {
	fs := parseFixture(t, NewAcunetix(), "acunetix_example.xml")
	// 19 ReportItems: the informational CSP alert skipped; two CSRF forms on
	// /m/zmain, six HttpOnly and six Secure cookie alerts on / folded.
	if len(fs) != 7 {
		t.Fatalf("got %d findings, want 7: %v", len(fs), ruleIDs(fs))
	}
	for _, f := range fs {
		if f.Title == "Content Security Policy (CSP) not implemented" {
			t.Error("informational CSP alert kept")
		}
	}

	csrf := acunetixByPath(t, fs, "/Crawler/12-Crawler_Form_NO_CSRF.js", "http://example.co.id/h/search")
	if csrf.Title != "HTML form without CSRF protection" || csrf.Severity != domain.SeverityMedium ||
		csrf.CWE == nil || *csrf.CWE != 352 || csrf.CVSS == nil || *csrf.CVSS != 4.3 || csrf.URL != "http://example.co.id" {
		t.Errorf("csrf = %q %s %v %v %q", csrf.Title, csrf.Severity, csrf.CWE, csrf.CVSS, csrf.URL)
	}
	if refs, _ := csrf.Metadata["references"].([]string); !slices.Contains(refs, "https://www.acunetix.com/websitesecurity/csrf-attacks/") {
		t.Errorf("csrf references = %v", csrf.Metadata["references"])
	}
	if m, _ := csrf.Metadata["mitigation"].(string); !strings.HasPrefix(m, "Verify if this form requires anti-CSRF protection") {
		t.Errorf("csrf mitigation = %q", m)
	}
	zmain := acunetixByPath(t, fs, "/Crawler/12-Crawler_Form_NO_CSRF.js", "http://example.co.id/m/zmain")
	if zmain.Metadata["occurrences"] != 2 {
		t.Errorf("zmain occurrences = %v", zmain.Metadata["occurrences"])
	}

	// The CVE is only named in the alert details' reference list.
	yui := acunetixByPath(t, fs, "/Scripts/PerFile/Javascript_Libraries_Audit.script", "http://example.co.id/yui/2.7.0/yahoo-dom-event/yahoo-dom-event.js")
	if yui.Title != "Vulnerable Javascript library" || yui.Severity != domain.SeverityMedium ||
		!slices.Equal(yui.CVE, []string{"CVE-2010-4207"}) || yui.CWE == nil || *yui.CWE != 16 || *yui.CVSS != 6.5 {
		t.Errorf("yui = %q %s %v %v %v", yui.Title, yui.Severity, yui.CVE, yui.CWE, yui.CVSS)
	}

	cookie := acunetixByPath(t, fs, "/RPA/Cookie_Without_HttpOnly.js", "http://example.co.id/")
	if cookie.Severity != domain.SeverityLow || cookie.Metadata["occurrences"] != 6 ||
		!strings.Contains(cookie.Description, "Set-Cookie: JSESSIONID") {
		t.Errorf("httponly = %s %v %q", cookie.Severity, cookie.Metadata["occurrences"], cookie.Description)
	}
	if _, triaged := cookie.Metadata[metaRemoteTriage]; triaged {
		t.Error("alert without IsFalsePositive carried triage")
	}
}

func TestAcunetix360JSON(t *testing.T) {
	fs := parseFixture(t, NewAcunetix(), "acunetix_360_multiple_cwe.json")
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	f := fs[0]
	if f.RuleID != "CookieNotMarkedAsHttpOnly" || f.Title != "Cookie Not Marked as HttpOnly" || f.Severity != domain.SeverityMedium {
		t.Errorf("finding = %s %q %s", f.RuleID, f.Title, f.Severity)
	}
	if f.FilePath != "http://php.testsparker.com/auth/login.php" || f.URL != "http://php.testsparker.com/" {
		t.Errorf("location = %q %q", f.FilePath, f.URL)
	}
	if f.CWE == nil || *f.CWE != 16 || !slices.Equal(f.Metadata["cwes"].([]string), []string{"16", "200"}) {
		t.Errorf("CWE = %v %v", f.CWE, f.Metadata["cwes"])
	}
	if f.CVSS == nil || *f.CVSS != 5.7 || f.Metadata["state"] != "Present" {
		t.Errorf("CVSS/state = %v %v", f.CVSS, f.Metadata["state"])
	}
	if _, triaged := f.Metadata[metaRemoteTriage]; triaged {
		t.Error("Present finding carried triage")
	}

	fp := parseFixture(t, NewAcunetix(), "acunetix_360_false_positive.json")
	if len(fp) != 1 || fp[0].Metadata[metaRemoteTriage] != "false_positive" ||
		fp[0].Metadata[metaRemoteTriageReason] != "acunetix360 state: FalsePositive" {
		t.Fatalf("false positive = %v", fp)
	}
}

func TestAcunetixEmptyAndMalformed(t *testing.T) {
	fs := parseFixture(t, NewAcunetix(), "acunetix_360_empty.json")
	if fs == nil || len(fs) != 0 {
		t.Fatalf("got %v, want empty non-nil", fs)
	}
	for _, in := range []string{`{"site":[]}`, `<OWASPZAPReport/>`, `not a report`} {
		if _, err := NewAcunetix().Parse(strings.NewReader(in)); err == nil {
			t.Errorf("Parse(%q) accepted non-Acunetix input", in)
		}
	}
}
