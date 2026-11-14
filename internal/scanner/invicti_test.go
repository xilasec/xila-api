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
//	invicti_one.json         ← invicti/invicti_one_finding.json
//	invicti_issue_10311.json ← invicti/issue_10311.json
//	invicti_empty.json       ← invicti/invicti_zero_finding.json

func TestInvictiOneFinding(t *testing.T) {
	fs := parseFixture(t, NewInvicti(), "invicti_one.json")
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
	if f.CWE == nil || *f.CWE != 16 || f.CVSS == nil || *f.CVSS != 5.7 {
		t.Errorf("CWE/CVSS = %v %v", f.CWE, f.CVSS)
	}
	if !strings.HasPrefix(f.Description, "Netsparker Enterprise identified a cookie not marked as HTTPOnly.") {
		t.Errorf("description = %q", f.Description)
	}
	if m, _ := f.Metadata["mitigation"].(string); !strings.HasPrefix(m, "Mark the cookie as HTTPOnly.") {
		t.Errorf("mitigation = %q", m)
	}
	if refs, _ := f.Metadata["references"].([]string); !slices.Contains(refs, "https://wiki.owasp.org/index.php/HttpOnly") {
		t.Errorf("references = %v", f.Metadata["references"])
	}
	if _, triaged := f.Metadata[metaRemoteTriage]; triaged {
		t.Error("Present finding carried triage")
	}
}

func TestInvictiIssue10311(t *testing.T) {
	fs := parseFixture(t, NewInvicti(), "invicti_issue_10311.json")
	if len(fs) != 3 {
		t.Fatalf("got %d findings, want 3: %v", len(fs), ruleIDs(fs))
	}
	secure := fs[0]
	if secure.RuleID != "CookieNotMarkedAsSecure" || secure.Severity != domain.SeverityHigh ||
		secure.CWE == nil || *secure.CWE != 614 || secure.FilePath != "https://www.sampleweb.org/" {
		t.Errorf("secure = %s %s %v %q", secure.RuleID, secure.Severity, secure.CWE, secure.FilePath)
	}
	boot := fs[1]
	if boot.RuleID != "BootstrapjsOutOfDate" || boot.Title != "Out-of-date Version (Bootstrap)" ||
		boot.Severity != domain.SeverityMedium || boot.CWE != nil {
		t.Errorf("bootstrap = %s %q %s %v", boot.RuleID, boot.Title, boot.Severity, boot.CWE)
	}
	if known, _ := boot.Metadata["known_vulnerabilities"].([]string); len(known) != 4 {
		t.Errorf("bootstrap known vulnerabilities = %v", boot.Metadata["known_vulnerabilities"])
	}
	if fs[2].RuleID != "CookieNotMarkedAsHttpOnly" || fs[2].Severity != domain.SeverityLow {
		t.Errorf("httponly = %s %s", fs[2].RuleID, fs[2].Severity)
	}
}

func TestInvictiStateTriage(t *testing.T) {
	for state, want := range map[string]string{
		"Present, FalsePositive": "false_positive",
		"Present, AcceptedRisk":  "risk_accepted",
		"Present, Ignored":       "wont_fix",
	} {
		in := `{"Target":{"Url":"https://x/"},"Vulnerabilities":[{"Url":"https://x/a","Type":"T","Name":"N","Severity":"High","State":"` + state + `"}]}`
		fs, err := NewInvicti().Parse(strings.NewReader(in))
		if err != nil || len(fs) != 1 || fs[0].Metadata[metaRemoteTriage] != want {
			t.Errorf("state %q: %v %v", state, fs, err)
		}
	}
	// Fixed (not present) and informational items are not findings.
	in := `{"Vulnerabilities":[{"Url":"https://x/a","Type":"T","Severity":"High","State":"Fixed (Unconfirmed)"},` +
		`{"Url":"https://x/b","Type":"U","Severity":"Information","State":"Present"}]}`
	if fs, err := NewInvicti().Parse(strings.NewReader(in)); err != nil || len(fs) != 0 {
		t.Errorf("fixed/info kept: %v %v", fs, err)
	}
}

func TestInvictiEmptyAndMalformed(t *testing.T) {
	fs := parseFixture(t, NewInvicti(), "invicti_empty.json")
	if fs == nil || len(fs) != 0 {
		t.Fatalf("got %v, want empty non-nil", fs)
	}
	for _, in := range []string{`{"site":[]}`, `<xml/>`, `[]`} {
		if _, err := NewInvicti().Parse(strings.NewReader(in)); err == nil {
			t.Errorf("Parse(%q) accepted non-Invicti input", in)
		}
	}
}
