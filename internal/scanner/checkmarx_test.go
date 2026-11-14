package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures from DefectDojo unittests/scans/checkmarx:
//
//	checkmarx_multiple.xml       ← multiple_findings.xml
//	checkmarx_false_positive.xml ← single_finding_false_positive.xml
//	checkmarx_empty.xml          ← no_finding.xml

func TestCheckmarxMultiple(t *testing.T) {
	out := parseFixture(t, NewCheckmarx(), "checkmarx_multiple.xml")
	// Three SQL_Injection paths; the two from Assignment5.java (username_login
	// and password_login) reach the same executeQuery() sink on line 50.
	if len(out) != 2 {
		t.Fatalf("findings = %d, want 2", len(out))
	}
	a5 := out[0]
	if a5.RuleID != "594" || a5.Title != "SQL Injection" || a5.Severity != domain.SeverityHigh ||
		a5.CWE == nil || *a5.CWE != 89 || a5.Category != domain.CategorySAST ||
		a5.FilePath != "WebGoat/webgoat-lessons/challenge/src/main/java/org/owasp/webgoat/plugin/challenge5/challenge6/Assignment5.java" ||
		a5.Line == nil || *a5.Line != 50 || a5.Metadata["occurrences"] != 2 {
		t.Errorf("Assignment5 finding = %+v", a5)
	}
	if !strings.Contains(a5.Description, "username_login") || !strings.Contains(a5.Description, "password_login") {
		t.Errorf("folded paths not described: %q", a5.Description)
	}
	a6 := out[1]
	if a6.FilePath != "WebGoat/webgoat-lessons/challenge/src/main/java/org/owasp/webgoat/plugin/challenge6/Assignment6.java" || *a6.Line != 52 {
		t.Errorf("Assignment6 finding = %+v", a6)
	}
	if _, ok := a5.Metadata[metaRemoteTriage]; ok {
		t.Errorf("state 0 result carries triage: %v", a5.Metadata)
	}
}

func TestCheckmarxNotExploitable(t *testing.T) {
	out := parseFixture(t, NewCheckmarx(), "checkmarx_false_positive.xml")
	if len(out) != 1 {
		t.Fatalf("findings = %d, want 1", len(out))
	}
	f := out[0]
	if f.RuleID != "595" || f.Title != "Stored XSS" || f.CWE == nil || *f.CWE != 79 ||
		f.FilePath != "WebGoat/webgoat-lessons/missing-function-ac/src/main/java/org/owasp/webgoat/plugin/Users.java" ||
		*f.Line != 58 || f.Metadata[metaRemoteTriage] != "false_positive" {
		t.Errorf("not-exploitable finding = %+v", f)
	}
}

func TestCheckmarxEmpty(t *testing.T) {
	out := parseFixture(t, NewCheckmarx(), "checkmarx_empty.xml")
	if out == nil || len(out) != 0 {
		t.Fatalf("empty report = %#v, want empty non-nil slice", out)
	}
	if _, err := NewCheckmarx().Parse(strings.NewReader(`<niktoscan/>`)); err == nil {
		t.Error("want error for non-Checkmarx XML")
	}
}

// checkmarx_aggregated_one_fp.xml ← two_aggregated_findings_one_is_false_positive.xml:
// two paths to one sink, only one marked false positive. The folded finding is
// still live through the other path, so it must not carry the verdict.
func TestCheckmarxFoldKeepsVerdictOnlyWhenUnanimous(t *testing.T) {
	out := parseFixture(t, NewCheckmarx(), "checkmarx_aggregated_one_fp.xml")
	if len(out) != 1 {
		t.Fatalf("findings = %d, want 1", len(out))
	}
	f := out[0]
	if f.RuleID != "594" || *f.Line != 50 || f.Metadata["occurrences"] != 2 {
		t.Errorf("folded finding = %+v", f)
	}
	if _, ok := f.Metadata[metaRemoteTriage]; ok {
		t.Errorf("mixed verdicts carried as triage: %v", f.Metadata)
	}
}
