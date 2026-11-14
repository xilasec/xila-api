package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixture: DefectDojo unittests/scans/arachni/arachni.afr.json (BSD-3-Clause),
// trimmed to its one XSS issue (the generated report is otherwise mostly
// request/response/DOM capture noise the parser doesn't read).
func TestArachniParse(t *testing.T) {
	out := parseFixture(t, NewArachni(), "arachni_xss.json")
	if len(out) != 1 {
		t.Fatalf("got %d findings, want 1", len(out))
	}
	f := out[0]
	if f.Category != domain.CategoryDAST || f.RuleID != "xss" || f.Title != "Cross-Site Scripting (XSS)" {
		t.Errorf("finding = %+v", f)
	}
	if f.Severity != domain.SeverityHigh {
		t.Errorf("severity = %s, want high", f.Severity)
	}
	if f.CWE == nil || *f.CWE != 79 {
		t.Errorf("CWE = %v, want 79", f.CWE)
	}
	// Arachni proved the issue against the form's action URL, not the page it
	// was found on — that's the DAST "location".
	if f.FilePath != "http://testfire.net/search.aspx" || f.URL != "http://testfire.net/search.aspx" {
		t.Errorf("location = %q / %q", f.FilePath, f.URL)
	}
	if f.Metadata["affected_input_name"] != "txtSearch" || f.Metadata["proof"] == "" {
		t.Errorf("metadata = %v", f.Metadata)
	}
}

func TestArachniRejectsMalformed(t *testing.T) {
	if _, err := NewArachni().Parse(strings.NewReader(`{"not":"arachni"}`)); err == nil {
		t.Error("want error for JSON without an issues array")
	}
	if _, err := NewArachni().Parse(strings.NewReader("not json")); err == nil {
		t.Error("want error for non-JSON input")
	}
}
