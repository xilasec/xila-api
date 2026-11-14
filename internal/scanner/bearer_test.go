package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures: DefectDojo unittests/scans/bearer_cli (BSD-3-Clause)
//   bearer_many_vul.json ← bearer_cli/bearer_cli_many_vul.json
//   bearer_one_vul.json  ← bearer_cli/bearer_cli_one_vul.json

func TestBearerManyVul(t *testing.T) {
	fs := parseFixture(t, NewBearer(), "bearer_many_vul.json")
	if len(fs) != 4 {
		t.Fatalf("got %d findings, want 4: %v", len(fs), ruleIDs(fs))
	}
	xss := fs[0]
	if xss.RuleID != "javascript_lang_dangerous_insert_html" ||
		xss.Title != "Unsanitized user input in dynamic HTML insertion (XSS)" ||
		xss.Severity != domain.SeverityHigh || xss.Category != domain.CategorySAST {
		t.Errorf("xss = %+v", xss)
	}
	if xss.CWE == nil || *xss.CWE != 79 {
		t.Errorf("xss CWE = %v, want 79", xss.CWE)
	}
	if xss.FilePath != "js/adminer/editing.js" || xss.Line == nil || *xss.Line != 581 {
		t.Errorf("xss location = %s:%v", xss.FilePath, xss.Line)
	}
	refs, _ := xss.Metadata["references"].([]string)
	if len(refs) != 1 || refs[0] != "https://docs.bearer.com/reference/rules/javascript_lang_dangerous_insert_html" {
		t.Errorf("xss references = %v", xss.Metadata["references"])
	}

	var redirects int
	for _, f := range fs {
		if f.RuleID != "php_lang_open_redirect" {
			continue
		}
		redirects++
		if f.Severity != domain.SeverityMedium || f.CWE == nil || *f.CWE != 601 {
			t.Errorf("redirect = %+v", f)
		}
		if f.FilePath == "main.php" && (f.Line == nil || *f.Line != 40) {
			t.Errorf("main.php line = %v, want 40", f.Line)
		}
		if f.FilePath == "redirect.php" && (f.Line == nil || *f.Line != 42) {
			t.Errorf("redirect.php line = %v, want 42", f.Line)
		}
	}
	if redirects != 2 {
		t.Errorf("got %d open-redirect findings, want 2", redirects)
	}
}

func TestBearerOneVulAndEmpty(t *testing.T) {
	fs := parseFixture(t, NewBearer(), "bearer_one_vul.json")
	if len(fs) != 1 || fs[0].FilePath != "js/adminer/editing.js" || *fs[0].Line != 581 {
		t.Fatalf("one vul = %+v", fs)
	}
	empty, err := NewBearer().Parse(strings.NewReader(`{}`))
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("clean report = %v, %v; want empty slice", empty, err)
	}
	for _, bad := range []string{`[]`, `{"findings": []}`, `not json`} {
		if _, err := NewBearer().Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("Parse(%q) accepted non-Bearer input", bad)
		}
	}
}
