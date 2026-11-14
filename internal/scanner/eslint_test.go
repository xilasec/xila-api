package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures (DefectDojo unit-test scans, BSD-3-Clause):
//
//	eslint_scan.json       ← unittests/scans/eslint/scan.json
//	eslint_empty.json      ← unittests/scans/eslint/empty.json
//	eslint_no_finding.json ← unittests/scans/eslint/no_finding.json
func TestESLintParse(t *testing.T) {
	out := parseFixture(t, NewESLint(), "eslint_scan.json")
	if len(out) != 2 {
		t.Fatalf("got %d findings, want 2", len(out))
	}
	const path = "/Users/omerlh/dev/juice-shop/routes/basketItems.js"
	err, warn := out[0], out[1]
	if err.RuleID != "security/detect-object-injection" || err.Severity != domain.SeverityMedium ||
		err.FilePath != path || err.Line == nil || *err.Line != 19 ||
		err.Description != "Generic Object Injection Sink" || err.Category != domain.CategorySAST {
		t.Errorf("error-level = %+v", err)
	}
	if warn.RuleID != "security/detect-object-injection" || warn.Severity != domain.SeverityLow ||
		warn.FilePath != path || *warn.Line != 20 || warn.Metadata["column"] != 25 {
		t.Errorf("warning-level = %+v", warn)
	}
	for _, name := range []string{"eslint_empty.json", "eslint_no_finding.json"} {
		if got := parseFixture(t, NewESLint(), name); got == nil || len(got) != 0 {
			t.Errorf("%s: got %v", name, got)
		}
	}
}

func TestESLintFatalAndMalformed(t *testing.T) {
	in := `[{"filePath":"/src/a.js","messages":[
	 {"ruleId":null,"fatal":true,"severity":2,"message":"Parsing error: Unexpected token","line":3,"column":7},
	 {"ruleId":"no-eval","severity":0,"message":"off","line":4,"column":1}]}]`
	out, err := NewESLint().Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].RuleID != "eslint" || out[0].Severity != domain.SeverityMedium || *out[0].Line != 3 {
		t.Fatalf("got %+v", out)
	}
	if _, err := NewESLint().Parse(strings.NewReader(`{"queries":[]}`)); err == nil {
		t.Error("expected error for non-ESLint input")
	}
	if _, err := NewESLint().Parse(strings.NewReader(`[{"code":"DL3008","line":1}]`)); err == nil {
		t.Error("expected error for hadolint input")
	}
}
