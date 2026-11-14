package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixture (DefectDojo unit-test scans, BSD-3-Clause):
//
//	hadolint_many.json ← unittests/scans/hadolint/many_dockerfile.json
func TestHadolintParse(t *testing.T) {
	out := parseFixture(t, NewHadolint(), "hadolint_many.json")
	// 12 entries: 9 warnings, 3 info (DL3015) which are skipped.
	if len(out) != 9 {
		t.Fatalf("got %d findings, want 9", len(out))
	}
	for _, f := range out {
		if f.RuleID == "DL3015" {
			t.Errorf("info-level DL3015 should be skipped: %+v", f)
		}
		if f.Category != domain.CategoryIaC {
			t.Errorf("category = %s", f.Category)
		}
	}
	first := out[0]
	if first.RuleID != "DL3008" || first.Severity != domain.SeverityLow ||
		first.FilePath != `django-DefectDojo\Dockerfile.django` || first.Line == nil || *first.Line != 9 ||
		!strings.Contains(first.Title, "Pin versions in apt get install") {
		t.Errorf("first = %+v", first)
	}
	var root *ParsedFinding
	for i := range out {
		if out[i].RuleID == "DL3002" {
			root = &out[i]
		}
	}
	if root == nil {
		t.Fatal("DL3002 missing")
	}
	if root.FilePath != `django-DefectDojo\Dockerfile.nginx` || *root.Line != 24 ||
		root.Description != "Last USER should not be root" || root.Severity != domain.SeverityLow {
		t.Errorf("DL3002 = %+v", root)
	}
}

func TestHadolintLevels(t *testing.T) {
	in := `[{"line":3,"code":"DL3000","message":"Use absolute WORKDIR","column":1,"file":"Dockerfile","level":"error"},
	{"line":4,"code":"SC2086","message":"Double quote","column":1,"file":"Dockerfile","level":"style"}]`
	out, err := NewHadolint().Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].Severity != domain.SeverityMedium || out[0].RuleID != "DL3000" {
		t.Fatalf("got %+v", out)
	}
	if out, err := NewHadolint().Parse(strings.NewReader(`[]`)); err != nil || out == nil || len(out) != 0 {
		t.Errorf("empty report: %v %v", out, err)
	}
	if _, err := NewHadolint().Parse(strings.NewReader(`{"queries":[]}`)); err == nil {
		t.Error("expected error for non-hadolint input")
	}
	if _, err := NewHadolint().Parse(strings.NewReader(`[{"filePath":"a.js","messages":[]}]`)); err == nil {
		t.Error("expected error for eslint input")
	}
}
