package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures (DefectDojo unit-test scans, BSD-3-Clause):
//
//	njsscan_many.json    ← unittests/scans/njsscan/njsscan_many_vuln.json
//	njsscan_no_vuln.json ← unittests/scans/njsscan/njsscan_no_vuln.json
func TestNJSScanParse(t *testing.T) {
	out := parseFixture(t, NewNJSScan(), "njsscan_many.json")
	// eval_nodejs (1) + express_xss (2) + generic_os_command_exec (1) + node_md5 (1).
	if len(out) != 5 {
		t.Fatalf("got %d findings, want 5", len(out))
	}
	find := func(rule string, line int) ParsedFinding {
		t.Helper()
		for _, f := range out {
			if f.RuleID == rule && f.Line != nil && *f.Line == line {
				return f
			}
		}
		t.Fatalf("%s@%d missing", rule, line)
		return ParsedFinding{}
	}

	eval := find("eval_nodejs", 14)
	if eval.Severity != domain.SeverityHigh || eval.CWE == nil || *eval.CWE != 95 || eval.FilePath != "server.js" ||
		eval.Category != domain.CategorySAST || !strings.Contains(eval.Description, "User controlled data in eval()") {
		t.Errorf("eval = %+v", eval)
	}
	if eval.Metadata["match_string"] != "  res.send(eval(req.query.expression));" || eval.Metadata["owasp_web"] != "A1: Injection" {
		t.Errorf("eval metadata = %v", eval.Metadata)
	}

	exec := find("generic_os_command_exec", 8)
	if exec.Severity != domain.SeverityHigh || *exec.CWE != 78 || exec.Metadata["end_line"] != 10 {
		t.Errorf("exec = %+v", exec)
	}

	md5 := find("node_md5", 18)
	if md5.Severity != domain.SeverityMedium || *md5.CWE != 327 || md5.FilePath != "server.js" {
		t.Errorf("md5 = %+v", md5)
	}
	find("express_xss", 14)
	find("express_xss", 18)

	if empty := parseFixture(t, NewNJSScan(), "njsscan_no_vuln.json"); empty == nil || len(empty) != 0 {
		t.Errorf("no_vuln: got %v", empty)
	}
	if _, err := NewNJSScan().Parse(strings.NewReader(`{"queries":[]}`)); err == nil {
		t.Error("expected error for non-njsscan input")
	}
}
