package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures (DefectDojo unit-test scans, BSD-3-Clause):
//
//	kics_many.json        ← unittests/scans/kics/many_findings.json
//	kics_no_findings.json ← unittests/scans/kics/no_findings.json
func TestKICSParse(t *testing.T) {
	out := parseFixture(t, NewKICS(), "kics_many.json")
	// 18 file locations; the 4 "RBAC Wildcard In Rule" matches on rbac.yaml:20
	// share one location and fold into one finding.
	if len(out) != 15 {
		t.Fatalf("got %d findings, want 15", len(out))
	}
	byRule := map[string]ParsedFinding{}
	for _, f := range out {
		byRule[f.RuleID] = f
	}

	secret := byRule["f996f3cb-00fc-480c-8973-8ab04d44a8cc"]
	if secret.Title != "Passwords And Secrets In Infrastructure Code" || secret.Severity != domain.SeverityHigh ||
		secret.FilePath != "test/charts/example/terraform/main.tf" || secret.Line == nil || *secret.Line != 25 ||
		secret.Category != domain.CategoryIaC {
		t.Errorf("secret = %+v", secret)
	}
	if secret.Metadata["search_key"] != "module.aws_reverse_proxy.basic_auth_password" ||
		secret.Metadata["references"] != "https://kics.io/" {
		t.Errorf("secret metadata = %v", secret.Metadata)
	}

	versioning := byRule["568a4d22-3517-44a6-a7ad-6a7eed88722c"]
	if versioning.Title != "S3 Bucket Without Versioning" || versioning.Severity != domain.SeverityMedium ||
		versioning.FilePath != "test/charts/example/terraform/s3.tf" || *versioning.Line != 5 {
		t.Errorf("versioning = %+v", versioning)
	}

	rbac := byRule["6b896afb-ca07-467a-b256-1a0077a1c08e"]
	if rbac.Severity != domain.SeverityLow || rbac.FilePath != "test/charts/example/templates/rbac.yaml" ||
		*rbac.Line != 20 || rbac.Metadata["occurrences"] != 4 {
		t.Errorf("rbac = %+v", rbac)
	}
	if !strings.Contains(rbac.Description, "rules[0].apiGroups") || !strings.Contains(rbac.Description, "rules[1].verbs") {
		t.Errorf("rbac description should carry every merged match: %q", rbac.Description)
	}

	if empty := parseFixture(t, NewKICS(), "kics_no_findings.json"); empty == nil || len(empty) != 0 {
		t.Errorf("no_findings: got %v", empty)
	}
}

func TestKICSSkipsInfoAndRejectsOtherFormats(t *testing.T) {
	in := `{"queries":[
	 {"query_name":"Info Q","query_id":"i1","severity":"INFO","files":[{"file_name":"a.tf","line":1}]},
	 {"query_name":"Trace Q","query_id":"t1","severity":"TRACE","files":[{"file_name":"a.tf","line":2}]},
	 {"query_name":"Low Q","query_id":"l1","severity":"LOW","cwe":"284","files":[{"file_name":"a.tf","line":3}]}]}`
	out, err := NewKICS().Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 || out[0].RuleID != "l1" || out[0].CWE == nil || *out[0].CWE != 284 {
		t.Fatalf("got %+v", out)
	}
	if _, err := NewKICS().Parse(strings.NewReader(`{"results":[]}`)); err == nil {
		t.Error("expected error for non-KICS input")
	}
}
