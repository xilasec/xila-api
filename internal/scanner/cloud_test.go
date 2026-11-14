package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

const prowlerSample = `[
  {
    "Provider": "aws", "CheckID": "iam_root_mfa_enabled", "CheckTitle": "Ensure MFA on root",
    "ServiceName": "iam", "Severity": "critical", "ResourceType": "AwsIamUser",
    "ResourceId": "arn:aws:iam::123456789012:root", "Status": "FAIL",
    "StatusExtended": "Root account does not have MFA.", "Region": "us-east-1",
    "AccountId": "123456789012", "Remediation": { "Recommendation": { "Text": "Enable MFA", "Url": "https://docs" } },
    "Compliance": { "CIS-1.5": ["1.5"] }
  },
  {
    "Provider": "aws", "CheckID": "s3_bucket_public", "CheckTitle": "S3 not public",
    "Severity": "high", "ResourceId": "arn:aws:s3:::my-bucket", "Status": "PASS"
  }
]`

func TestProwlerParse(t *testing.T) {
	out, err := Prowler{}.Parse(strings.NewReader(prowlerSample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(out) != 1 { // only the FAIL becomes a finding
		t.Fatalf("findings = %d, want 1 (PASS skipped)", len(out))
	}
	f := out[0]
	if f.Category != domain.CategoryCloud || f.Severity != domain.SeverityCritical {
		t.Errorf("finding = %+v, want cloud/critical", f)
	}
	if f.RuleID != "iam_root_mfa_enabled" { // becomes rule_id for compliance mapping
		t.Errorf("rule_id = %q", f.RuleID)
	}
	if f.FilePath != "arn:aws:iam::123456789012:root" {
		t.Errorf("resource = %q", f.FilePath)
	}
	if f.URL != "https://docs" || f.Metadata["service"] != "iam" {
		t.Errorf("metadata/url wrong: %+v", f)
	}
}

const kubescapeSample = `{
  "results": [
    { "resourceID": "apps/v1/Deployment/default/web",
      "controls": [
        { "controlID": "C-0016", "name": "Allow privilege escalation", "status": { "status": "failed" } },
        { "controlID": "C-0017", "name": "Immutable filesystem", "status": { "status": "passed" } }
      ] }
  ],
  "resources": [
    { "resourceID": "apps/v1/Deployment/default/web",
      "object": { "kind": "Deployment", "metadata": { "name": "web", "namespace": "default" } } }
  ],
  "summaryDetails": { "controls": { "C-0016": { "name": "Allow privilege escalation", "severity": "High" } } }
}`

func TestKubescapeParse(t *testing.T) {
	out, err := Kubescape{}.Parse(strings.NewReader(kubescapeSample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(out) != 1 { // only the failed control
		t.Fatalf("findings = %d, want 1", len(out))
	}
	f := out[0]
	if f.Category != domain.CategoryKubernetes || f.RuleID != "C-0016" || f.Severity != domain.SeverityHigh {
		t.Errorf("finding = %+v, want kubernetes/C-0016/high", f)
	}
	if f.FilePath != "Deployment default/web" {
		t.Errorf("location = %q, want 'Deployment default/web'", f.FilePath)
	}
}

const kubeauditSample = `{"level":"error","msg":"container allows privilege escalation","AuditResultName":"AllowPrivilegeEscalationNil","ResourceKind":"Deployment","ResourceName":"web","ResourceNamespace":"default","Container":"app"}
{"level":"warning","msg":"no apparmor annotation","AuditResultName":"AppArmorAnnotationMissing","ResourceKind":"Pod","ResourceName":"db","ResourceNamespace":"prod"}
{"level":"info","msg":"audit complete"}`

func TestKubeauditParse(t *testing.T) {
	out, err := Kubeaudit{}.Parse(strings.NewReader(kubeauditSample))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(out) != 2 { // info entry skipped
		t.Fatalf("findings = %d, want 2", len(out))
	}
	if out[0].Severity != domain.SeverityHigh || out[0].RuleID != "AllowPrivilegeEscalationNil" {
		t.Errorf("first = %+v, want high/AllowPrivilegeEscalationNil", out[0])
	}
	if out[0].FilePath != "Deployment default/web" {
		t.Errorf("location = %q", out[0].FilePath)
	}
	if out[1].Severity != domain.SeverityMedium || out[1].Category != domain.CategoryKubernetes {
		t.Errorf("second = %+v, want medium/kubernetes", out[1])
	}
}
