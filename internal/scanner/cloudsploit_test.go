package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixture: DefectDojo unittests/scans/cloudsploit/cloudsploit_many_vul.json (BSD-3-Clause).
func TestCloudSploitParse(t *testing.T) {
	out := parseFixture(t, NewCloudSploit(), "cloudsploit_many_vul.json")
	// 6 entries: stackTerminationProtection(FAIL), cloudtrailBucketDelete(WARN,
	// skipped), flowLogsEnabled×2(FAIL), acmValidation(OK, skipped),
	// cloudfrontWafEnabled(FAIL) = 4 findings.
	if len(out) != 4 {
		t.Fatalf("got %d findings, want 4: %v", len(out), out)
	}
	for _, f := range out {
		if f.Category != domain.CategoryCloud || f.Severity != domain.SeverityMedium {
			t.Errorf("finding = %+v, want cloud/medium", f)
		}
	}

	stack := findByRule(t, out, "stackTerminationProtection")
	if stack.FilePath != "arn:aws:cloudformation:us-east-1:0123456789012:stack/myStack-3ab9f838-96cf-4943-ab90-86cce3a83473/d52a5180-f519-11eb" {
		t.Errorf("stack resource = %q", stack.FilePath)
	}
	if stack.Metadata["region"] != "us-east-1" || stack.Metadata["cloud_category"] != "CloudFormation" {
		t.Errorf("stack metadata = %v", stack.Metadata)
	}

	var flowLogs int
	for _, f := range out {
		if f.RuleID == "flowLogsEnabled" {
			flowLogs++
		}
	}
	if flowLogs != 2 {
		t.Errorf("flowLogsEnabled findings = %d, want 2 (one per VPC)", flowLogs)
	}

	// region is a list (global service) rather than a plain string on this check.
	cf := findByRule(t, out, "cloudfrontWafEnabled")
	if cf.Metadata["region"] != "global" {
		t.Errorf("cloudfront region = %v, want \"global\" (flattened list)", cf.Metadata["region"])
	}
}

func TestCloudSploitRejectsMalformed(t *testing.T) {
	if _, err := NewCloudSploit().Parse(strings.NewReader("not json")); err == nil {
		t.Error("want error for non-JSON input")
	}
}
