package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures: DefectDojo unittests/scans/awssecurityhub (BSD-3-Clause)
//   aws-security-hub_config_passed.json             ← awssecurityhub/config_many_findings.json
//   aws-security-hub_config_multiple_resources.json ← awssecurityhub/config_multiple_resources.json
//   aws-security-hub_guardduty.json                 ← awssecurityhub/guardduty.json
//   aws-security-hub_inspector_ecr.json             ← awssecurityhub/inspector_ecr.json

func TestAWSSecurityHubPassedControlsSkipped(t *testing.T) {
	// All three controls in this export have Compliance.Status PASSED.
	fs := parseFixture(t, NewAWSSecurityHub(), "aws-security-hub_config_passed.json")
	if fs == nil || len(fs) != 0 {
		t.Fatalf("got %v, want an empty slice", ruleIDs(fs))
	}
}

func TestAWSSecurityHubConfigMultipleResources(t *testing.T) {
	fs := parseFixture(t, NewAWSSecurityHub(), "aws-security-hub_config_multiple_resources.json")
	// EC2.2 fails on 3 resources, S3.8 on 2: one finding per failing resource.
	if len(fs) != 5 {
		t.Fatalf("got %d findings, want 5: %v", len(fs), ruleIDs(fs))
	}
	var s3 []ParsedFinding
	for _, f := range fs {
		if f.RuleID == "aws-foundational-security-best-practices/v/1.0.0/S3.8" {
			s3 = append(s3, f)
		}
	}
	if len(s3) != 2 {
		t.Fatalf("S3.8 findings = %d, want 2", len(s3))
	}
	b := s3[0]
	if b.Category != domain.CategoryCloud || b.Severity != domain.SeverityMedium ||
		b.Title != "S3.8 S3 Block Public Access setting should be enabled at the bucket level" ||
		b.FilePath != "arn:aws:s3:::zeta-reports-bucket" || b.Metadata["resource_arn"] != "arn:aws:s3:::zeta-reports-bucket" {
		t.Errorf("S3.8 = %+v", b)
	}
	if refs, _ := b.Metadata["references"].([]string); len(refs) != 1 || refs[0] != "https://docs.aws.amazon.com/console/securityhub/S3.8/remediation" {
		t.Errorf("S3.8 references = %v", b.Metadata["references"])
	}
	if s3[1].FilePath != "arn:aws:s3:::alpha-artifacts-bucket" {
		t.Errorf("second S3.8 resource = %s", s3[1].FilePath)
	}
	ec2 := findRule(t, fs, "aws-foundational-security-best-practices/v/1.0.0/EC2.2")
	if ec2.Severity != domain.SeverityHigh {
		t.Errorf("EC2.2 severity = %s", ec2.Severity)
	}
}

func TestAWSSecurityHubGuardDuty(t *testing.T) {
	fs := parseFixture(t, NewAWSSecurityHub(), "aws-security-hub_guardduty.json")
	if len(fs) != 4 {
		t.Fatalf("got %d findings, want 4: %v", len(fs), ruleIDs(fs))
	}
	ssh := findRule(t, fs, "TTPs/Initial Access/UnauthorizedAccess:EC2-SSHBruteForce")
	if ssh.Category != domain.CategoryCloud || ssh.Severity != domain.SeverityLow ||
		ssh.Title != "1.2.9.9 is performing SSH brute force attacks against i-1234567890." ||
		ssh.FilePath != "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890" ||
		ssh.URL != "https://us-east-1.console.aws.amazon.com/guardduty/home?region=us-east-1#/findings?macros=current&fId=4897489798789" ||
		ssh.Metadata["generator_id"] != "arn:aws:guardduty:us-east-1:123456789012:detector/123456789" {
		t.Errorf("SSH brute force = %+v", ssh)
	}
}

func TestAWSSecurityHubInspectorECR(t *testing.T) {
	fs := parseFixture(t, NewAWSSecurityHub(), "aws-security-hub_inspector_ecr.json")
	// 7 findings listing 12 packages; three certifi entries (two versions)
	// share app/poetry.lock and fold into one, so 12 entries are 10 findings.
	if len(fs) != 10 {
		t.Fatalf("got %d findings, want 10: %v", len(fs), ruleIDs(fs))
	}
	semver := findRule(t, fs, "CVE-2022-25883")
	if semver.Category != domain.CategoryContainer || semver.Severity != domain.SeverityHigh ||
		semver.Package != "semver" || semver.PackageVersion != "7.5.1" || semver.FixedVersion != "7.5.2" ||
		semver.Purl != "pkg:npm/semver@7.5.1" || len(semver.CVE) != 1 || semver.CVE[0] != "CVE-2022-25883" {
		t.Errorf("semver = %+v", semver)
	}
	if semver.CVSS == nil || *semver.CVSS != 7.5 {
		t.Errorf("semver CVSS = %v", semver.CVSS)
	}
	if !strings.HasPrefix(semver.FilePath, "arn:aws:ecr:eu-central-1:123456789012:repository/repo-nodepkg/") ||
		semver.Metadata["package_path"] != "usr/local/lib/node_modules/npm/node_modules/semver/package.json" {
		t.Errorf("semver location = %s / %v", semver.FilePath, semver.Metadata["package_path"])
	}
	kafka := findRule(t, fs, "CVE-2023-25194")
	if kafka.Package != "org.apache.kafka:kafka-clients" || kafka.FixedVersion != "3.4.0" ||
		kafka.Purl != "pkg:maven/org.apache.kafka/kafka-clients@3.1.2" || kafka.Severity != domain.SeverityHigh {
		t.Errorf("kafka = %+v", kafka)
	}
}

func TestAWSSecurityHubWorkflowAndInvalid(t *testing.T) {
	// config_one_finding_active.json's IAM.5 finding with its workflow state
	// varied.
	finding := func(workflow, record string) string {
		return `{"Findings":[{"Id":"arn:aws:securityhub:us-east-1:012345678912:subscription/aws-foundational-security-best-practices/v/1.0.0/IAM.5/finding/x",
		"GeneratorId":"aws-foundational-security-best-practices/v/1.0.0/IAM.5","Title":"IAM.5 MFA should be enabled",
		"Severity":{"Label":"MEDIUM"},"Compliance":{"Status":"FAILED"},"RecordState":"` + record + `",
		"Workflow":{"Status":"` + workflow + `"},"Resources":[{"Id":"AWS::::Account:012345678912","Type":"AwsAccount"}]}]}`
	}
	fs, err := NewAWSSecurityHub().Parse(strings.NewReader(finding("SUPPRESSED", "ACTIVE")))
	if err != nil || len(fs) != 1 || fs[0].Metadata["remote_triage"] != string(domain.FindingRiskAccepted) {
		t.Fatalf("suppressed = %+v, %v", fs, err)
	}
	for _, tc := range [][2]string{{"NEW", "ARCHIVED"}, {"RESOLVED", "ACTIVE"}} {
		fs, err := NewAWSSecurityHub().Parse(strings.NewReader(finding(tc[0], tc[1])))
		if err != nil || len(fs) != 0 {
			t.Errorf("workflow %s record %s = %v, %v; want skipped", tc[0], tc[1], fs, err)
		}
	}
	for _, bad := range []string{`{}`, `[]`, `{"Findings":[{"Title":"x"}]}`} {
		if _, err := NewAWSSecurityHub().Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("Parse(%q) accepted non-ASFF input", bad)
		}
	}
}
