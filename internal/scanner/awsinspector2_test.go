package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures: DefectDojo unittests/scans/aws_inspector2 (BSD-3-Clause)
//   aws-inspector2_many_vul.json  ← aws_inspector2/aws_inspector2_many_vul.json
//   aws-inspector2_lambda.json    ← aws_inspector2/aws_inspector2_package_vuln_metadata.json
//   aws-inspector2_zero_vul.json  ← aws_inspector2/aws_inspector2_zero_vul.json

const inspector2Image = "arn:aws:ecr:us-east-1:012345678901:repository/my-awesome-docker-image/sha256:d667ad018b538adadb5bd1db75836c8561b23bc7d31d9cd8941fa74f5df93802"

func inspector2Find(t *testing.T, fs []ParsedFinding, cve, pkg string) ParsedFinding {
	t.Helper()
	for _, f := range fs {
		if f.RuleID == cve && f.Package == pkg {
			return f
		}
	}
	t.Fatalf("no finding %s on %s in %v", cve, pkg, ruleIDs(fs))
	return ParsedFinding{}
}

func TestAWSInspector2ManyVul(t *testing.T) {
	fs := parseFixture(t, NewAWSInspector2(), "aws-inspector2_many_vul.json")
	// 8 findings, one CLOSED (CVE-2021-3744); the EC2 one lists two
	// packages, CVE-2022-29824 lists libxml2 twice.
	if len(fs) != 8 {
		t.Fatalf("got %d findings, want 8: %v", len(fs), ruleIDs(fs))
	}
	for _, f := range fs {
		if f.RuleID == "CVE-2021-3744" {
			t.Error("CLOSED finding CVE-2021-3744 was mapped")
		}
	}

	k := inspector2Find(t, fs, "CVE-2021-3640", "linux")
	if k.Category != domain.CategoryContainer || k.Severity != domain.SeverityHigh ||
		k.PackageVersion != "4.19.118" || k.FixedVersion != "0:4.19.232-1" ||
		len(k.CVE) != 1 || k.CVE[0] != "CVE-2021-3640" || k.FilePath != inspector2Image ||
		k.URL != "https://security-tracker.debian.org/tracker/CVE-2021-3640" {
		t.Errorf("CVE-2021-3640 = %+v", k)
	}
	if k.CVSS == nil || *k.CVSS != 7.0 {
		t.Errorf("CVE-2021-3640 CVSS = %v, want 7.0", k.CVSS)
	}

	// UNTRIAGED with no score stays visible; "NotAvailable" is not a fix.
	u := inspector2Find(t, fs, "CVE-2024-37021", "linux")
	if u.Severity != domain.SeverityMedium || u.FixedVersion != "" {
		t.Errorf("untriaged = sev %s fix %q", u.Severity, u.FixedVersion)
	}

	py := inspector2Find(t, fs, "CVE-2015-8035", "libxml2-python")
	if py.Category != domain.CategorySCA || py.Severity != domain.SeverityLow ||
		py.PackageVersion != "2.9.1" || py.FixedVersion != "0:2.9.1-6.el7.4" || py.FilePath != "i-0b22a22eec53b9321" {
		t.Errorf("EC2 libxml2-python = %+v", py)
	}
	inspector2Find(t, fs, "CVE-2015-8035", "libxml2")
}

func TestAWSInspector2LambdaCodeAndPackages(t *testing.T) {
	fs := parseFixture(t, NewAWSInspector2(), "aws-inspector2_lambda.json")
	// 27 package findings listing 30 packages + 1 code vulnerability.
	if len(fs) != 31 {
		t.Fatalf("got %d findings, want 31", len(fs))
	}
	code := findRule(t, fs, "python-log-injection")
	if code.Category != domain.CategorySAST || code.Severity != domain.SeverityHigh ||
		code.CWE == nil || *code.CWE != 117 || code.Title != "CWE-117,93 - Log injection" ||
		code.FilePath != "src/project_api/service/api_client.py" || code.Line == nil || *code.Line != 268 {
		t.Errorf("code vuln = %+v", code)
	}

	var req []ParsedFinding
	for _, f := range fs {
		if f.RuleID == "CVE-2024-47081" {
			req = append(req, f)
		}
	}
	if len(req) != 2 {
		t.Fatalf("requests findings = %d, want 2 (one per manifest)", len(req))
	}
	for _, f := range req {
		if f.Category != domain.CategorySCA || f.Severity != domain.SeverityMedium || f.Package != "requests" ||
			f.PackageVersion != "2.32.0" || f.FixedVersion != "2.32.4" || f.Purl != "pkg:pypi/requests@2.32.0" ||
			len(f.CVE) != 1 || f.CVE[0] != "CVE-2024-47081" {
			t.Errorf("requests = %+v", f)
		}
	}
}

func TestAWSInspector2EmptyAndInvalid(t *testing.T) {
	fs := parseFixture(t, NewAWSInspector2(), "aws-inspector2_zero_vul.json")
	if fs == nil || len(fs) != 0 {
		t.Fatalf("zero_vul = %v, want empty slice", fs)
	}
	// DefectDojo's empty_with_error.json is `{}`.
	for _, bad := range []string{`{}`, `[]`, `{"findings": [{"title": "x"}]}`} {
		if _, err := NewAWSInspector2().Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("Parse(%q) accepted non-Inspector input", bad)
		}
	}
}

func TestAWSInspector2SuppressedIsRiskAccepted(t *testing.T) {
	// The many_vul fixture, with one finding's status flipped.
	in := `{"findings":[{"findingArn":"arn:aws:inspector2:us-east-1:012345678901:finding/x","type":"PACKAGE_VULNERABILITY",
	"status":"SUPPRESSED","severity":"HIGH","title":"CVE-2021-3640 - linux",
	"resources":[{"id":"i-0b22a22eec53b9321","type":"AWS_EC2_INSTANCE"}],
	"packageVulnerabilityDetails":{"vulnerabilityId":"CVE-2021-3640","vulnerablePackages":[{"name":"linux","version":"4.19.118"}]}}]}`
	fs, err := NewAWSInspector2().Parse(strings.NewReader(in))
	if err != nil || len(fs) != 1 {
		t.Fatalf("Parse = %v, %v", fs, err)
	}
	if fs[0].Metadata["remote_triage"] != string(domain.FindingRiskAccepted) {
		t.Errorf("remote_triage = %v", fs[0].Metadata["remote_triage"])
	}
}
