package scanner

import (
	"os"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

const sampleTrivyReport = `{
  "SchemaVersion": 2,
  "ArtifactName": "app",
  "Results": [
    {
      "Target": "package-lock.json",
      "Class": "lang-pkgs",
      "Type": "npm",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2020-8203",
          "PkgName": "lodash",
          "InstalledVersion": "4.17.15",
          "FixedVersion": "4.17.19",
          "Title": "Prototype pollution in lodash",
          "Description": "lodash before 4.17.19 is vulnerable to prototype pollution.",
          "Severity": "HIGH",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2020-8203",
          "CweIDs": ["CWE-770", "CWE-1321"]
        }
      ]
    },
    {
      "Target": "Dockerfile",
      "Class": "config",
      "Type": "dockerfile",
      "Misconfigurations": [
        {
          "ID": "DS002",
          "AVDID": "AVD-DS-0002",
          "Title": "Image user should not be 'root'",
          "Description": "Running containers with 'root' user is dangerous.",
          "Resolution": "Add 'USER <non root>' to the Dockerfile.",
          "Severity": "MEDIUM",
          "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002"
        }
      ]
    },
    {
      "Target": ".env",
      "Class": "secret",
      "Secrets": [
        {
          "RuleID": "aws-access-key-id",
          "Category": "AWS",
          "Title": "AWS Access Key ID",
          "Severity": "CRITICAL",
          "StartLine": 3,
          "Match": "AKIA************"
        }
      ]
    }
  ]
}`

func TestTrivyParse(t *testing.T) {
	findings, err := Trivy{}.Parse(strings.NewReader(sampleTrivyReport))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(findings))
	}

	byCategory := map[domain.Category]ParsedFinding{}
	for _, f := range findings {
		byCategory[f.Category] = f
	}

	sca, ok := byCategory[domain.CategorySCA]
	if !ok {
		t.Fatal("missing SCA finding")
	}
	if sca.Severity != domain.SeverityHigh {
		t.Errorf("SCA severity = %q, want high", sca.Severity)
	}
	if sca.Package != "lodash" || sca.PackageVersion != "4.17.15" || sca.FixedVersion != "4.17.19" {
		t.Errorf("SCA package fields wrong: %+v", sca)
	}
	if sca.CWE == nil || *sca.CWE != 770 {
		t.Errorf("SCA CWE = %v, want 770", sca.CWE)
	}
	if len(sca.CVE) != 1 || sca.CVE[0] != "CVE-2020-8203" {
		t.Errorf("SCA CVE = %v", sca.CVE)
	}

	iac, ok := byCategory[domain.CategoryIaC]
	if !ok {
		t.Fatal("missing IaC finding")
	}
	if iac.Severity != domain.SeverityMedium || iac.RuleID != "AVD-DS-0002" {
		t.Errorf("IaC finding wrong: %+v", iac)
	}

	secret, ok := byCategory[domain.CategorySecret]
	if !ok {
		t.Fatal("missing secret finding")
	}
	if secret.Severity != domain.SeverityCritical || secret.Line == nil || *secret.Line != 3 {
		t.Errorf("secret finding wrong: %+v", secret)
	}
}

func TestMapTrivySeverityUnknown(t *testing.T) {
	if got := mapTrivySeverity("UNKNOWN"); got != domain.SeverityInfo {
		t.Errorf("UNKNOWN mapped to %q, want info", got)
	}
}

func TestTrivyCVSS(t *testing.T) {
	// nvd V3 is preferred over other providers.
	report := `{"Results":[{"Target":"go.mod","Type":"gomod","Vulnerabilities":[
	  {"VulnerabilityID":"CVE-1","PkgName":"p","InstalledVersion":"1","Severity":"HIGH",
	   "CVSS":{"redhat":{"V3Score":6.5},"nvd":{"V3Score":9.8,"V2Score":7.5}}}]}]}`
	findings, err := Trivy{}.Parse(strings.NewReader(report))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(findings) != 1 || findings[0].CVSS == nil {
		t.Fatalf("expected a CVSS score, got %+v", findings)
	}
	if *findings[0].CVSS != 9.8 {
		t.Errorf("CVSS = %v, want 9.8 (nvd V3)", *findings[0].CVSS)
	}
}

// An image scan tags each vulnerability with the image, its OS and package
// class, which remediation uses to group distro packages into one rebuild.
func TestTrivyImageMetadata(t *testing.T) {
	f, err := os.Open("testdata/trivy_image.json")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got, err := NewTrivy().Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 6 {
		t.Fatalf("findings = %d, want 6", len(got))
	}
	libc := got[0]
	if libc.Package != "libc6" || libc.Metadata["image"] != "python:3.11-slim" || libc.Metadata["os"] != "debian 12.5" ||
		libc.Metadata["pkg_class"] != "os-pkgs" || libc.Metadata["layer_diff_id"] != "sha256:ae134c61b154341a1dd932bd88cb44e805837508284e5d60c9f4fdbde8f8c5b4" {
		t.Errorf("libc6 metadata = %+v", libc.Metadata)
	}
	if pip := got[4]; pip.Package != "pip" || pip.Metadata["pkg_class"] != "lang-pkgs" || pip.Metadata["image"] != "python:3.11-slim" {
		t.Errorf("pip metadata = %+v", pip.Metadata)
	}
}
