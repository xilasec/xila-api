package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures: DefectDojo unittests/scans/jfrog_xray_unified (BSD-3-Clause)
//   jfrog-xray_many_vulns.json   ← jfrog_xray_unified/many_vulns.json
//   jfrog-xray_issue_13628.json  ← jfrog_xray_unified/issue_13628.json
//   jfrog-xray_no_vuln.json      ← jfrog_xray_unified/no_vuln.json

func TestJFrogXrayManyVulns(t *testing.T) {
	fs := parseFixture(t, NewJFrogXray(), "jfrog-xray_many_vulns.json")
	if len(fs) != 3 {
		t.Fatalf("got %d findings, want 3: %v", len(fs), ruleIDs(fs))
	}
	jinja := findRule(t, fs, "XRAY-139239")
	if jinja.Package != "Jinja2" || jinja.PackageVersion != "2.11.2" || jinja.FixedVersion != "2.11.3" ||
		jinja.Purl != "pkg:pypi/jinja2@2.11.2" {
		t.Errorf("jinja package = %q %q fix %q purl %q", jinja.Package, jinja.PackageVersion, jinja.FixedVersion, jinja.Purl)
	}
	if jinja.Severity != domain.SeverityMedium || jinja.Category != domain.CategorySCA ||
		len(jinja.CVE) != 1 || jinja.CVE[0] != "CVE-2020-28493" {
		t.Errorf("jinja = sev %s cat %s cve %v", jinja.Severity, jinja.Category, jinja.CVE)
	}
	if jinja.CVSS == nil || *jinja.CVSS != 5.3 {
		t.Errorf("jinja CVSS = %v, want 5.3", jinja.CVSS)
	}

	// The vulnerable component, not the impacted artifact, is the package.
	jq := findRule(t, fs, "XRAY-97245")
	if jq.Package != "jquery" || jq.PackageVersion != "3.4.1" || jq.FixedVersion != "3.5.0" ||
		jq.Purl != "pkg:npm/jquery@3.4.1" || len(jq.CVE) != 1 || jq.CVE[0] != "CVE-2020-11023" {
		t.Errorf("jquery = %+v", jq)
	}
	if jq.Metadata["impacted_artifact"] != "pypi://Werkzeug:1.0.1" {
		t.Errorf("impacted artifact = %v", jq.Metadata["impacted_artifact"])
	}
	if c := findRule(t, fs, "XRAY-97257").CVE; len(c) != 1 || c[0] != "CVE-2020-11022" {
		t.Errorf("XRAY-97257 CVE = %v", c)
	}
}

func TestJFrogXrayBuildArtifactAndEmpty(t *testing.T) {
	fs := parseFixture(t, NewJFrogXray(), "jfrog-xray_issue_13628.json")
	if len(fs) != 1 {
		t.Fatalf("got %d findings, want 1", len(fs))
	}
	ip := fs[0]
	if ip.RuleID != "XRAY-123" || ip.Severity != domain.SeverityCritical || ip.Package != "ip" ||
		ip.PackageVersion != "2.0.0" || ip.FixedVersion != "2.0.1" || len(ip.CVE) != 1 || ip.CVE[0] != "CVE-2023-42282" {
		t.Errorf("ip = %+v", ip)
	}

	empty := parseFixture(t, NewJFrogXray(), "jfrog-xray_no_vuln.json")
	if empty == nil || len(empty) != 0 {
		t.Fatalf("no_vuln = %v, want empty slice", empty)
	}
	for _, bad := range []string{`{}`, `[]`, `{"rows": [{"severity": "High"}]}`} {
		if _, err := NewJFrogXray().Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("Parse(%q) accepted non-Xray input", bad)
		}
	}
}

func TestJFrogXrayComponent(t *testing.T) {
	for _, tc := range []struct{ id, scheme, name, version string }{
		{"npm://lodash:4.17.15", "npm", "lodash", "4.17.15"},
		{"gav://org.apache.logging.log4j:log4j-core:2.14.1", "gav", "org.apache.logging.log4j:log4j-core", "2.14.1"},
		{"rpm://7:curl:16:7.29.0-54.el7_7.2", "rpm", "curl", "16:7.29.0-54.el7_7.2"},
		{"rpm://7:binutils:0:2.27-41.base.el7_7.3", "rpm", "binutils", "2.27-41.base.el7_7.3"},
		{"deb://debian:buster:libc6:2.28-10", "deb", "libc6", "2.28-10"},
	} {
		s, n, v := jfrogXrayComponent(tc.id)
		if s != tc.scheme || n != tc.name || v != tc.version {
			t.Errorf("%s → %q %q %q", tc.id, s, n, v)
		}
	}
}
