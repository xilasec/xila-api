package scanner

import (
	"slices"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures (DefectDojo unit-test scans, BSD-3-Clause,
// https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans):
//
//	openvas_many.xml  ← openvas/many_vuln.xml
//	openvas_empty.xml ← openvas/no_vuln.xml

func openvasByRule(t *testing.T, fs []ParsedFinding, rule, path string) ParsedFinding {
	t.Helper()
	for _, f := range fs {
		if f.RuleID == rule && f.FilePath == path {
			return f
		}
	}
	t.Fatalf("no finding %s at %s in %v", rule, path, ruleIDs(fs))
	return ParsedFinding{}
}

func TestOpenVASParse(t *testing.T) {
	fs := parseFixture(t, NewOpenVAS(), "openvas_many.xml")
	if len(fs) != 44 {
		t.Fatalf("got %d findings, want 44", len(fs))
	}

	distcc := openvasByRule(t, fs, "1.3.6.1.4.1.25623.1.0.103553", "192.168.1.1001:3632/tcp")
	if distcc.Title != "DistCC RCE Vulnerability (CVE-2004-2687)" || distcc.Severity != domain.SeverityHigh ||
		!slices.Equal(distcc.CVE, []string{"CVE-2004-2687"}) || distcc.CVSS == nil || *distcc.CVSS != 9.3 {
		t.Errorf("distcc = %q %s %v %v", distcc.Title, distcc.Severity, distcc.CVE, distcc.CVSS)
	}
	if distcc.URL != "192.168.1.1001" || distcc.Metadata["hostname"] != "b6b9f466d63" || distcc.Metadata["port"] != "3632" ||
		distcc.Metadata["protocol"] != "tcp" || distcc.Metadata["qod"] != "99" || distcc.Metadata["solution_type"] != "VendorFix" {
		t.Errorf("distcc location/metadata = %q %v", distcc.URL, distcc.Metadata)
	}
	if refs, _ := distcc.Metadata["references"].([]string); !slices.Contains(refs, "https://distcc.github.io/security.html") {
		t.Errorf("distcc references = %v", distcc.Metadata["references"])
	}
	if !strings.HasPrefix(distcc.Description, "DistCC is prone to a remote code execution (RCE)") {
		t.Errorf("distcc description = %q", distcc.Description)
	}

	// The CWE is only named in a cwe.mitre.org reference link.
	http := openvasByRule(t, fs, "1.3.6.1.4.1.25623.1.0.108440", "192.168.1.1001:80/tcp")
	if http.Title != "Cleartext Transmission of Sensitive Information via HTTP" || http.Severity != domain.SeverityMedium ||
		http.CWE == nil || *http.CWE != 319 || len(http.CVE) != 0 {
		t.Errorf("cleartext = %q %s %v %v", http.Title, http.Severity, http.CWE, http.CVE)
	}

	// "general/tcp" results sit on the host itself.
	eol := openvasByRule(t, fs, "1.3.6.1.4.1.25623.1.0.103674", "192.168.1.1001")
	if eol.Title != "Operating System (OS) End of Life (EOL) Detection" || eol.Severity != domain.SeverityHigh {
		t.Errorf("os eol = %q %s", eol.Title, eol.Severity)
	}
	if m, _ := eol.Metadata["mitigation"].(string); !strings.HasPrefix(m, "Upgrade the OS on the") {
		t.Errorf("os eol mitigation = %q", m)
	}

	// No threat class: the CVSS score ranks it.
	weak := openvasByRule(t, fs, "1.3.6.1.4.1.25623.1.0.105880", "192.168.1.1001:5432/tcp")
	if weak.Title != "SSL/TLS: Certificate Signed Using A Weak Signature Algorithm" || weak.Severity != domain.SeverityMedium {
		t.Errorf("weak sig = %q %s", weak.Title, weak.Severity)
	}
}

func TestOpenVASNoResults(t *testing.T) {
	fs := parseFixture(t, NewOpenVAS(), "openvas_empty.xml")
	if fs == nil || len(fs) != 0 {
		t.Fatalf("got %v, want empty non-nil", fs)
	}
	for _, in := range []string{`{"results":[]}`, `<NessusClientData_v2/>`, `<report><results>`} {
		if _, err := NewOpenVAS().Parse(strings.NewReader(in)); err == nil {
			t.Errorf("Parse(%q) accepted non-OpenVAS input", in)
		}
	}
}
