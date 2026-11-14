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
//	nessus_cvssv3.nessus ← tenable/nessus/nessus_with_cvssv3.nessus (the <Policy> block dropped)
//	nessus_tenable.csv   ← tenable/tenable_many_vuln.csv
//	nessus_sc.csv        ← tenable/issue_9612.csv

func nessusByRule(t *testing.T, fs []ParsedFinding, rule, path string) ParsedFinding {
	t.Helper()
	for _, f := range fs {
		if f.RuleID == rule && f.FilePath == path {
			return f
		}
	}
	t.Fatalf("no finding %s at %s in %v", rule, path, ruleIDs(fs))
	return ParsedFinding{}
}

func TestNessusXML(t *testing.T) {
	fs := parseFixture(t, NewNessus(), "nessus_cvssv3.nessus")
	// 49 ReportItems: 23 severity-0 plugins skipped, the two 58987 hits on
	// port 80 folded into one.
	if len(fs) != 25 {
		t.Fatalf("got %d findings, want 25: %v", len(fs), ruleIDs(fs))
	}
	for _, f := range fs {
		if f.Severity == domain.SeverityInfo {
			t.Errorf("informational plugin %s %q kept", f.RuleID, f.Title)
		}
	}
	if slices.Contains(ruleIDs(fs), "45590") {
		t.Error("severity-0 CPE plugin 45590 kept")
	}

	php := nessusByRule(t, fs, "31649", "testphp.vulnweb.com:80/tcp")
	if php.Title != "PHP 5.x < 5.2 Multiple Vulnerabilities" || php.Severity != domain.SeverityHigh {
		t.Errorf("31649 = %q %s", php.Title, php.Severity)
	}
	if len(php.CVE) != 15 || php.CVE[0] != "CVE-2006-1015" || php.CVE[14] != "CVE-2007-5424" {
		t.Errorf("31649 CVEs = %v", php.CVE)
	}
	if php.CWE == nil || *php.CWE != 94 || php.CVSS == nil || *php.CVSS != 7.5 {
		t.Errorf("31649 CWE/CVSS = %v %v", php.CWE, php.CVSS)
	}
	if php.URL != "testphp.vulnweb.com" || php.Metadata["ip"] != "44.228.249.3" || php.Metadata["port"] != "80" ||
		php.Metadata["protocol"] != "tcp" || php.Metadata["mitigation"] != "Upgrade to PHP version 5.2.0 or later." {
		t.Errorf("31649 location/metadata = %q %v", php.URL, php.Metadata)
	}
	if !strings.Contains(php.Description, "Fixed version : 5.2") {
		t.Errorf("31649 description lacks plugin output: %q", php.Description)
	}

	eol := nessusByRule(t, fs, "58987", "testphp.vulnweb.com:80/tcp")
	if eol.Severity != domain.SeverityCritical || eol.CVSS == nil || *eol.CVSS != 10.0 || eol.Metadata["occurrences"] != 2 {
		t.Errorf("58987 = %s %v %v", eol.Severity, eol.CVSS, eol.Metadata["occurrences"])
	}
	if !strings.Contains(eol.Description, "Installed version : 5.1.6") ||
		!strings.Contains(eol.Description, "Installed version : 5.6.40-38+ubuntu20.04.1+deb.sury.org+1") {
		t.Errorf("58987 merged description = %q", eol.Description)
	}

	creds := nessusByRule(t, fs, "26194", "testphp.vulnweb.com:80/tcp")
	if creds.Title != "Web Server Transmits Cleartext Credentials" || creds.Severity != domain.SeverityLow ||
		creds.CWE == nil || *creds.CWE != 522 || len(creds.CVE) != 0 {
		t.Errorf("26194 = %q %s %v %v", creds.Title, creds.Severity, creds.CWE, creds.CVE)
	}
}

func TestNessusTenableCSV(t *testing.T) {
	fs := parseFixture(t, NewNessus(), "nessus_tenable.csv")
	// 20 per-CVE rows (+2 blank) fold into 9 plugin hits per host.
	if len(fs) != 9 {
		t.Fatalf("got %d findings, want 9: %v", len(fs), ruleIDs(fs))
	}
	maria := nessusByRule(t, fs, "176703", "ip-127-0-0-1.us-west-2.compute.internal")
	if maria.Title != "Amazon Linux 2 : mariadb (ALAS-2023-2057)" || maria.Severity != domain.SeverityHigh {
		t.Errorf("176703 = %q %s", maria.Title, maria.Severity)
	}
	if len(maria.CVE) != 10 || maria.CVE[0] != "CVE-2021-46666" || !slices.Contains(maria.CVE, "CVE-2021-46668") {
		t.Errorf("176703 CVEs = %v", maria.CVE)
	}
	if maria.CVSS == nil || *maria.CVSS != 7.5 || maria.Metadata["ip"] != "127.0.0.1" ||
		maria.Metadata["mitigation"] != "Run 'yum update mariadb' to update your system." {
		t.Errorf("176703 CVSS/metadata = %v %v", maria.CVSS, maria.Metadata)
	}
	if _, merged := maria.Metadata["occurrences"]; merged {
		t.Error("per-CVE rows should fold into one hit, not count as occurrences")
	}

	splunk := nessusByRule(t, fs, "164329", "ip-192-168-1-110.us-west-2.compute.internal")
	if splunk.Severity != domain.SeverityMedium || !slices.Equal(splunk.CVE, []string{"CVE-2022-37439"}) ||
		splunk.CVSS == nil || *splunk.CVSS != 5.5 || splunk.Metadata["ip"] != "192.168.1.110" {
		t.Errorf("164329 = %s %v %v %v", splunk.Severity, splunk.CVE, splunk.CVSS, splunk.Metadata)
	}
}

func TestNessusSecurityCenterCSV(t *testing.T) {
	fs := parseFixture(t, NewNessus(), "nessus_sc.csv")
	if len(fs) != 3 {
		t.Fatalf("got %d findings, want 3: %v", len(fs), ruleIDs(fs))
	}
	f := nessusByRule(t, fs, "73756", "2.3.4.5:5555/tcp")
	if f.Title != "Microsoft SQL Server Unsupported Version Detection (remote check)" ||
		f.Severity != domain.SeverityCritical || f.CVSS == nil || *f.CVSS != 10.0 || f.Metadata["plugin_family"] != "Databases" {
		t.Errorf("73756 = %q %s %v %v", f.Title, f.Severity, f.CVSS, f.Metadata)
	}
	nessusByRule(t, fs, "73756", "1.2.3.4:1433/tcp")
}

func TestNessusRejectsOtherFormats(t *testing.T) {
	for _, in := range []string{`{"vulnerabilities":[]}`, `<nmaprun></nmaprun>`, "a,b,c\n1,2,3\n"} {
		if _, err := NewNessus().Parse(strings.NewReader(in)); err == nil {
			t.Errorf("Parse(%q) accepted non-Nessus input", in)
		}
	}
}
