package scanner

import (
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures from DefectDojo unittests/scans/testssl:
//
//	testssl_demo.csv          ← demo.csv
//	testssl_many_cves.csv     ← many_cves.csv
//	testssl_many_vuln.csv     ← defectdojo_many_vuln.csv
//	testssl_empty.csv         ← defectdojo_no_vuln.csv
//	testssl_failed_target.csv ← failed_target.csv

func TestTestSSLOnlyOKAndInfo(t *testing.T) {
	// demo.csv: every row is OK or INFO — a clean scan.
	out := parseFixture(t, NewTestSSL(), "testssl_demo.csv")
	if out == nil || len(out) != 0 {
		t.Fatalf("demo findings = %#v, want none", out)
	}
	if out := parseFixture(t, NewTestSSL(), "testssl_empty.csv"); out == nil || len(out) != 0 {
		t.Fatalf("empty findings = %#v, want none", out)
	}
}

func TestTestSSLManyCVEs(t *testing.T) {
	out := parseFixture(t, NewTestSSL(), "testssl_many_cves.csv")
	if len(out) != 1 {
		t.Fatalf("findings = %d, want 1", len(out))
	}
	f := out[0]
	if f.RuleID != "DROWN" || f.Severity != domain.SeverityHigh || f.Category != domain.CategoryDAST ||
		!slices.Equal(f.CVE, []string{"CVE-2016-0800", "CVE-2016-0703"}) || f.CWE == nil || *f.CWE != 310 ||
		f.FilePath != "www.defectdojo.org:443" || f.Description != "vulnerable to DROWN on this host and port" {
		t.Errorf("DROWN = %+v", f)
	}
}

func TestTestSSLManyVulns(t *testing.T) {
	out := parseFixture(t, NewTestSSL(), "testssl_many_vuln.csv")
	// 16 LOW/HIGH rows = 4 checks × 4 IPs of www.defectdojo.org; the WARN
	// engine_problem row and every OK/INFO row are skipped.
	if got := ruleIDs(out); !slices.Equal(got, []string{"cipherlist_AVERAGE", "HSTS", "BREACH", "LUCKY13"}) {
		t.Fatalf("rules = %v", got)
	}
	breach := findRule(t, out, "BREACH")
	if breach.Severity != domain.SeverityHigh || !slices.Equal(breach.CVE, []string{"CVE-2013-3587"}) ||
		breach.FilePath != "www.defectdojo.org:443" || len(breach.Metadata["ips"].([]string)) != 4 {
		t.Errorf("BREACH = %+v", breach)
	}
	if f := findRule(t, out, "LUCKY13"); f.Severity != domain.SeverityLow || !slices.Equal(f.CVE, []string{"CVE-2013-0169"}) {
		t.Errorf("LUCKY13 = %+v", f)
	}
}

func TestTestSSLRejects(t *testing.T) {
	f, err := os.Open("testdata/testssl_failed_target.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := NewTestSSL().Parse(f); err == nil || !strings.Contains(err.Error(), "Can't connect") {
		t.Errorf("failed target err = %v", err)
	}
	if _, err := NewTestSSL().Parse(strings.NewReader("a,b\n1,2\n")); err == nil {
		t.Error("want error for non-testssl CSV")
	}
}
