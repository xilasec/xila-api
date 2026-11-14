package scanner

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixture: DefectDojo unittests/scans/nancy/nancy_many_findings.json (BSD-3-Clause).
func TestNancyParse(t *testing.T) {
	out := parseFixture(t, NewNancy(), "nancy_many_findings.json")
	// 6 vulnerable packages: oauth2_proxy(1), go-ethereum(1), beats(1), etcd(3),
	// gogs(6), gophish(1) = 13 vulnerabilities; "Excluded" entries would be
	// skipped but none are in this fixture.
	if len(out) != 13 {
		t.Fatalf("got %d findings, want 13", len(out))
	}

	oauth := findByRule(t, out, "9eb9a5bc-8310-4104-bf85-3a820d28ba79")
	if oauth.Category != domain.CategorySCA || oauth.Package != "github.com/bitly/oauth2_proxy" ||
		oauth.PackageVersion != "0.1" || oauth.Purl != "pkg:golang/github.com/bitly/oauth2_proxy@0.1" {
		t.Errorf("oauth2_proxy finding = %+v", oauth)
	}
	if len(oauth.CVE) != 1 || oauth.CVE[0] != "CVE-2017-1000070" {
		t.Errorf("CVE = %v, want [CVE-2017-1000070]", oauth.CVE)
	}
	if oauth.CVSS == nil || *oauth.CVSS != 6.1 || oauth.Severity != domain.SeverityMedium {
		t.Errorf("cvss/severity = %v/%s, want 6.1/medium", oauth.CVSS, oauth.Severity)
	}

	// Several OSS Index vulnerabilities carry only a CWE title, no CVE — the
	// finding still has to come through, just without a CVE.
	sqli := findByRule(t, out, "a4c682fa-9c9f-4e9e-b218-720d5125b17f")
	if len(sqli.CVE) != 0 {
		t.Errorf("sqli CVE = %v, want none", sqli.CVE)
	}
	if sqli.CVSS == nil || *sqli.CVSS != 9.9 || sqli.Severity != domain.SeverityCritical {
		t.Errorf("sqli cvss/severity = %v/%s, want 9.9/critical", sqli.CVSS, sqli.Severity)
	}
	if sqli.Package != "github.com/gogs/gogs" || sqli.PackageVersion != "0.9.45" {
		t.Errorf("sqli package = %+v", sqli)
	}

	// etcd has three vulnerabilities, all package-level, all unique CVEs.
	etcdCVEs := map[string]bool{}
	for _, f := range out {
		if f.Package == "github.com/etcd-io/etcd" {
			for _, c := range f.CVE {
				etcdCVEs[c] = true
			}
		}
	}
	for _, want := range []string{"CVE-2018-1098", "CVE-2018-1099", "CVE-2018-16886"} {
		if !etcdCVEs[want] {
			t.Errorf("etcd CVEs %v missing %s", etcdCVEs, want)
		}
	}
}

func TestNancyRejectsMalformed(t *testing.T) {
	if _, err := NewNancy().Parse(strings.NewReader(`{"not":"nancy"}`)); err == nil {
		t.Error("want error for JSON without a vulnerable array")
	}
	if _, err := NewNancy().Parse(strings.NewReader("not json")); err == nil {
		t.Error("want error for non-JSON input")
	}
}
