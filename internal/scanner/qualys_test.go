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
//	qualys_asset_data.xml ← qualys/Qualys_Sample_Report.xml, trimmed to host
//	                        64.41.200.246 and the glossary entries it references
//	qualys_empty.xml      ← qualys/empty.xml
//	qualys_sample.csv     ← qualys/Qualys_Sample_Report.csv

func qualysByRule(t *testing.T, fs []ParsedFinding, rule, path string) ParsedFinding {
	t.Helper()
	for _, f := range fs {
		if f.RuleID == rule && f.FilePath == path {
			return f
		}
	}
	t.Fatalf("no finding %s at %s in %v", rule, path, ruleIDs(fs))
	return ParsedFinding{}
}

func TestQualysXML(t *testing.T) {
	fs := parseFixture(t, NewQualys(), "qualys_asset_data.xml")
	// 47 detections on the host: 39 "Information gathered" (Ig) skipped.
	if len(fs) != 8 {
		t.Fatalf("got %d findings, want 8: %v", len(fs), ruleIDs(fs))
	}
	if slices.Contains(ruleIDs(fs), "6") || slices.Contains(ruleIDs(fs), "82040") {
		t.Errorf("information-gathered QIDs kept: %v", ruleIDs(fs))
	}

	ms17 := qualysByRule(t, fs, "91345", "64.41.200.246")
	if ms17.Title != "Microsoft SMB Server Remote Code Execution Vulnerability (MS17-010) and Shadow Brokers" ||
		ms17.Severity != domain.SeverityCritical {
		t.Errorf("91345 = %q %s", ms17.Title, ms17.Severity)
	}
	if !slices.Equal(ms17.CVE, []string{"CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0146", "CVE-2017-0148", "CVE-2017-0147"}) {
		t.Errorf("91345 CVEs = %v", ms17.CVE)
	}
	if ms17.URL != "64.41.200.246" || ms17.Metadata["dns"] != "win2008r2.trn.qualys.com" ||
		ms17.Metadata["detection"] != "confirmed" || ms17.Metadata["category"] != "Windows" {
		t.Errorf("91345 location/metadata = %q %v", ms17.URL, ms17.Metadata)
	}
	if !strings.Contains(ms17.Description, "detected on port 445 over TCP") || strings.Contains(ms17.Description, "<P>") {
		t.Errorf("91345 description = %q", ms17.Description)
	}

	rc4 := qualysByRule(t, fs, "38601", "64.41.200.246:3389/tcp")
	if rc4.Title != "SSL/TLS use of weak RC4(Arcfour) cipher" || rc4.Severity != domain.SeverityMedium ||
		!slices.Equal(rc4.CVE, []string{"CVE-2013-2566", "CVE-2015-2808"}) || rc4.Metadata["ssl"] != "true" {
		t.Errorf("38601 = %q %s %v %v", rc4.Title, rc4.Severity, rc4.CVE, rc4.Metadata)
	}

	cn := qualysByRule(t, fs, "38170", "64.41.200.246:3389/tcp")
	if cn.Title != "SSL Certificate - Subject Common Name Does Not Match Server FQDN" || cn.Severity != domain.SeverityLow || len(cn.CVE) != 0 {
		t.Errorf("38170 = %q %s %v", cn.Title, cn.Severity, cn.CVE)
	}
}

func TestQualysCSV(t *testing.T) {
	fs := parseFixture(t, NewQualys(), "qualys_sample.csv")
	if len(fs) != 6 {
		t.Fatalf("got %d findings, want 6: %v", len(fs), ruleIDs(fs))
	}
	upd := qualysByRule(t, fs, "91762", "10.98.57.180")
	if upd.Title != "Microsoft Windows Security Update for May 2021" || upd.Severity != domain.SeverityCritical {
		t.Errorf("91762 = %q %s", upd.Title, upd.Severity)
	}
	if len(upd.CVE) != 23 || upd.CVE[0] != "CVE-2021-31192" || upd.CVE[22] != "CVE-2020-24588" {
		t.Errorf("91762 CVEs = %v", upd.CVE)
	}
	if upd.CVSS == nil || *upd.CVSS != 9.9 {
		t.Errorf("91762 CVSS = %v", upd.CVSS)
	}
	if refs, _ := upd.Metadata["references"].([]string); len(refs) == 0 || refs[0] != "KB5003169" {
		t.Errorf("91762 references = %v", upd.Metadata["references"])
	}

	eol := qualysByRule(t, fs, "105971", "10.98.57.151")
	if eol.Title != "EOL/Obsolete Software: Microsoft ASP.NET 1.0 Detected" || eol.Severity != domain.SeverityCritical ||
		eol.CVSS == nil || *eol.CVSS != 8.1 || len(eol.CVE) != 0 ||
		!strings.HasPrefix(eol.Metadata["impact"].(string), "The system is at high risk") {
		t.Errorf("105971 = %q %s %v %v", eol.Title, eol.Severity, eol.CVSS, eol.Metadata)
	}
}

func TestQualysEmpty(t *testing.T) {
	fs := parseFixture(t, NewQualys(), "qualys_empty.xml")
	if fs == nil || len(fs) != 0 {
		t.Fatalf("got %v, want empty non-nil", fs)
	}
	for _, in := range []string{`{"data":[]}`, `<NessusClientData_v2/>`, "a,b\n1,2\n"} {
		if _, err := NewQualys().Parse(strings.NewReader(in)); err == nil {
			t.Errorf("Parse(%q) accepted non-Qualys input", in)
		}
	}
}
