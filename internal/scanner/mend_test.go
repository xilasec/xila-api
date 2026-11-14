package scanner

import (
	"slices"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures from DefectDojo unittests/scans/mend:
//
//	mend_api3.json             ← mend-sca-platform-api3-multiple-findings.json
//	mend_api3_empty.json       ← mend-sca-platform-api3-no-findings.json
//	mend_legacy.json           ← okhttp_many_vuln.json
//	mend_legacy_empty.json     ← okhttp_no_vuln.json
//	mend_legacy_locations.json ← mend_sca_vuln.json

func TestMendAPI3(t *testing.T) {
	out := parseFixture(t, NewMend(), "mend_api3.json")
	// 11 findings, 6 of them LIBRARY_REMOVED: the 5 ACTIVE ones are all axis-1.4.jar.
	if len(out) != 5 {
		t.Fatalf("findings = %d, want 5: %v", len(out), ruleIDs(out))
	}
	for _, f := range out {
		if f.Package != "axis" || f.PackageVersion != "1.4" {
			t.Errorf("removed library imported: %+v", f)
		}
	}
	crit := findRule(t, out, "CVE-2023-40743")
	if crit.Severity != domain.SeverityCritical || !slices.Equal(crit.CVE, []string{"CVE-2023-40743"}) ||
		crit.CVSS == nil || *crit.CVSS != 9.8 || crit.Category != domain.CategorySCA || crit.FixedVersion != "" {
		t.Errorf("CVE-2023-40743 = %+v", crit)
	}
	// "axis:axis - 1.3-atlassian-1" upgrades this library.
	if f := findRule(t, out, "CVE-2014-3596"); f.Severity != domain.SeverityMedium || f.FixedVersion != "1.3-atlassian-1" {
		t.Errorf("CVE-2014-3596 = %+v", f)
	}
	// "org.apache.axis2:axis2:1.7.9" swaps in another artifact: no fixed version.
	if f := findRule(t, out, "CVE-2019-0227"); f.Severity != domain.SeverityHigh || f.FixedVersion != "" ||
		!strings.Contains(f.Metadata["mitigation"].(string), "axis2") {
		t.Errorf("CVE-2019-0227 = %+v", f)
	}
	// "no_fix".
	if f := findRule(t, out, "CVE-2018-8032"); f.FixedVersion != "" || f.Metadata["mitigation"] != nil {
		t.Errorf("CVE-2018-8032 = %+v", f)
	}
}

func TestMendLegacy(t *testing.T) {
	out := parseFixture(t, NewMend(), "mend_legacy.json")
	if len(out) != 6 {
		t.Fatalf("findings = %d, want 6", len(out))
	}
	ws := findRule(t, out, "WS-2010-0001")
	if ws.Package != "commons-codec:commons-codec" || ws.PackageVersion != "1.3" || ws.FixedVersion != "1.7" ||
		ws.Severity != domain.SeverityMedium || len(ws.CVE) != 0 || ws.Purl != "pkg:maven/commons-codec/commons-codec@1.3" {
		t.Errorf("WS-2010-0001 = %+v", ws)
	}
	// "Upgrade To Version 4.3.5,4.0.2": the nearest fix above 4.0.1.
	hc := findRule(t, out, "CVE-2014-3577")
	if hc.Package != "org.apache.httpcomponents:httpclient" || hc.PackageVersion != "4.0.1" || hc.FixedVersion != "4.0.2" ||
		!slices.Equal(hc.CVE, []string{"CVE-2014-3577"}) || hc.CVSS == nil || *hc.CVSS != 5.8 {
		t.Errorf("CVE-2014-3577 = %+v", hc)
	}
	// cvss3 rating and score preferred; "checkstyle-8.18" names this library.
	cs := findRule(t, out, "CVE-2019-9658")
	if cs.Severity != domain.SeverityMedium || cs.CVSS == nil || *cs.CVSS != 5.3 || cs.FixedVersion != "8.18" {
		t.Errorf("CVE-2019-9658 = %+v", cs)
	}
	if f := findRule(t, out, "WS-2009-0001"); f.Severity != domain.SeverityLow || f.CVSS != nil || f.FixedVersion != "" {
		t.Errorf("WS-2009-0001 = %+v", f)
	}
}

func TestMendLegacyLocations(t *testing.T) {
	out := parseFixture(t, NewMend(), "mend_legacy_locations.json")
	if len(out) != 1 {
		t.Fatalf("findings = %d, want 1", len(out))
	}
	f := out[0]
	if f.RuleID != "WS-2019-0379" || f.Package != "commons-codec" || f.PackageVersion != "1.6" || f.FixedVersion != "1.13" ||
		f.FilePath != `D:\MendRepo\test-product\test-project\test-project-subcomponent\path\to\the\Java\commons-codec-1.6_donotuse.jar` {
		t.Errorf("finding = %+v", f)
	}
}

// A trimmed entry of DefectDojo's cli_generated_many_vulns.json (Mend CLI).
func TestMendCLILibraries(t *testing.T) {
	doc := `{"libraries":[{"name":"libsass-3.5.5","groupId":"sass","artifactId":"libsass","version":"3.5.5","type":"SOURCE_LIBRARY","vulnerabilities":[{"name":"CVE-2018-11499","type":"CVE","severity":"HIGH","score":7.5,"cvss3_severity":"HIGH","cvss3_score":9.8,"scoreMetadataVector":"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H","topFix":{"fixResolution":"Upgrade to version 3.6.0","message":"Upgrade to version"}}]}]}`
	out, err := NewMend().Parse(strings.NewReader(doc))
	if err != nil || len(out) != 1 {
		t.Fatalf("parse = %+v, %v", out, err)
	}
	f := out[0]
	if f.Package != "libsass" || f.PackageVersion != "3.5.5" || f.FixedVersion != "3.6.0" || f.Severity != domain.SeverityHigh ||
		f.CVSS == nil || *f.CVSS != 9.8 || !slices.Equal(f.CVE, []string{"CVE-2018-11499"}) {
		t.Errorf("finding = %+v", f)
	}
}

func TestMendEmptyAndInvalid(t *testing.T) {
	for _, name := range []string{"mend_api3_empty.json", "mend_legacy_empty.json"} {
		if out := parseFixture(t, NewMend(), name); out == nil || len(out) != 0 {
			t.Errorf("%s = %#v, want empty non-nil slice", name, out)
		}
	}
	if _, err := NewMend().Parse(strings.NewReader(`{"findings":[]}`)); err == nil {
		t.Error("want error for non-Mend JSON")
	}
}
