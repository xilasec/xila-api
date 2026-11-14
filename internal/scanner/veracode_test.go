package scanner

import (
	"slices"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures from DefectDojo unittests/scans/veracode:
//
//	veracode_many.xml          ← many_findings.xml
//	veracode_mitigated.xml     ← mitigated_finding.xml
//	veracode_sca_mitigated.xml ← veracode_scan_sca_mitigated.xml

func TestVeracodeManyFindings(t *testing.T) {
	out := parseFixture(t, NewVeracode(), "veracode_many.xml")
	// One static flaw, one dynamic flaw, two vulnerable components.
	if len(out) != 4 {
		t.Fatalf("findings = %d, want 4", len(out))
	}
	static := out[0]
	if static.Category != domain.CategorySAST || static.RuleID != "123" || static.Title != "catname" ||
		static.Severity != domain.SeverityMedium || static.CWE == nil || *static.CWE != 123 ||
		static.FilePath != "sourcefilepath/MyApp.java" || static.Line == nil || *static.Line != 1 {
		t.Errorf("static flaw = %+v", static)
	}
	// mitigation_status "proposed" is not a verdict.
	if _, ok := static.Metadata[metaRemoteTriage]; ok {
		t.Errorf("proposed mitigation carried as triage: %v", static.Metadata)
	}
	dyn := out[1]
	if dyn.Category != domain.CategoryDAST || dyn.CWE == nil || *dyn.CWE != 456 || dyn.URL != "https://www.example.com/index.html" {
		t.Errorf("dynamic flaw = %+v", dyn)
	}
	sca := findRule(t, out, "CVE-1234-1234")
	if sca.Category != domain.CategorySCA || sca.Severity != domain.SeverityHigh || sca.Package != "library" ||
		sca.PackageVersion != "1234" || !slices.Equal(sca.CVE, []string{"CVE-1234-1234"}) || sca.CVSS == nil || *sca.CVSS != 7.5 ||
		sca.FilePath != "filepath.jar" {
		t.Errorf("sca finding = %+v", sca)
	}
	if f := findRule(t, out, "CVE-5678-5678"); f.Package != "library1" {
		t.Errorf("second component = %+v", f)
	}
}

func TestVeracodeMitigatedFlaw(t *testing.T) {
	out := parseFixture(t, NewVeracode(), "veracode_mitigated.xml")
	if len(out) != 1 {
		t.Fatalf("findings = %d, want 1", len(out))
	}
	if f := out[0]; f.Metadata[metaRemoteTriage] != "risk_accepted" || f.CWE == nil || *f.CWE != 123 {
		t.Errorf("mitigated flaw = %+v", f)
	}
}

func TestVeracodeMitigatedComponent(t *testing.T) {
	out := parseFixture(t, NewVeracode(), "veracode_sca_mitigated.xml")
	// commons-lang has no vulnerabilities; h2 has one, mitigated by design.
	if len(out) != 1 {
		t.Fatalf("findings = %d, want 1", len(out))
	}
	f := out[0]
	if f.RuleID != "CVE-2018-10054" || f.Severity != domain.SeverityCritical || f.CWE == nil || *f.CWE != 20 ||
		f.Package != "com.h2database:h2" || f.PackageVersion != "2.1.214" || f.Purl != "pkg:maven/com.h2database/h2@2.1.214" ||
		f.Metadata[metaRemoteTriage] != "risk_accepted" ||
		!strings.Contains(f.Metadata[metaRemoteTriageReason].(string), "Mitigate by Design") {
		t.Errorf("mitigated component = %+v", f)
	}
}

func TestVeracodeSeverityAndTriageMapping(t *testing.T) {
	doc := `<?xml version="1.0" encoding="ISO-8859-1"?>
<detailedreport xmlns="https://www.veracode.com/schema/reports/export/1.0">
<severity level="5"><category categoryid="80" categoryname="SQL Injection"><cwe cweid="89"><staticflaws>
<flaw severity="5" categoryname="SQL Injection" issueid="7" cweid="89" categoryid="80" remediation_status="Open" mitigation_status="accepted" sourcefile="Db.java" sourcefilepath="com/x/" line="12">
<mitigations><mitigation action="Potential False Positive" description="sanitized upstream"/><mitigation action="Approve Mitigation" description="ok"/></mitigations></flaw>
<flaw severity="5" categoryname="SQL Injection" issueid="8" cweid="89" categoryid="80" remediation_status="Fixed" sourcefile="Db.java" sourcefilepath="com/x/" line="40"/>
</staticflaws></cwe></category></severity>
<severity level="1"><category categoryid="9" categoryname="Info Leak"><cwe cweid="200"><staticflaws>
<flaw severity="1" categoryname="Info Leak" issueid="9" cweid="200" categoryid="9" remediation_status="Open" sourcefile="LATIN1.java" sourcefilepath="com/x/" line="3"/>
</staticflaws></cwe></category></severity>
</detailedreport>`
	// The report declares ISO-8859-1: 0xC4 is "Ä".
	doc = strings.Replace(doc, "LATIN1", "\xc4", 1)
	out, err := NewVeracode().Parse(strings.NewReader(doc))
	if err != nil || len(out) != 2 {
		t.Fatalf("parse = %+v, %v", out, err)
	}
	if f := out[0]; f.Severity != domain.SeverityCritical || f.Metadata[metaRemoteTriage] != "false_positive" || f.FilePath != "com/x/Db.java" {
		t.Errorf("very-high false positive = %+v", f)
	}
	if f := out[1]; f.Severity != domain.SeverityInfo || f.FilePath != "com/x/\u00c4.java" {
		t.Errorf("very-low flaw = %+v", f)
	}
	if _, err := NewVeracode().Parse(strings.NewReader(`<CxXMLResults/>`)); err == nil {
		t.Error("want error for non-Veracode XML")
	}
}
