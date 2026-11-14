package vex

import (
	"os"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

const openVexDocJSON = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "author": "security@example.com",
  "statements": [
    {
      "vulnerability": {"name": "CVE-2021-44228"},
      "products": [{"@id": "pkg:maven/log4j-core@2.14.1"}],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "We never call the JNDI lookup."
    },
    {
      "vulnerability": {"name": "CVE-2022-22965"},
      "products": [{"@id": "pkg:maven/spring-beans@5.3.0"}],
      "status": "affected"
    },
    {
      "vulnerability": {"name": "CVE-2023-0001"},
      "status": "under_investigation"
    },
    {"vulnerability": {"name": "CVE-BAD"}, "status": "who_knows"}
  ]
}`

func TestParseOpenVEX(t *testing.T) {
	stmts, err := Parse([]byte(openVexDocJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// The unrecognized status is dropped, not guessed: misreading a verdict would
	// silently suppress a real finding.
	if len(stmts) != 3 {
		t.Fatalf("got %d statements, want 3 (the unknown status is dropped)", len(stmts))
	}
	s := stmts[0]
	if s.VulnID != "CVE-2021-44228" || s.Status != StatusNotAffected ||
		s.Product != "pkg:maven/log4j-core@2.14.1" ||
		s.Justification != "vulnerable_code_not_in_execute_path" ||
		s.Detail != "We never call the JNDI lookup." || s.Source != "openvex" {
		t.Errorf("statement = %+v", s)
	}
	if stmts[1].Status != StatusAffected {
		t.Errorf("affected statement = %+v", stmts[1])
	}
	// A statement with no products applies project-wide.
	if stmts[2].Product != "" || stmts[2].Status != StatusUnderInvestigation {
		t.Errorf("product-less statement = %+v", stmts[2])
	}
}

const cycloneVexJSON = `{
  "bomFormat": "CycloneDX", "specVersion": "1.5",
  "vulnerabilities": [
    {
      "id": "CVE-2021-44228",
      "analysis": {"state": "not_affected", "justification": "code_not_reachable", "detail": "no JNDI"},
      "affects": [{"ref": "pkg:maven/log4j-core@2.14.1"}]
    },
    {"id": "CVE-2020-1", "analysis": {"state": "resolved"}},
    {"id": "CVE-2020-2", "analysis": {"state": "exploitable"}}
  ]
}`

func TestParseCycloneDXVEX(t *testing.T) {
	stmts, err := Parse([]byte(cycloneVexJSON))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(stmts) != 3 {
		t.Fatalf("got %d statements, want 3", len(stmts))
	}
	if stmts[0].Status != StatusNotAffected || stmts[0].Source != "cyclonedx" {
		t.Errorf("statement = %+v", stmts[0])
	}
	if stmts[1].Status != StatusFixed { // "resolved" = the build carries the fix
		t.Errorf("resolved should map to fixed, got %q", stmts[1].Status)
	}
	if stmts[2].Status != StatusAffected { // "exploitable" = confirmed
		t.Errorf("exploitable should map to affected, got %q", stmts[2].Status)
	}
}

func TestParseRejectsUnknownDocument(t *testing.T) {
	if _, err := Parse([]byte(`{"hello":"world"}`)); err == nil {
		t.Error("a document that is neither OpenVEX nor CycloneDX must be rejected, not silently ignored")
	}
}

func TestMatchPrefersTheExactProduct(t *testing.T) {
	f := finding.Finding{
		RuleID: "GHSA-jfh8", CVE: []string{"CVE-2021-44228"},
		PackageName: "log4j-core", PackageVersion: "2.14.1",
		Purl: "pkg:maven/log4j-core@2.14.1",
	}
	stmts := []Statement{
		{VulnID: "CVE-2021-44228", Status: StatusAffected},                                            // project-wide
		{VulnID: "CVE-2021-44228", Product: "pkg:maven/log4j-core@2.14.1", Status: StatusNotAffected}, // exact
	}
	got, ok := match(stmts, f)
	if !ok || got.Status != StatusNotAffected {
		t.Errorf("match = %+v (ok %v); a statement naming the exact product must beat a project-wide one", got, ok)
	}

	// The advisory can also be named by the id an OSV finding carries in rule_id.
	byGHSA := []Statement{{VulnID: "GHSA-jfh8", Status: StatusNotAffected}}
	if _, ok := match(byGHSA, f); !ok {
		t.Error("a GHSA statement must match a finding whose rule_id is that GHSA")
	}

	// An unrelated CVE must never match.
	if _, ok := match([]Statement{{VulnID: "CVE-2000-1", Status: StatusNotAffected}}, f); ok {
		t.Error("an unrelated advisory must not match")
	}
}

func TestNamesProductMatchesBarePackage(t *testing.T) {
	f := finding.Finding{PackageName: "lodash", PackageVersion: "4.17.21"}
	for _, product := range []string{"lodash", "pkg:npm/lodash@4.17.21", "pkg:npm/lodash"} {
		if !namesProduct(product, f) {
			t.Errorf("product %q should match package lodash@4.17.21", product)
		}
	}
	if namesProduct("pkg:npm/express@4.0.0", f) {
		t.Error("a different package must not match")
	}
	if namesProduct("pkg:npm/lodash@3.0.0", f) {
		t.Error("a different version of the same package must not match")
	}
}

func TestTargetStatus(t *testing.T) {
	// not_affected and fixed both mean "stop showing me this", and both become a
	// *triage* state rather than remediated — remediated would be reopened the
	// moment the next scan reported the package again.
	for _, s := range []Status{StatusNotAffected, StatusFixed} {
		got, ok := targetStatus(s)
		if !ok || got != domain.FindingFalsePositive {
			t.Errorf("targetStatus(%q) = %q/%v, want false_positive", s, got, ok)
		}
	}
	if got, ok := targetStatus(StatusAffected); !ok || got != domain.FindingConfirmed {
		t.Errorf("targetStatus(affected) = %q/%v, want confirmed", got, ok)
	}
	if _, ok := targetStatus(StatusUnderInvestigation); ok {
		t.Error("under_investigation must change nothing")
	}
}

// A real CSAF 2.0 VEX document (Red Hat's, trimmed): product ids resolve
// through the product tree and its relationships to the component's purl;
// every status list maps; the flag is the justification; the same component
// in several product contexts is one statement.
func TestParseCSAFVEX(t *testing.T) {
	data, err := os.ReadFile("testdata/redhat-csaf-vex-cve-2021-44228.json")
	if err != nil {
		t.Fatal(err)
	}
	stmts, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	by := map[Status][]Statement{}
	for _, s := range stmts {
		if s.VulnID != "CVE-2021-44228" || s.Source != "csaf" {
			t.Errorf("statement %+v", s)
		}
		by[s.Status] = append(by[s.Status], s)
	}
	if len(stmts) != 5 || len(by[StatusFixed]) != 2 || len(by[StatusAffected]) != 1 || len(by[StatusNotAffected]) != 2 {
		t.Fatalf("statements = %d (%d fixed, %d affected, %d not affected), want 5 (2, 1, 2)",
			len(stmts), len(by[StatusFixed]), len(by[StatusAffected]), len(by[StatusNotAffected]))
	}
	if a := by[StatusAffected][0]; a.Product != "pkg:maven/org.apache.logging.log4j/log4j-core" ||
		!strings.Contains(a.Detail, "log4j2.formatMsgNoLookups") {
		t.Errorf("affected = %+v", a)
	}
	for _, n := range by[StatusNotAffected] {
		if !strings.HasPrefix(n.Product, "pkg:oci/") || n.Justification != "vulnerable_code_not_present" {
			t.Errorf("not affected = %+v", n)
		}
	}
	if f := by[StatusFixed][0]; !strings.HasPrefix(f.Product, "pkg:rpm/redhat/eap7-apache-cxf@3.1.16") {
		t.Errorf("fixed = %+v", f)
	}

	// Only the VEX profile: a CSAF security advisory is refused, not misread.
	if _, err := Parse([]byte(`{"document":{"category":"csaf_security_advisory","csaf_version":"2.0"},"vulnerabilities":[]}`)); err == nil {
		t.Error("a csaf_security_advisory was accepted as VEX")
	}
}
