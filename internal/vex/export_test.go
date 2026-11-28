package vex

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
)

var exportScope = ExportScope{ProjectID: "p1", ProjectSlug: "shop", ProjectName: "Shop",
	VersionID: "v1", VersionName: "release/2.0"}

func exportFinding(cve, purl string, status domain.FindingStatus, by string) ExportFinding {
	return ExportFinding{RuleID: cve, CVE: []string{cve}, Purl: purl,
		PackageName: "pkg", PackageVersion: "1.0.0", Status: status, ExceptionReason: "reason for " + cve,
		ExceptionBy: by, Severity: domain.SeverityHigh, Title: "Bug " + cve, TriagedAt: time.Unix(1700000000, 0)}
}

func TestVerdictNeverInventsAJustification(t *testing.T) {
	manual := VerdictFor(Triaged{Status: domain.FindingFalsePositive, Reason: "test fixture only", By: "bob"}, nil)
	if manual.Status != StatusNotAffected || manual.Justification != "" || manual.Impact != "test fixture only" {
		t.Errorf("manual false positive = %+v, want not_affected with the reason as impact and no justification", manual)
	}
	// A matching statement that did not do the triage must not lend its code.
	stmt := &Statement{Status: StatusNotAffected, Justification: "code_not_reachable", Detail: "d"}
	if v := VerdictFor(Triaged{Status: domain.FindingFalsePositive, Reason: "mine", By: "bob"}, stmt); v.Justification != "" {
		t.Errorf("human triage borrowed the statement's justification: %+v", v)
	}
	// Triaged by VEX: the statement's code is carried over as recorded (each
	// format translates it; see TestExportRestatesTheRecordedJustification).
	if v := VerdictFor(Triaged{Status: domain.FindingFalsePositive, By: vexActor}, stmt); v.Justification != "code_not_reachable" || v.Impact != "d" {
		t.Errorf("VEX triage = %+v", v)
	}
	// A free-text justification stays prose.
	free := &Statement{Status: StatusNotAffected, Justification: "we checked", Detail: "twice"}
	if v := VerdictFor(Triaged{Status: domain.FindingFalsePositive, By: vexActor}, free); v.Justification != "" || v.Impact != "we checked: twice" {
		t.Errorf("free-text justification = %+v", v)
	}
	// VEX said fixed: export fixed, not not_affected.
	if v := VerdictFor(Triaged{Status: domain.FindingFalsePositive, By: vexActor}, &Statement{Status: StatusFixed}); v.Status != StatusFixed {
		t.Errorf("VEX fixed exported as %s", v.Status)
	}
}

func TestVerdictMapping(t *testing.T) {
	exp := time.Date(2027, 1, 31, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		t      Triaged
		status Status
		action string
	}{
		{Triaged{Status: domain.FindingOpen}, StatusUnderInvestigation, ""},
		{Triaged{Status: domain.FindingRemediated}, StatusFixed, ""},
		{Triaged{Status: domain.FindingConfirmed, FixedVersion: "2.0"}, StatusAffected, "Upgrade to 2.0."},
		{Triaged{Status: domain.FindingRiskAccepted, Reason: "behind WAF", ExpiresAt: &exp}, StatusAffected, "Risk accepted until 2027-01-31: behind WAF"},
		{Triaged{Status: domain.FindingWontFix, Reason: "EOL"}, StatusAffected, "Will not fix: EOL"},
	} {
		v := VerdictFor(tc.t, nil)
		if v.Status != tc.status || v.Action != tc.action {
			t.Errorf("%s → %s %q, want %s %q", tc.t.Status, v.Status, v.Action, tc.status, tc.action)
		}
	}
}

func TestBuildStatementsMergesPerProduct(t *testing.T) {
	const purl = "pkg:npm/lodash@4.17.20"
	findings := []ExportFinding{
		// Two findings on the same (CVE, package): one affected instance wins.
		exportFinding("CVE-1", purl, domain.FindingFalsePositive, "bob"),
		exportFinding("CVE-1", purl, domain.FindingConfirmed, ""),
		// No package at all: the project version is the product.
		{RuleID: "CVE-2", CVE: []string{"CVE-2"}, Status: domain.FindingOpen},
		// A package without a purl: a generic one, by name and version.
		exportFinding("CVE-3", "", domain.FindingRemediated, ""),
	}
	stored := []Statement{
		// Covers nothing exported: carried over as stored, project-wide.
		{VulnID: "CVE-9", Status: StatusNotAffected, Justification: "component_not_present", UpdatedAt: time.Unix(1, 0)},
	}
	got := BuildStatements(exportScope, findings, stored)
	if len(got) != 4 {
		t.Fatalf("statements = %+v, want 4", got)
	}
	if got[0].VulnID != "CVE-1" || got[0].Product != purl || got[0].Status != StatusAffected {
		t.Errorf("merged statement = %+v, want CVE-1 affected on %s", got[0], purl)
	}
	project := "pkg:generic/shop@release%2F2.0"
	if got[1].VulnID != "CVE-2" || got[1].Product != project || got[1].Status != StatusUnderInvestigation {
		t.Errorf("purl-less statement = %+v, want under_investigation on %s", got[1], project)
	}
	if got[2].VulnID != "CVE-3" || got[2].Product != "pkg:generic/pkg@1.0.0" || got[2].Status != StatusFixed {
		t.Errorf("purl-less package statement = %+v, want fixed on pkg:generic/pkg@1.0.0", got[2])
	}
	if got[3].VulnID != "CVE-9" || got[3].Product != project || got[3].Justification != "component_not_present" {
		t.Errorf("stored statement = %+v", got[3])
	}
}

// TestCSAFSatisfiesVEXProfile checks the CSAF 2.0 VEX profile's mandatory
// parts on a document mixing every status.
func TestCSAFSatisfiesVEXProfile(t *testing.T) {
	findings := []ExportFinding{
		exportFinding("CVE-1", "pkg:npm/a@1", domain.FindingFalsePositive, "bob"),
		exportFinding("CVE-1", "pkg:npm/b@1", domain.FindingConfirmed, ""),
		exportFinding("CVE-2", "pkg:npm/a@1", domain.FindingRiskAccepted, "bob"),
		exportFinding("CVE-3", "pkg:npm/a@1", domain.FindingRemediated, ""),
		exportFinding("GHSA-xxxx-yyyy-zzzz", "pkg:npm/c@1", domain.FindingOpen, ""),
	}
	findings[4].CVE = nil
	stored := []Statement{{VulnID: "CVE-1", Product: "pkg:npm/d@1", Status: StatusNotAffected,
		Justification: "vulnerable_code_not_present"}}
	raw, _ := json.Marshal(CSAFVEX(exportScope, BuildStatements(exportScope, findings, stored), time.Now()))
	var doc struct {
		Document struct {
			Category  string
			Publisher struct{ Category, Name, Namespace string }
			Title     string
			Tracking  struct {
				ID, Status, Version string
				InitialReleaseDate  string                                   `json:"initial_release_date"`
				CurrentReleaseDate  string                                   `json:"current_release_date"`
				RevisionHistory     []struct{ Date, Number, Summary string } `json:"revision_history"`
			}
		}
		ProductTree struct {
			FullProductNames []struct {
				ProductID string `json:"product_id"`
			} `json:"full_product_names"`
		} `json:"product_tree"`
		Vulnerabilities []struct {
			CVE           string
			IDs           []struct{ Text string }
			Notes         []struct{ Category, Text string }
			ProductStatus map[string][]string `json:"product_status"`
			Flags         []struct {
				ProductIDs []string `json:"product_ids"`
			}
			Threats []struct {
				Category   string
				ProductIDs []string `json:"product_ids"`
			}
			Remediations []struct {
				Category, Details string
				ProductIDs        []string `json:"product_ids"`
			}
		}
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	d := doc.Document
	if d.Category != "csaf_vex" || d.Publisher.Name == "" || d.Publisher.Namespace == "" || d.Publisher.Category == "" ||
		d.Title == "" || d.Tracking.ID == "" || d.Tracking.Status == "" || d.Tracking.Version == "" ||
		d.Tracking.InitialReleaseDate == "" || d.Tracking.CurrentReleaseDate == "" || len(d.Tracking.RevisionHistory) == 0 {
		t.Fatalf("document is missing mandatory fields: %s", raw)
	}
	var tree []string
	for _, p := range doc.ProductTree.FullProductNames {
		tree = append(tree, p.ProductID)
	}
	if len(doc.Vulnerabilities) != 4 {
		t.Fatalf("vulnerabilities = %d, want 4 (one per id)", len(doc.Vulnerabilities))
	}
	for _, v := range doc.Vulnerabilities {
		if v.CVE == "" && len(v.IDs) == 0 {
			t.Errorf("vulnerability without cve/ids: %+v", v)
		}
		if len(v.Notes) == 0 || len(v.ProductStatus) == 0 {
			t.Errorf("vulnerability %s lacks notes or product_status", v.CVE)
		}
		covered := func(pid string, lists ...[]string) bool {
			return slices.ContainsFunc(lists, func(l []string) bool { return slices.Contains(l, pid) })
		}
		var flagged, threatened, remediated [][]string
		for _, f := range v.Flags {
			flagged = append(flagged, f.ProductIDs)
		}
		for _, th := range v.Threats {
			if th.Category == "impact" {
				threatened = append(threatened, th.ProductIDs)
			}
		}
		for _, r := range v.Remediations {
			if r.Category == "" || r.Details == "" {
				t.Errorf("incomplete remediation %+v", r)
			}
			remediated = append(remediated, r.ProductIDs)
		}
		for status, pids := range v.ProductStatus {
			for _, pid := range pids {
				if !slices.Contains(tree, pid) {
					t.Errorf("%s %s references %s, not in the product tree", v.CVE, status, pid)
				}
				switch status {
				case "known_not_affected":
					if !covered(pid, append(flagged, threatened...)...) {
						t.Errorf("%s: not-affected %s has no flag or impact threat", v.CVE, pid)
					}
				case "known_affected":
					if !covered(pid, remediated...) {
						t.Errorf("%s: affected %s has no remediation", v.CVE, pid)
					}
				}
			}
		}
	}
	if cve1 := doc.Vulnerabilities[0]; cve1.CVE != "CVE-1" || len(cve1.ProductStatus["known_not_affected"]) != 2 ||
		len(cve1.ProductStatus["known_affected"]) != 1 {
		t.Errorf("CVE-1 product status = %v, want 2 not affected (finding + stored) and 1 affected", cve1.ProductStatus)
	}
}

// A stored analysis (M13 13.2) comes out of each format in that format's own
// vocabulary: CycloneDX restates its nine codes exactly (not folded through
// OpenVEX's five), OpenVEX and CSAF translate. A justification explains
// not_affected only, so a wont_fix one appears in no document.
func TestExportRestatesTheRecordedJustification(t *testing.T) {
	fp := exportFinding("CVE-1", "pkg:npm/a@1", domain.FindingFalsePositive, "bob")
	fp.VexJustification = domain.VexJustificationProtectedAtRuntime
	fp.VexResponse = []domain.VexResponse{domain.VexResponseWorkaroundAvailable}
	wf := exportFinding("CVE-2", "pkg:npm/a@1", domain.FindingWontFix, "bob")
	wf.VexJustification = domain.VexJustificationCodeNotPresent
	stmts := BuildStatements(exportScope, []ExportFinding{fp, wf}, nil)
	now := time.Now()

	var cdx struct {
		Vulnerabilities []struct {
			ID       string
			Analysis struct {
				State, Justification string
				Response             []string
			}
		}
	}
	raw, _ := json.Marshal(CycloneDXVEX(exportScope, stmts, "urn:uuid:1", "1.6", now))
	if err := json.Unmarshal(raw, &cdx); err != nil {
		t.Fatal(err)
	}
	cdxJust := map[string]string{}
	for _, v := range cdx.Vulnerabilities {
		cdxJust[v.ID] = v.Analysis.Justification
		if v.ID == "CVE-1" && !slices.Equal(v.Analysis.Response, []string{"workaround_available"}) {
			t.Errorf("CycloneDX CVE-1 response = %v", v.Analysis.Response)
		}
	}
	if cdxJust["CVE-1"] != "protected_at_runtime" || cdxJust["CVE-2"] != "" {
		t.Errorf("CycloneDX justifications = %v, want CVE-1 protected_at_runtime and none for the wont_fix", cdxJust)
	}

	var ov struct {
		Statements []struct {
			Vulnerability struct{ Name string }
			Justification string
		}
	}
	raw, _ = json.Marshal(OpenVEX(exportScope, stmts, now))
	if err := json.Unmarshal(raw, &ov); err != nil {
		t.Fatal(err)
	}
	ovJust := map[string]string{}
	for _, s := range ov.Statements {
		ovJust[s.Vulnerability.Name] = s.Justification
	}
	if ovJust["CVE-1"] != "inline_mitigations_already_exist" || ovJust["CVE-2"] != "" {
		t.Errorf("OpenVEX justifications = %v", ovJust)
	}

	var csaf struct {
		Vulnerabilities []struct {
			CVE   string
			Flags []struct{ Label string }
		}
	}
	raw, _ = json.Marshal(CSAFVEX(exportScope, stmts, now))
	if err := json.Unmarshal(raw, &csaf); err != nil {
		t.Fatal(err)
	}
	for _, v := range csaf.Vulnerabilities {
		var labels []string
		for _, f := range v.Flags {
			labels = append(labels, f.Label)
		}
		want := map[string][]string{"CVE-1": {"inline_mitigations_already_exist"}}[v.CVE]
		if !slices.Equal(labels, want) {
			t.Errorf("CSAF %s flags = %v, want %v", v.CVE, labels, want)
		}
	}
}
