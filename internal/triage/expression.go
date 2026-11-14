package triage

import (
	"math"

	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/expr"
	"github.com/xilasec/xila-api/internal/finding"
)

// findingDoc is what a rule's expression sees about a finding. Unknown facts
// are null and never match: no CVSS or EPSS yet, no CWE, no dependency graph.
// Custom fields are finding.custom.<key> / project.custom.<key>; one that is
// unset is absent, so reading it is "no match" (has() tests for it).
func findingDoc(f finding.Finding, p ProjectFacts) map[string]any {
	crit := p.Criticality
	str := func(xs []string) []any {
		out := make([]any, len(xs))
		for i, x := range xs {
			out[i] = x
		}
		return out
	}
	var cwe, cvss, epss, direct, depth any
	if f.CWE != nil {
		cwe = int64(*f.CWE)
	}
	if f.CVSS != nil {
		cvss = *f.CVSS
	}
	if f.EPSS != nil {
		// findings.epss is a REAL: a stored 0.9 reads back as 0.8999999761…;
		// EPSS has 5 decimals, so round to them and `epss >= 0.9` holds.
		epss = math.Round(*f.EPSS*1e5) / 1e5
	}
	if f.DepDirect != nil {
		direct = *f.DepDirect
	}
	if f.DepDepth != nil {
		depth = int64(*f.DepDepth)
	}
	var scope any
	if f.DepScope != "" {
		scope = string(f.DepScope)
	}
	var critVal any
	if crit != "" {
		critVal = string(crit)
	}
	return map[string]any{
		"finding": map[string]any{
			"scanner": f.Scanner, "category": string(f.Category), "rule_id": f.RuleID, "title": f.Title,
			"severity": string(f.Severity), "status": string(f.Status),
			"cve": str(f.CVE), "cwe": cwe, "cvss": cvss, "epss": epss, "kev": f.KEV,
			"kev_sources": str(f.KEVSources),
			"package":     f.PackageName, "version": f.PackageVersion, "fixed_version": f.FixedVersion, "purl": f.Purl,
			"file_path": f.FilePath, "url": f.URL, "tags": str(f.Tags),
			"dep_direct": direct, "dep_depth": depth, "dep_scope": scope,
			"custom": customDoc(f.Custom),
		},
		"project": map[string]any{"criticality": critVal, "custom": customDoc(p.Custom)},
	}
}

// customDoc copies stored custom values into a document (never nil).
func customDoc(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// FindingSchema is the document triage expressions are checked against, built
// by findingDoc itself so the two can't drift. It carries no custom fields;
// FindingSchemaFor adds the defined ones.
var FindingSchema = FindingSchemaFor(nil, nil)

// FindingSchemaFor is FindingSchema with a sample value for every finding and
// project custom field defined, so `finding.custom.<key>` validates when (and
// only when) that field exists.
func FindingSchemaFor(findingFields, projectFields []customfield.Definition) expr.Schema {
	cwe, depth, direct := 79, 2, false
	cvss, epss := 9.8, 0.5
	sample := findingDoc(finding.Finding{
		Scanner: "trivy", Category: domain.CategorySCA, RuleID: "CVE-2021-44228", Title: "t", Severity: domain.SeverityHigh,
		Status: domain.FindingOpen, CVE: []string{"CVE-2021-44228"}, CWE: &cwe, CVSS: &cvss, EPSS: &epss, KEV: true,
		KEVSources:  []string{"cisa", "enisa"},
		PackageName: "log4j-core", PackageVersion: "2.14.1", FixedVersion: "2.15.0", Purl: "pkg:maven/x/y@1",
		FilePath: "pom.xml", URL: "https://x", Tags: []string{"pci"},
		DepDirect: &direct, DepDepth: &depth, DepScope: domain.DepScope("required"),
		Custom: customfield.Samples(findingFields),
	}, ProjectFacts{Criticality: domain.Criticality("high"), Custom: customfield.Samples(projectFields)})
	return expr.Schema{Vars: []string{"finding", "project"}, Sample: sample}
}
