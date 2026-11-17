package vulnpolicy

import (
	"math"
	"slices"
	"strings"

	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/expr"
	"github.com/xilasec/xila-api/internal/finding"
)

// pairDoc is what a policy's condition sees about one component +
// vulnerability pair — a package finding. Unknown facts are null and never
// match: no CVSS/EPSS yet, no CWE, no dependency graph, no disclosure date
// (findings don't carry one; vulnerability.published is always unknown).
// Project tags/custom come from ProjectFacts, the same shape triage rules use.
func pairDoc(f finding.Finding, p ProjectFacts) map[string]any {
	strs := func(xs []string) []any {
		out := make([]any, len(xs))
		for i, x := range xs {
			out[i] = x
		}
		return out
	}
	var direct any
	if f.DepDirect != nil {
		direct = *f.DepDirect
	}
	var scope any
	if f.DepScope != "" {
		scope = string(f.DepScope)
	}
	var license any
	if l, ok := f.Metadata["license"].(string); ok && l != "" {
		license = l
	}
	group, name := purlGroupName(f.Purl)
	if name == "" {
		name = f.PackageName
	}
	var groupVal any
	if group != "" {
		groupVal = group
	}

	var cvss, epss any
	if f.CVSS != nil {
		cvss = *f.CVSS
	}
	if f.EPSS != nil {
		// findings.epss is a REAL: round to its 5 stored decimals so
		// `epss >= 0.9` holds for a stored 0.9.
		epss = math.Round(*f.EPSS*1e5) / 1e5
	}
	cwes := make([]any, 0, 1)
	if f.CWE != nil {
		cwes = append(cwes, int64(*f.CWE))
	}
	var critVal any
	if p.Criticality != "" {
		critVal = string(p.Criticality)
	}

	return map[string]any{
		"component": map[string]any{
			"name": name, "version": f.PackageVersion, "purl": f.Purl,
			"group": groupVal, "license": license, "scope": scope, "direct": direct,
		},
		"vulnerability": map[string]any{
			"id": vulnID(f), "aliases": strs(aliases(f)),
			"severity": string(f.Severity), "cvss": cvss, "epss": epss, "kev": f.KEV,
			"cwes": cwes, "published": nil,
		},
		"project": map[string]any{
			"name": p.Name, "tags": strs(p.Tags), "criticality": critVal, "custom": customDoc(p.Custom),
		},
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

// vulnID is the pair's primary vulnerability identity: the first CVE, else
// the rule id (OSV findings carry a GHSA/EUVD there).
func vulnID(f finding.Finding) string {
	if len(f.CVE) > 0 {
		return f.CVE[0]
	}
	return f.RuleID
}

// aliases is every id the pair's vulnerability is known by: its CVEs and its
// rule id, deduplicated.
func aliases(f finding.Finding) []string {
	out := append([]string{}, f.CVE...)
	if f.RuleID != "" && !slices.ContainsFunc(out, func(x string) bool { return strings.EqualFold(x, f.RuleID) }) {
		out = append(out, f.RuleID)
	}
	return out
}

// purlGroupName splits a PURL's namespace and name (pkg:type/namespace/name@
// version?qualifiers#subpath); group is "" without one. Unparsable/empty
// input returns "", "". The version separator is only searched for after the
// last '/' — an npm scope's own leading '@' (pkg:npm/@angular/core@1.2.3)
// must never be mistaken for it.
func purlGroupName(purl string) (group, name string) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return "", ""
	}
	_, rest, ok = strings.Cut(rest, "/")
	if !ok {
		return "", ""
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	searchFrom := 0
	if slash := strings.LastIndex(rest, "/"); slash >= 0 {
		searchFrom = slash + 1
	}
	if at := strings.IndexByte(rest[searchFrom:], '@'); at >= 0 {
		rest = rest[:searchFrom+at]
	}
	if idx := strings.LastIndex(rest, "/"); idx >= 0 {
		return rest[:idx], rest[idx+1:]
	}
	return "", rest
}

// Schema is the document vuln policy conditions are checked against with no
// custom project fields defined; built by pairDoc itself so the two can't
// drift. SchemaFor adds the project's currently defined custom fields, so
// `project.custom.<key>` validates when (and only when) that field exists.
var Schema = SchemaFor(nil)

// SchemaFor is Schema with a sample value for every project custom field
// defined.
func SchemaFor(projectFields []customfield.Definition) expr.Schema {
	cwe, direct, cvss, epss := 79, false, 9.8, 0.5
	sample := pairDoc(finding.Finding{
		Scanner: "osv", Category: domain.CategorySCA, RuleID: "GHSA-jfh8-c2jp-5v3q", Title: "t", Severity: domain.SeverityCritical,
		CVE: []string{"CVE-2021-44228"}, CWE: &cwe, CVSS: &cvss, EPSS: &epss, KEV: true,
		PackageName: "log4j-core", PackageVersion: "2.14.1", Purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
		DepDirect: &direct, DepScope: domain.DepScope("required"),
		Metadata: map[string]any{"license": "Apache-2.0"},
	}, ProjectFacts{Name: "demo", Tags: []string{"pci"}, Criticality: domain.Criticality("high"), Custom: customfield.Samples(projectFields)})
	return expr.Schema{Vars: []string{"component", "vulnerability", "project"}, Sample: sample}
}
