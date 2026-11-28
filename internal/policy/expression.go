package policy

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/expr"
	"github.com/xilasec/xila-api/internal/license"
	"github.com/xilasec/xila-api/internal/sbom"
)

// SubjectExpression is a CEL condition over the component's facts (see
// componentDoc): `component.name == "log4j-core" && vulns.kev`,
// `pkg.versions_behind >= 3`, `"GPL-3.0-only" in component.license.ids`.
// Its operator is "matches"; its value the expression source.
const SubjectExpression Subject = "expression"

func init() { operators[SubjectExpression] = []Operator{OpMatches} }

// componentDoc is what an expression sees about one component. Unknown facts
// are null (and so never match): no SBOM dependency graph, no license, no
// registry data, no EPSS.
func componentDoc(c *Component, now time.Time) map[string]any {
	ids := []any{}
	if !c.License.IsZero() {
		for _, id := range c.License.IDs() {
			ids = append(ids, id)
		}
	}
	var resolved any
	if c.LicenseResolved != nil {
		resolved = *c.LicenseResolved
	}
	var integrity any // null when unknown
	if c.Integrity != "" {
		integrity = c.Integrity
	}
	var algs []string
	for alg, v := range c.Hashes {
		if v != "" {
			algs = append(algs, alg)
		}
	}
	slices.Sort(algs)
	hashes := make([]any, len(algs))
	for i, a := range algs {
		hashes[i] = a
	}

	vulnIDs := []any{}
	for _, id := range c.VulnIDs {
		vulnIDs = append(vulnIDs, id)
	}
	kevSources := []any{}
	for _, s := range c.KEVSources {
		kevSources = append(kevSources, s)
	}
	cwes := []any{}
	for _, w := range c.CWEs {
		cwes = append(cwes, int64(w))
	}
	var maxSev, epss any
	maxRank := int64(0) // critical 5 … info 1, none 0 — for `vulns.max_severity_rank >= 4`
	if c.MaxSeverity != nil {
		maxSev, maxRank = string(*c.MaxSeverity), int64(severityRank(*c.MaxSeverity))
	}
	if c.EPSS != nil {
		epss = *c.EPSS
	}

	pkg := map[string]any{"known": false, "latest": nil, "outdated": nil, "versions_behind": nil, "age_days": nil}
	if c.Meta != nil {
		pkg["known"], pkg["latest"], pkg["outdated"] = true, c.Meta.Latest, c.Meta.Outdated
		if c.Meta.VersionsBehind != nil {
			pkg["versions_behind"] = int64(*c.Meta.VersionsBehind)
		}
		if c.Meta.Published != nil {
			pkg["age_days"] = int64(now.Sub(*c.Meta.Published).Hours() / 24)
		}
	}
	// model: the AI inventory facts; empty lists / null for software and for
	// whatever a model card doesn't say.
	suppliers, datasets := []any{}, []any{}
	var task, family any
	if c.ML != nil {
		for _, o := range c.ML.Organizations() {
			suppliers = append(suppliers, o)
		}
		for _, d := range datasetNames(c) {
			datasets = append(datasets, d)
		}
		if c.ML.Task != "" {
			task = c.ML.Task
		}
		if c.ML.ArchitectureFamily != "" {
			family = c.ML.ArchitectureFamily
		}
	}
	return map[string]any{
		"component": map[string]any{
			"type": c.Type, "kind": cmp.Or(c.Kind, sbom.KindSoftware), "group": c.Group, "name": c.Name, "version": c.Version, "purl": c.Purl,
			"hashes": hashes, "integrity": integrity,
			// Graph facts from the SBOM (M13 13.20): unknown is null, never false.
			"direct": nullable(c.Direct), "depth": nullableInt(c.Depth), "scope": nullableString(string(c.Scope)),
			"internal": c.Internal,
			"license": map[string]any{
				"raw": c.License, "expression": c.LicenseExpression, "ids": ids, "resolved": resolved,
			},
		},
		"vulns": map[string]any{
			"count": int64(len(c.VulnIDs)), "ids": vulnIDs, "max_severity": maxSev,
			"max_severity_rank": maxRank, "kev": c.KEV, "kev_sources": kevSources, "epss": epss, "cwes": cwes,
		},
		"pkg":   pkg,
		"model": map[string]any{"suppliers": suppliers, "task": task, "architecture_family": family, "datasets": datasets},
		"project": map[string]any{"name": c.ProjectName, "version": c.VersionName, "default_version": c.IsDefault,
			"custom": projectCustom(c.ProjectCustom)},
	}
}

// nullable is *b as a document value: null when unknown.
func nullable(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

// nullableInt is *n as a document value: null when unknown.
func nullableInt(n *int) any {
	if n == nil {
		return nil
	}
	return int64(*n)
}

// nullableString is s as a document value: null when empty (unknown).
func nullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// projectCustom copies a project's custom-field values into a document
// (project.custom.<key>; an unset field is absent and never matches).
func projectCustom(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	maps.Copy(out, m)
	return out
}

// ComponentSchema is the document expressions are checked against: every
// fact present (sample values), built by componentDoc itself so the two
// can't drift. It carries no custom fields; ComponentSchemaFor adds them.
var ComponentSchema = ComponentSchemaFor(nil)

// ComponentSchemaFor is ComponentSchema with a sample for every project
// custom field defined, so `project.custom.<key>` validates when that field
// exists.
func ComponentSchemaFor(projectFields []customfield.Definition) expr.Schema {
	sev := domain.SeverityHigh
	behind := 2
	pub := time.Now().Add(-48 * time.Hour)
	resolved := true
	direct, depth := true, 1
	epss := 0.5
	lic, _ := license.ParseExpression("MIT")
	sample := componentDoc(&Component{
		InventoryComponent: sbom.InventoryComponent{
			Type: "library", Group: "org.example", Name: "lib", Version: "1.0.0", Purl: "pkg:maven/org.example/lib@1.0.0",
			Hashes: map[string]string{"SHA-256": "00"}, Integrity: "verified", License: "MIT", LicenseExpression: "MIT", LicenseResolved: &resolved,
			VulnIDs: []string{"CVE-2021-44228"}, MaxSeverity: &sev, KEV: true, KEVSources: []string{"cisa", "enisa"}, EPSS: &epss, CWEs: []int{79},
			ProjectName: "p", VersionName: "main", IsDefault: true, ProjectCustom: customfield.Samples(projectFields),
			Direct: &direct, Depth: &depth, Scope: domain.DepScopeRuntime, Internal: true,
			Kind: sbom.KindModel, ML: &sbom.MLFacts{Supplier: "Hugging Face", Task: "text-generation",
				ArchitectureFamily: "llama", Datasets: []sbom.MLDataset{{Name: "wikipedia"}}},
		},
		License: lic,
		Meta:    &PackageInfo{Latest: "1.2.0", Outdated: true, VersionsBehind: &behind, Published: &pub},
	}, time.Now())
	// A frame that is never Set: graph functions declare (so save-time checks
	// accept them) and are false. An evaluation run gets its own (fresh()).
	return expr.Schema{Vars: []string{"component", "vulns", "pkg", "model", "project"}, Sample: sample, Frame: expr.NewGraphFrame()}
}

func compileExpression(c Condition, schema expr.Schema) (matcher, any, error) {
	var src string
	if err := decode(c, &src, "a CEL expression"); err != nil {
		return nil, nil, err
	}
	prg, err := expr.Compile(schema, src)
	if err != nil {
		return nil, nil, invalid("%s", err)
	}
	frame := schema.Frame
	return func(x *Component, now time.Time) (bool, string) {
		if frame != nil {
			frame.Set(x.Graph, x.GraphNode) // what depends_on and the rest read as "this"
		}
		if !prg.Match(context.Background(), componentDoc(x, now)) {
			return false, ""
		}
		return true, fmt.Sprintf("expression holds for %s %s", x.Name, x.Version)
	}, prg.Source, nil
}
