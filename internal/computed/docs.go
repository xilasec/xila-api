package computed

import (
	"github.com/xilasec/xila-api/internal/asset"
	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/expr"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/triage"
)

// Document variable names, by entity — what a computed field's expression
// may read (see expr.Schema.Vars and the *Doc builders below).
var (
	findingSchemaVars = []string{"finding", "project"}
	projectSchemaVars = []string{"project"}
	assetSchemaVars   = []string{"asset", "project"}
)

// findingDoc is the document a computed finding field's expression evaluates
// against: exactly triage.FindingDoc (finding.*, project.*), so it can't
// drift from what the triage engine already reads for the same finding —
// with every computed key dropped from both custom maps so one computed
// field never reads another (avoids cycles). Other consumers of finding.custom
// / project.custom (triage rules, policies, filters, exports) still see a
// computed field's stored value unchanged; the exclusion is only for computing
// a new one.
func findingDoc(f finding.Finding, facts triage.ProjectFacts, findingFields, projectFields []customfield.Definition) map[string]any {
	doc := triage.FindingDoc(f, facts)
	stripComputed(doc, "finding", findingFields)
	stripComputed(doc, "project", projectFields)
	return doc
}

// findingSchemaFor is the schema a computed finding field's expression is
// validated against on save — the same shape findingDoc builds, so the dry
// run can't accept something runtime evaluation would never see.
func findingSchemaFor(findingFields, projectFields []customfield.Definition) expr.Schema {
	s := triage.FindingSchemaFor(findingFields, projectFields)
	stripComputed(s.Sample, "finding", findingFields)
	stripComputed(s.Sample, "project", projectFields)
	return s
}

// stripComputed deletes every computed key of defs from doc[section]["custom"].
func stripComputed(doc map[string]any, section string, defs []customfield.Definition) {
	sec, ok := doc[section].(map[string]any)
	if !ok {
		return
	}
	custom, ok := sec["custom"].(map[string]any)
	if !ok {
		return
	}
	for _, d := range defs {
		if d.Computed {
			delete(custom, d.Key)
		}
	}
}

// sampleOpenFindings is the zeroed "open_findings" sample every project
// document carries, so `project.open_findings.critical` validates on save.
func sampleOpenFindings() map[string]any {
	out := map[string]any{}
	for _, sev := range domain.SeveritiesAtLeast(domain.SeverityInfo) {
		out[string(sev)] = int64(0)
	}
	return out
}

// openFindingCounts sums a project's open/confirmed finding counts by
// severity (finding.Repository.CountByProjects, already computed for the
// portfolio rollups — reusing it keeps this "if cheap": one query per
// project, no new join).
func openFindingCounts(counts []finding.StatusSeverityCount) map[string]any {
	out := sampleOpenFindings()
	for _, c := range counts {
		if c.Status.CountsRisk() {
			out[string(c.Severity)] = out[string(c.Severity)].(int64) + int64(c.Count)
		}
	}
	return out
}

// projectDoc is what a computed project field's own expression sees
// (project.*), and the project.* section of a computed asset field's
// document. Unknown facts are null; a project's own computed keys never
// appear in project.custom (avoids cycles).
func projectDoc(p project.Project, openFindings map[string]any, projectFields []customfield.Definition) map[string]any {
	tags := make([]any, len(p.Tags))
	for i, t := range p.Tags {
		tags[i] = t
	}
	var crit any
	if p.BusinessCriticality != "" {
		crit = string(p.BusinessCriticality)
	}
	return map[string]any{
		"project": map[string]any{
			"name": p.Name, "slug": p.Slug, "tags": tags,
			"criticality":   crit,
			"custom":        customfield.FilterComputed(p.Custom, projectFields),
			"open_findings": openFindings,
		},
	}
}

// projectSchemaFor is the schema a computed project field's expression is
// validated against — built by projectDoc itself so the two can't drift.
func projectSchemaFor(projectFields []customfield.Definition) expr.Schema {
	sample := projectDoc(project.Project{
		Name: "demo-service", Slug: "demo-service", Tags: []string{"pci"},
		BusinessCriticality: domain.CriticalityHigh,
		Custom:              customfield.Samples(projectFields),
	}, sampleOpenFindings(), projectFields)
	return expr.Schema{Vars: projectSchemaVars, Sample: sample}
}

// assetDoc is what a computed asset field's expression sees: asset.* plus
// the same project.* section a computed project field would see for that
// asset's project.
func assetDoc(a asset.Asset, projectSection map[string]any, assetFields []customfield.Definition) map[string]any {
	var exposure any
	if a.Exposure != nil && *a.Exposure != domain.ExposureUnknown {
		exposure = string(*a.Exposure)
	}
	doc := map[string]any{
		"asset": map[string]any{
			"name": a.Name, "type": string(a.Type), "identifier": a.Identifier,
			"exposure": exposure,
			"custom":   customfield.FilterComputed(a.Custom, assetFields),
		},
	}
	for k, v := range projectSection {
		doc[k] = v
	}
	return doc
}

// assetSchemaFor is the schema a computed asset field's expression is
// validated against — built by assetDoc itself so the two can't drift.
func assetSchemaFor(assetFields, projectFields []customfield.Definition) expr.Schema {
	exposure := domain.ExposureInternet
	sample := assetDoc(asset.Asset{
		Name: "api", Type: domain.AssetHost, Identifier: "10.0.0.1", Exposure: &exposure,
		Custom: customfield.Samples(assetFields),
	}, projectSchemaFor(projectFields).Sample, assetFields)
	return expr.Schema{Vars: assetSchemaVars, Sample: sample}
}
