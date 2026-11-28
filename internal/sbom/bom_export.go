package sbom

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/vex"
)

// TriageFact is the project's triage of one finding on one component of a
// snapshot: what a BOM export's vulnerability analysis is derived from.
type TriageFact struct {
	ComponentID string
	// IDs are the finding's CVEs and rule id — what it is matched to a
	// vulnerability by.
	IDs []string
	vex.Triaged
	// Statement is the stored VEX statement about the finding's vulnerability
	// (nil = none); it supplies the justification of a VEX-triaged finding.
	Statement *vex.Statement
}

// SnapshotTriage returns the triage of every non-duplicate finding on the
// snapshot's version that hits one of its packages (by the VulnState rule:
// purl, else name + version), in any status.
func (r *Repository) SnapshotTriage(ctx context.Context, sbomID string) ([]TriageFact, error) {
	q := `
		SELECT c.id, f.cve, f.rule_id, f.status, COALESCE(acc.justification, f.exception_reason),
		       COALESCE(acc.approver, f.exception_by), COALESCE(acc.expires_at, f.exception_expires_at),
		       f.fixed_version,
		       COALESCE((SELECT max(e.created_at) FROM finding_events e
		                 WHERE e.finding_id = f.id AND e.kind = 'status'), f.last_seen_at),
		       st.status, st.justification, st.detail
		FROM sbom_components c
		JOIN sboms s ON s.id = c.sbom_id
		JOIN findings f ON f.project_id = c.project_id AND f.version_id = s.version_id
		 AND f.duplicate_of IS NULL AND f.category <> 'license' AND f.scanner <> 'policy' AND` + archive.Finding("f") + `
		 AND ((c.purl <> '' AND f.purl = c.purl)
		   OR (f.package_name <> '' AND lower(f.package_name) = lower(c.name) AND f.package_version = c.version))
		LEFT JOIN LATERAL (
			-- A risk_accepted finding's reason and expiry are its approved acceptance's.
			SELECT ra.justification, ra.approver, ra.expires_at
			FROM risk_acceptance_findings ram JOIN risk_acceptances ra ON ra.id = ram.acceptance_id
			WHERE ram.finding_id = f.id AND ram.removed_at IS NULL AND ra.state = 'approved'
		) acc ON f.status = 'risk_accepted'
		LEFT JOIN LATERAL (
			SELECT v.status, v.justification, v.detail FROM vex_statements v
			WHERE v.project_id = f.project_id
			  AND (lower(v.vuln_id) = lower(f.rule_id) OR lower(v.vuln_id) IN (SELECT lower(x) FROM unnest(f.cve) x))
			  AND (v.product = '' OR lower(v.product) IN (lower(f.purl), lower(f.package_name)))
			ORDER BY v.product = '', v.updated_at DESC
			LIMIT 1
		) st ON true
		WHERE c.sbom_id = $1
		ORDER BY c.id, f.id`
	rows, err := r.db.Query(ctx, q, sbomID)
	if err != nil {
		return nil, fmt.Errorf("snapshot triage: %w", err)
	}
	defer rows.Close()
	out := []TriageFact{}
	for rows.Next() {
		var (
			t                       TriageFact
			cves                    []string
			ruleID                  string
			stStatus, stJust, stDtl *string
		)
		if err := rows.Scan(&t.ComponentID, &cves, &ruleID, &t.Status, &t.Reason, &t.By, &t.ExpiresAt,
			&t.FixedVersion, &t.At, &stStatus, &stJust, &stDtl); err != nil {
			return nil, fmt.Errorf("scan snapshot triage: %w", err)
		}
		cves = append(cves, ruleID)
		t.IDs = cves
		if stStatus != nil {
			t.Statement = &vex.Statement{Status: vex.Status(*stStatus), Justification: *stJust, Detail: *stDtl}
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

type cdxBOM struct {
	BomFormat       string                 `json:"bomFormat"`
	SpecVersion     string                 `json:"specVersion"`
	SerialNumber    string                 `json:"serialNumber"`
	Version         int                    `json:"version"`
	Metadata        cdxBOMMetadata         `json:"metadata"`
	Components      []cdxBOMComponent      `json:"components"`
	Services        []cdxService           `json:"services,omitempty"`
	Dependencies    []cycloneDependency    `json:"dependencies"`
	Vulnerabilities []vex.CDXVulnerability `json:"vulnerabilities,omitempty"`
}

type cdxBOMMetadata struct {
	Timestamp string           `json:"timestamp"`
	Tools     cdxBOMTools      `json:"tools"`
	Component vex.CDXComponent `json:"component"`
}

type cdxBOMTools struct {
	Components []vex.CDXComponent `json:"components"`
}

// ExportCycloneDX renders a snapshot as a CycloneDX JSON BOM of the given spec
// version (vex.CDXSpecVersions): the root as
// the metadata component (timestamp = snapshot time), every component and
// service with its original bom-ref (services re-nested under their parents),
// the dependency graph, and — when vulns is non-nil — its vulnerabilities, each
// with severity, the components it affects and the project's analysis of it.
func ExportCycloneDX(s Sbom, comps []ComponentHit, svcs []BomService, edges []Edge, vulns []Vulnerability, facts []TriageFact, spec string) any {
	doc := cdxBOM{
		BomFormat:    "CycloneDX",
		SpecVersion:  spec,
		SerialNumber: "urn:uuid:" + s.ID,
		Version:      1,
		Metadata: cdxBOMMetadata{
			Timestamp: s.CreatedAt.UTC().Format(time.RFC3339),
			Tools:     cdxBOMTools{Components: []vex.CDXComponent{{Type: "application", Name: "Xila"}}},
			Component: vex.CDXComponent{BomRef: s.RootRef, Type: "application",
				Name: cmp.Or(s.Artifact, "unnamed"), Version: s.Version},
		},
		Components:   make([]cdxBOMComponent, 0, len(comps)),
		Dependencies: []cycloneDependency{},
	}

	refs := make(map[string]string, len(comps)) // component id → bom-ref
	used := map[string]bool{}
	if s.RootRef != "" {
		used[s.RootRef] = true
	}
	for _, c := range comps {
		if c.Kind == KindAIService {
			continue // a service's AI inventory row: exported as the service
		}
		ref := c.BomRef
		if ref == "" || used[ref] {
			ref = "xila:component:" + c.ID // a ref the document lacked, or a clash
		}
		used[ref] = true
		refs[c.ID] = ref
		doc.Components = append(doc.Components, cdxComponent(c.Component, ref))
	}
	doc.Services = cdxServices(svcs, used)

	// Edges come sorted by parent: one dependencies entry per parent.
	for i := 0; i < len(edges); {
		d := cycloneDependency{Ref: edges[i].Parent}
		for ; i < len(edges) && edges[i].Parent == d.Ref; i++ {
			d.DependsOn = append(d.DependsOn, edges[i].Child)
		}
		doc.Dependencies = append(doc.Dependencies, d)
	}

	if vulns != nil {
		doc.Vulnerabilities = make([]vex.CDXVulnerability, 0, len(vulns))
		for _, v := range vulns {
			doc.Vulnerabilities = append(doc.Vulnerabilities, cdxVulnerability(v, refs, facts))
		}
	}
	return doc
}

type cdxService struct {
	BomRef             string           `json:"bom-ref,omitempty"`
	Provider           *cdxOrg          `json:"provider,omitempty"`
	Group              string           `json:"group,omitempty"`
	Name               string           `json:"name"`
	Version            string           `json:"version,omitempty"`
	Description        string           `json:"description,omitempty"`
	Endpoints          []string         `json:"endpoints,omitempty"`
	Authenticated      *bool            `json:"authenticated,omitempty"`
	TrustBoundary      *bool            `json:"x-trust-boundary,omitempty"`
	TrustZone          string           `json:"trustZone,omitempty"`
	Data               []storedDataFlow `json:"data,omitempty"`
	Licenses           []vex.CDXLicense `json:"licenses,omitempty"`
	ExternalReferences []ExternalRef    `json:"externalReferences,omitempty"`
	Properties         []Property       `json:"properties,omitempty"`
	Services           []cdxService     `json:"services,omitempty"`
}

type cdxOrg struct {
	Name string   `json:"name,omitempty"`
	URL  []string `json:"url,omitempty"`
}

// cdxServices renders a snapshot's flattened services (in document order) as
// CycloneDX's nested services. A ref already taken (by the root, a component or
// an earlier service) is replaced so the BOM's refs stay unique; a service
// whose parent isn't an earlier service of the snapshot goes top-level.
func cdxServices(svcs []BomService, used map[string]bool) []cdxService {
	if len(svcs) == 0 {
		return nil
	}
	nodes := make([]cdxService, len(svcs))
	firstByRef := map[string]int{}
	for i, sv := range svcs {
		ref := sv.BomRef
		if ref != "" && used[ref] {
			ref = "xila:service:" + sv.ID
		}
		if ref != "" {
			used[ref] = true
		}
		if _, ok := firstByRef[sv.BomRef]; !ok && sv.BomRef != "" {
			firstByRef[sv.BomRef] = i
		}
		n := cdxService{BomRef: ref, Group: sv.Group, Name: sv.Name, Version: sv.Version,
			Description: sv.Description, Endpoints: sv.Endpoints, Authenticated: sv.Authenticated,
			TrustBoundary: sv.TrustBoundary, TrustZone: sv.TrustZone, Licenses: cdxLicenses(sv.License),
			ExternalReferences: sv.ExternalRefs, Properties: sv.Properties}
		if sv.Provider != "" || len(sv.ProviderURL) > 0 {
			n.Provider = &cdxOrg{Name: sv.Provider, URL: sv.ProviderURL}
		}
		if len(sv.Data) > 0 {
			n.Data = storedFlows(sv.Data)
		}
		nodes[i] = n
	}
	children := make([][]int, len(svcs))
	var top []int
	for i, sv := range svcs {
		// Parents precede their children in document order, which also rules
		// out cycles.
		if p, ok := firstByRef[sv.ParentRef]; sv.ParentRef != "" && ok && p < i {
			children[p] = append(children[p], i)
		} else {
			top = append(top, i)
		}
	}
	var build func(i int) cdxService
	build = func(i int) cdxService {
		n := nodes[i]
		for _, c := range children[i] {
			n.Services = append(n.Services, build(c))
		}
		return n
	}
	out := make([]cdxService, 0, len(top))
	for _, i := range top {
		out = append(out, build(i))
	}
	return out
}

// cdxBOMComponent is a BOM component with its ML-BOM fields (model card,
// supplier, pedigree…), which only AI components carry.
type cdxBOMComponent struct {
	vex.CDXComponent
	Supplier           *cdxOrg            `json:"supplier,omitempty"`
	Manufacturer       *cdxOrg            `json:"manufacturer,omitempty"`
	Publisher          string             `json:"publisher,omitempty"`
	Description        string             `json:"description,omitempty"`
	ExternalReferences []ExternalRef      `json:"externalReferences,omitempty"`
	Pedigree           *cdxPedigree       `json:"pedigree,omitempty"`
	ModelCard          *cdxModelCard      `json:"modelCard,omitempty"`
	Data               []cdxComponentData `json:"data,omitempty"`
}

type cdxPedigree struct {
	Ancestors []MLAncestor `json:"ancestors"`
}

type cdxModelCard struct {
	ModelParameters cdxModelParameters `json:"modelParameters"`
}

type cdxModelParameters struct {
	Approach           *cdxApproach       `json:"approach,omitempty"`
	Task               string             `json:"task,omitempty"`
	ArchitectureFamily string             `json:"architectureFamily,omitempty"`
	ModelArchitecture  string             `json:"modelArchitecture,omitempty"`
	Datasets           []cdxComponentData `json:"datasets,omitempty"`
	Inputs             []cdxFormat        `json:"inputs,omitempty"`
	Outputs            []cdxFormat        `json:"outputs,omitempty"`
}

type cdxApproach struct {
	Type string `json:"type"`
}

type cdxFormat struct {
	Format string `json:"format"`
}

// cdxComponentData is CycloneDX's componentData, or in a model card a
// reference to a data component ({"ref"}).
type cdxComponentData struct {
	Ref            string       `json:"ref,omitempty"`
	Type           string       `json:"type,omitempty"`
	Name           string       `json:"name,omitempty"`
	Classification string       `json:"classification,omitempty"`
	Description    string       `json:"description,omitempty"`
	Contents       *cdxContents `json:"contents,omitempty"`
}

type cdxContents struct {
	URL string `json:"url"`
}

func cdxData(ds []MLDataset) []cdxComponentData {
	var out []cdxComponentData
	for _, d := range ds {
		if d.Ref != "" {
			out = append(out, cdxComponentData{Ref: d.Ref}) // the data component carries the rest
			continue
		}
		n := cdxComponentData{Type: d.Type, Name: d.Name, Classification: d.Classification, Description: d.Description}
		if d.URL != "" {
			n.Contents = &cdxContents{URL: d.URL}
		}
		out = append(out, n)
	}
	return out
}

func cdxFormats(fs []string) []cdxFormat {
	var out []cdxFormat
	for _, f := range fs {
		out = append(out, cdxFormat{Format: f})
	}
	return out
}

// cdxComponent renders a stored component; an AI component's ML facts become
// its supplier, publisher, pedigree, external references, data and model card.
func cdxComponent(c Component, ref string) cdxBOMComponent {
	out := cdxBOMComponent{CDXComponent: cdxComponentCore(c, ref)}
	m := c.ML
	if m == nil {
		return out
	}
	if m.Supplier != "" {
		out.Supplier = &cdxOrg{Name: m.Supplier}
	}
	if m.Manufacturer != "" {
		out.Manufacturer = &cdxOrg{Name: m.Manufacturer}
	}
	out.Publisher, out.Description, out.ExternalReferences = m.Publisher, m.Description, m.ExternalRefs
	if len(m.Ancestors) > 0 {
		out.Pedigree = &cdxPedigree{Ancestors: m.Ancestors}
	}
	out.Data = cdxData(m.Data)
	p := cdxModelParameters{Task: m.Task, ArchitectureFamily: m.ArchitectureFamily, ModelArchitecture: m.ModelArchitecture,
		Datasets: cdxData(m.Datasets), Inputs: cdxFormats(m.Inputs), Outputs: cdxFormats(m.Outputs)}
	if m.Approach != "" {
		p.Approach = &cdxApproach{Type: m.Approach}
	}
	if c.Kind == KindModel {
		out.ModelCard = &cdxModelCard{ModelParameters: p}
	}
	return out
}

func cdxComponentCore(c Component, ref string) vex.CDXComponent {
	out := vex.CDXComponent{BomRef: ref, Type: cmp.Or(c.Type, "library"), Group: c.Group, Name: c.Name,
		Version: c.Version, Purl: c.Purl, Cpe: c.Cpe, Licenses: cdxLicenses(c.License)}
	switch c.Scope {
	case domain.DepScopeRuntime:
		out.Scope = "required"
	case domain.DepScopeDev:
		out.Scope = "excluded"
	case domain.DepScopeOptional:
		out.Scope = "optional"
	}
	for _, alg := range slices.Sorted(maps.Keys(c.Hashes)) {
		if a := cdxHashAlg(alg); a != "" && c.Hashes[alg] != "" {
			out.Hashes = append(out.Hashes, vex.CDXHash{Alg: a, Content: c.Hashes[alg]})
		}
	}
	if c.FilePath != "" {
		out.Evidence = &vex.CDXEvidence{Occurrences: []vex.CDXOccurrence{{Location: c.FilePath}}}
	}
	return out
}

// cdxLicenses turns the stored, flattened license string back into CycloneDX
// licenses: one SPDX expression when it is one, else one named license per
// part. (Names, not ids: an id outside the SPDX list would make the BOM
// invalid, and the importer reads either.)
func cdxLicenses(s string) []vex.CDXLicense {
	parts := slices.DeleteFunc(strings.Split(s, ", "), func(p string) bool { return strings.TrimSpace(p) == "" })
	if len(parts) == 0 {
		return nil
	}
	if len(parts) == 1 && isExpression(parts[0]) {
		return []vex.CDXLicense{{Expression: parts[0]}}
	}
	out := make([]vex.CDXLicense, 0, len(parts))
	for _, p := range parts {
		out = append(out, vex.CDXLicense{License: &vex.CDXLicenseName{Name: strings.TrimSpace(p)}})
	}
	return out
}

func isExpression(s string) bool {
	return strings.Contains(s, " OR ") || strings.Contains(s, " AND ") || strings.Contains(s, " WITH ")
}

// cdxHashAlg normalizes a stored hash algorithm (CycloneDX or SPDX spelling)
// to CycloneDX's enumeration; "" for one it doesn't know.
func cdxHashAlg(alg string) string {
	switch strings.ToUpper(strings.NewReplacer("-", "", "_", "").Replace(alg)) {
	case "MD5":
		return "MD5"
	case "SHA1":
		return "SHA-1"
	case "SHA256":
		return "SHA-256"
	case "SHA384":
		return "SHA-384"
	case "SHA512":
		return "SHA-512"
	case "SHA3256":
		return "SHA3-256"
	case "SHA3384":
		return "SHA3-384"
	case "SHA3512":
		return "SHA3-512"
	case "BLAKE2B256":
		return "BLAKE2b-256"
	case "BLAKE2B384":
		return "BLAKE2b-384"
	case "BLAKE2B512":
		return "BLAKE2b-512"
	case "BLAKE3":
		return "BLAKE3"
	}
	return ""
}

// cdxVulnerability renders one snapshot vulnerability, with the analysis the
// project's triage of it amounts to (absent when nobody triaged it). A
// remediated finding says nothing here: the snapshot is immutable and still
// ships the package — remediated only means the project moved off it since.
func cdxVulnerability(v Vulnerability, refs map[string]string, facts []TriageFact) vex.CDXVulnerability {
	out := vex.CDXVulnerability{ID: v.Key, Source: vex.VulnSource(v.Key), Description: v.Summary,
		Ratings: []vex.CDXRating{{Severity: vex.CDXSeverity(v.Severity)}}, Affects: []vex.CDXAffectsRef{}}
	for _, id := range v.IDs {
		if !strings.EqualFold(id, v.Key) {
			out.References = append(out.References, vex.CDXReference{ID: id, Source: *vex.VulnSource(id)})
		}
	}
	if v.FixedVersion != "" {
		out.Recommendation = "Upgrade to " + v.FixedVersion
	}
	hit := map[string]bool{}
	for _, c := range v.Components {
		hit[c.ID] = true
		out.Affects = append(out.Affects, vex.CDXAffectsRef{Ref: refs[c.ID]})
	}

	var verdict *vex.Verdict
	for _, f := range facts {
		if !hit[f.ComponentID] || f.Status == domain.FindingRemediated || !namesVulnerability(f.IDs, v) {
			continue
		}
		next := vex.VerdictFor(f.Triaged, f.Statement)
		if verdict == nil {
			verdict = &next
		} else {
			*verdict = vex.Combine(*verdict, next)
		}
	}
	if verdict != nil {
		a := vex.CycloneAnalysis(*verdict)
		out.Analysis = &a
	}
	return out
}

func namesVulnerability(ids []string, v Vulnerability) bool {
	for _, id := range ids {
		if id == "" {
			continue
		}
		if strings.EqualFold(id, v.Key) || slices.ContainsFunc(v.IDs, func(x string) bool { return strings.EqualFold(x, id) }) {
			return true
		}
	}
	return false
}
