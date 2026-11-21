package sbom

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Document is the parsed, tool-agnostic result of an SBOM upload.
type Document struct {
	Format       string
	SpecVersion  string
	SerialNumber string
	Artifact     string // subject of the SBOM (metadata.component.name)
	Version      string // metadata.component.version
	Components   []Component
	// Services the document declares (CycloneDX only; SPDX has no services),
	// flattened in document order. Their dependencies are part of Edges.
	Services []BomService
	// The dependency graph, in the document's own node ids (Component.BomRef).
	// RootRef is the subject — usually not itself a listed component; empty when
	// the document doesn't name one.
	RootRef string
	Edges   []Edge
	// XML marks a document parsed from CycloneDX XML rather than JSON: strict
	// schema validation (SBOM_STRICT_VALIDATION / ?strict=true) checks the JSON
	// schema only, so an XML upload in strict mode is refused, not silently
	// skipped (see ErrStrictXMLUnsupported).
	XML bool
}

// Edge is one "Parent depends on Child" link of the dependency graph.
type Edge struct {
	Parent string `json:"from"`
	Child  string `json:"to"`
}

// --- CycloneDX JSON schema (the subset we consume) ---

type cycloneDoc struct {
	BomFormat    string `json:"bomFormat"`
	SpecVersion  string `json:"specVersion"`
	SerialNumber string `json:"serialNumber"`
	Metadata     struct {
		Component cycloneComponent `json:"component"`
	} `json:"metadata"`
	Components   []cycloneComponent  `json:"components"`
	Services     []cycloneService    `json:"services"`
	Dependencies []cycloneDependency `json:"dependencies"`
}

// cycloneDependency is one edge list in the BOM's dependency graph: ref depends
// on each of dependsOn. Walking it from the root component is what tells us which
// packages the project actually asked for and which it merely inherited.
type cycloneDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

type cycloneComponent struct {
	BomRef   string           `json:"bom-ref"`
	Scope    string           `json:"scope"`
	Type     string           `json:"type"`
	Group    string           `json:"group"`
	Name     string           `json:"name"`
	Version  string           `json:"version"`
	Purl     string           `json:"purl"`
	Cpe      string           `json:"cpe"`
	Licenses []cycloneLicense `json:"licenses"`
	Hashes   []cycloneHash    `json:"hashes"`
	Evidence   cycloneEvidence   `json:"evidence"`
	Properties []cycloneProperty `json:"properties"`

	// ML-BOM: who made it, what it is and the model card (see MLFacts).
	Supplier           *cycloneOrg       `json:"supplier"`
	Manufacturer       *cycloneOrg       `json:"manufacturer"`
	Publisher          string            `json:"publisher"`
	Description        string            `json:"description"`
	ExternalReferences []ExternalRef     `json:"externalReferences"`
	Pedigree           *cyclonePedigree  `json:"pedigree"`
	ModelCard          *cycloneModelCard `json:"modelCard"`
	Data               []cycloneDataset  `json:"data"`
}

// cycloneLicense is one entry of a licenseChoice: a license (SPDX id or free
// name) or an SPDX expression. CycloneDX 1.6 adds an acknowledgement
// ("declared" by the author / "concluded" by analysis) on both shapes.
type cycloneLicense struct {
	License struct {
		ID              string `json:"id"`
		Name            string `json:"name"`
		Acknowledgement string `json:"acknowledgement"`
	} `json:"license"`
	Expression      string `json:"expression"`
	Acknowledgement string `json:"acknowledgement"`
}

// term is the entry's single license statement.
func (l cycloneLicense) term() string {
	switch {
	case l.License.ID != "":
		return l.License.ID
	case l.License.Name != "":
		return l.License.Name
	}
	return l.Expression
}

func (l cycloneLicense) concluded() bool {
	return strings.EqualFold(l.License.Acknowledgement, "concluded") || strings.EqualFold(l.Acknowledgement, "concluded")
}

type cycloneHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// cycloneOccurrence is one evidence.occurrences[] entry (named, not inline,
// so the XML parser can build the same value CycloneDX JSON decodes into).
type cycloneOccurrence struct {
	Location string `json:"location"`
}

// cycloneEvidence is a component's evidence.occurrences[].
type cycloneEvidence struct {
	Occurrences []cycloneOccurrence `json:"occurrences"`
}

// cycloneProperty is one CycloneDX name/value property.
type cycloneProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// parseCycloneDX decodes a CycloneDX JSON BOM into a Document.
func parseCycloneDX(r io.Reader) (Document, error) {
	var doc cycloneDoc
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("decode cyclonedx: %w", err)
	}
	if !strings.EqualFold(doc.BomFormat, "CycloneDX") {
		return Document{}, fmt.Errorf("not a CycloneDX document (bomFormat=%q)", doc.BomFormat)
	}
	return buildCycloneDocument(doc)
}

// buildCycloneDocument turns a decoded cycloneDoc (from JSON or, via
// parseCycloneDXXML's conversion, XML) into a Document. Both formats share
// this one walk, so a document means the same thing either way it was
// encoded.
func buildCycloneDocument(doc cycloneDoc) (Document, error) {
	out := Document{
		Format:       "CycloneDX",
		SpecVersion:  doc.SpecVersion,
		SerialNumber: doc.SerialNumber,
		Artifact:     doc.Metadata.Component.Name,
		Version:      doc.Metadata.Component.Version,
		Components:   make([]Component, 0, len(doc.Components)),
		RootRef:      doc.Metadata.Component.BomRef,
		Services:     flattenServices(doc.Services),
	}
	for _, d := range doc.Dependencies {
		for _, child := range d.DependsOn {
			out.Edges = append(out.Edges, Edge{Parent: d.Ref, Child: child})
		}
	}
	depths := cycloneDepths(doc)
	names := make(map[string]string, len(doc.Components)) // bom-ref → name, for model-card dataset refs
	for _, c := range doc.Components {
		if c.BomRef != "" && c.Name != "" {
			names[c.BomRef] = c.Name
		}
	}
	for _, c := range doc.Components {
		if c.Name == "" {
			continue // a component without a name is not addressable
		}
		comp := Component{
			BomRef:       c.BomRef,
			Type:         firstNonEmpty(c.Type, "library"),
			Group:        c.Group,
			Name:         c.Name,
			Version:      c.Version,
			Purl:         c.Purl,
			Cpe:          c.Cpe,
			License:      licenseString(c.Licenses),
			LicenseTerms: licenseTerms(c.Licenses),
			FilePath:     componentLocation(c),
			Hashes:       hashMap(c.Hashes),
			Scope:        cycloneScope(c),
			Kind:         componentKind(c.Type),
		}
		if IsAIKind(comp.Kind) {
			comp.ML = mlFacts(c, names)
		}
		if d, ok := depths[c.BomRef]; ok {
			direct := d == 1
			comp.Direct, comp.Depth = &direct, &d
		}
		out.Components = append(out.Components, comp)
	}
	for _, comp := range aiServices(out.Components, out.Services, out.Edges) {
		if d, ok := depths[comp.BomRef]; ok && comp.BomRef != "" {
			direct := d == 1
			comp.Direct, comp.Depth = &direct, &d
		}
		out.Components = append(out.Components, comp)
	}
	return out, nil
}

// cycloneDepths walks the dependency graph outward from the root component,
// returning each bom-ref's distance from it: 1 = the project depends on it
// directly, 2+ = it came along with something else. Refs the graph never reaches
// (or a BOM with no graph at all) are simply absent — unknown, not zero.
func cycloneDepths(doc cycloneDoc) map[string]int {
	root := doc.Metadata.Component.BomRef
	if root == "" || len(doc.Dependencies) == 0 {
		return nil
	}
	edges := make(map[string][]string, len(doc.Dependencies))
	for _, d := range doc.Dependencies {
		edges[d.Ref] = append(edges[d.Ref], d.DependsOn...)
	}

	depths := map[string]int{}
	queue := []string{root}
	seen := map[string]bool{root: true}
	for depth := 1; len(queue) > 0; depth++ {
		var next []string
		for _, ref := range queue {
			for _, child := range edges[ref] {
				if seen[child] {
					continue // first time we reach it is its shortest path
				}
				seen[child] = true
				depths[child] = depth
				next = append(next, child)
			}
		}
		queue = next
	}
	return depths
}

// cycloneScope maps CycloneDX's component scope. The spec's "excluded" means the
// component is present but not used at runtime — build/test tooling — which is
// exactly what we call dev. Some tools instead say so in a property.
func cycloneScope(c cycloneComponent) domain.DepScope {
	switch strings.ToLower(c.Scope) {
	case "excluded":
		return domain.DepScopeDev
	case "optional":
		return domain.DepScopeOptional
	case "required":
		return domain.DepScopeRuntime
	}
	for _, p := range c.Properties {
		// cdxgen and friends flag dev dependencies with a boolean property.
		if strings.Contains(strings.ToLower(p.Name), "dev") && strings.EqualFold(p.Value, "true") {
			return domain.DepScopeDev
		}
	}
	return domain.DepScopeUnknown
}

// componentLocation extracts the file a component was found in. It prefers the
// standard CycloneDX evidence.occurrences[].location, then falls back to syft's
// "syft:location:N:path" properties (emitted by Syft/Grype/Trivy).
func componentLocation(c cycloneComponent) string {
	for _, occ := range c.Evidence.Occurrences {
		if occ.Location != "" {
			return occ.Location
		}
	}
	for _, p := range c.Properties {
		if strings.HasPrefix(p.Name, "syft:location:") && strings.HasSuffix(p.Name, ":path") && p.Value != "" {
			return p.Value
		}
	}
	return ""
}

// licenseString flattens CycloneDX's license shapes into an SPDX-ish string.
func licenseString(licenses []cycloneLicense) string {
	var parts []string
	for _, l := range licenses {
		switch {
		case l.License.ID != "":
			parts = append(parts, l.License.ID)
		case l.License.Name != "":
			parts = append(parts, l.License.Name)
		case l.Expression != "":
			parts = append(parts, l.Expression)
		}
	}
	return strings.Join(parts, ", ")
}

// licenseTerms are the statements license resolution combines. The CycloneDX
// spec doesn't define how several entries of a licenseChoice relate; a list of
// licenses on one component means the component is distributed under all of
// them (each file under its own), so they combine with AND — the conservative
// reading for policy, which an alternative-choice OR would only loosen. When
// entries are acknowledged (1.6), the "concluded" ones win over "declared", as
// SPDX's licenseConcluded does over licenseDeclared.
func licenseTerms(licenses []cycloneLicense) []string {
	var terms, concluded []string
	for _, l := range licenses {
		t := l.term()
		if t == "" {
			continue
		}
		terms = append(terms, t)
		if l.concluded() {
			concluded = append(concluded, t)
		}
	}
	if len(concluded) > 0 {
		return concluded
	}
	return terms
}

func hashMap(hashes []cycloneHash) map[string]string {
	out := make(map[string]string, len(hashes))
	for _, h := range hashes {
		if h.Alg != "" {
			out[h.Alg] = h.Content
		}
	}
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
