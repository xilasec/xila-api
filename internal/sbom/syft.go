package sbom

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// --- Syft native JSON schema (the subset we consume) ---
//
// Syft (`syft <target> -o json`) is an SBOM generator, not a vulnerability
// scanner — it has nothing for scanner.Parser to map, since it reports
// packages, not findings (Grype, which matches Syft's output against
// advisories, is the scanner; see grype.go). Syft can already emit CycloneDX
// or SPDX JSON directly, both already handled above; this format is for the
// native `-o json` output, which additionally carries Syft's own package id
// graph (artifactRelationships) and license evidence detail CycloneDX/SPDX
// conversion sometimes loses.

type syftDoc struct {
	Artifacts             []syftPackage      `json:"artifacts"`
	ArtifactRelationships []syftRelationship `json:"artifactRelationships"`
	Source                struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"source"`
	Descriptor struct {
		Name string `json:"name"`
	} `json:"descriptor"`
	Schema struct {
		Version string `json:"version"`
	} `json:"schema"`
}

// syftRelationship is one edge Syft reports between any two graph nodes
// (package, file or source). "dependency-of" is a proxy for the SPDX
// DEPENDENCY_OF relationship: the From package is a dependency of the To
// package, i.e. To depends on From — the reverse of Edge's own
// "Parent depends on Child" convention, so parseSyft swaps them.
type syftRelationship struct {
	Parent string `json:"parent"`
	Child  string `json:"child"`
	Type   string `json:"type"`
}

type syftPackage struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Type      string `json:"type"`
	Purl      string `json:"purl"`
	Locations []struct {
		Path string `json:"path"`
	} `json:"locations"`
	Licenses []struct {
		Value          string `json:"value"`
		SPDXExpression string `json:"spdxExpression"`
	} `json:"licenses"`
	CPEs []struct {
		CPE string `json:"cpe"`
	} `json:"cpes"`
}

// isSyft sniffs Syft's native JSON by its descriptor, the same way
// isScanCodeIO reads ScanCode.io's tool_name header.
func isSyft(raw []byte) bool {
	var probe struct {
		Artifacts  []json.RawMessage `json:"artifacts"`
		Descriptor struct {
			Name string `json:"name"`
		} `json:"descriptor"`
	}
	if json.Unmarshal(raw, &probe) != nil {
		return false
	}
	return probe.Artifacts != nil && strings.EqualFold(probe.Descriptor.Name, "syft")
}

// parseSyft decodes Syft's native JSON output into a Document. Syft doesn't
// name a single root component the way CycloneDX/SPDX do (its "source" node
// is the scan target, not a package), so Direct/Depth aren't computed here —
// only the raw dependency edges, which a future depth computation could still
// walk from a known root.
func parseSyft(r io.Reader) (Document, error) {
	var doc syftDoc
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("decode syft: %w", err)
	}
	if doc.Artifacts == nil {
		return Document{}, fmt.Errorf("not a syft document (missing artifacts)")
	}

	out := Document{
		Format:      "Syft",
		SpecVersion: doc.Schema.Version,
		Artifact:    doc.Source.Name,
		Version:     doc.Source.Version,
		Components:  make([]Component, 0, len(doc.Artifacts)),
		RootRef:     doc.Source.ID,
	}
	for _, rel := range doc.ArtifactRelationships {
		if strings.EqualFold(rel.Type, "dependency-of") {
			out.Edges = append(out.Edges, Edge{Parent: rel.Child, Child: rel.Parent})
		}
	}
	for _, a := range doc.Artifacts {
		if a.Name == "" {
			continue // a package without a name is not addressable
		}
		comp := Component{
			BomRef:  a.ID,
			Type:    firstNonEmpty(a.Type, "library"),
			Name:    a.Name,
			Version: a.Version,
			Purl:    a.Purl,
			Cpe:     syftCpe(a.CPEs),
			License: syftLicense(a.Licenses),
		}
		if len(a.Locations) > 0 {
			comp.FilePath = a.Locations[0].Path
		}
		if comp.License != "" {
			comp.LicenseTerms = []string{comp.License}
		}
		out.Components = append(out.Components, comp)
	}
	return out, nil
}

func syftCpe(cpes []struct {
	CPE string `json:"cpe"`
},
) string {
	if len(cpes) > 0 {
		return cpes[0].CPE
	}
	return ""
}

// syftLicense flattens Syft's license evidence into an SPDX-ish string,
// preferring each entry's normalized spdxExpression over its raw value.
func syftLicense(licenses []struct {
	Value          string `json:"value"`
	SPDXExpression string `json:"spdxExpression"`
},
) string {
	parts := make([]string, 0, len(licenses))
	for _, l := range licenses {
		parts = append(parts, firstNonEmpty(l.SPDXExpression, l.Value))
	}
	return strings.Join(parts, ", ")
}
