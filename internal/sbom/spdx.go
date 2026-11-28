package sbom

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// --- SPDX 2.x JSON schema (the subset we consume) ---

type spdxDoc struct {
	SpdxVersion       string             `json:"spdxVersion"`
	Name              string             `json:"name"`
	DocumentDescribes []string           `json:"documentDescribes"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

// spdxRelationship is one edge of SPDX's graph. DEPENDS_ON gives us the tree;
// DEV/TEST/OPTIONAL_DEPENDENCY_OF tell us whether a package ships.
type spdxRelationship struct {
	SpdxElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSpdxElement string `json:"relatedSpdxElement"`
}

type spdxPackage struct {
	SpdxID           string         `json:"SPDXID"`
	Name             string         `json:"name"`
	VersionInfo      string         `json:"versionInfo"`
	LicenseConcluded string         `json:"licenseConcluded"`
	LicenseDeclared  string         `json:"licenseDeclared"`
	ExternalRefs     []spdxExtRef   `json:"externalRefs"`
	Checksums        []spdxChecksum `json:"checksums"`
}

type spdxExtRef struct {
	ReferenceType    string `json:"referenceType"`
	ReferenceLocator string `json:"referenceLocator"`
}

type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

// parseSPDX decodes an SPDX JSON document into a Document.
func parseSPDX(r io.Reader) (Document, error) {
	var doc spdxDoc
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("decode spdx: %w", err)
	}
	if doc.SpdxVersion == "" {
		return Document{}, errors.New("not an SPDX document (missing spdxVersion)")
	}

	out := Document{
		Format:      "SPDX",
		SpecVersion: doc.SpdxVersion,
		Artifact:    doc.Name,
		Components:  make([]Component, 0, len(doc.Packages)),
	}
	depths, scopes := spdxGraph(doc)
	out.RootRef, out.Edges = spdxEdges(doc)
	for _, p := range doc.Packages {
		if p.Name == "" {
			continue
		}
		comp := Component{
			BomRef:  p.SpdxID,
			Type:    "library",
			Name:    p.Name,
			Version: p.VersionInfo,
			Purl:    spdxPurl(p.ExternalRefs),
			Cpe:     spdxCpe(p.ExternalRefs),
			License: spdxLicense(p),
			Hashes:  spdxHashes(p.Checksums),
			Scope:   scopes[p.SpdxID],
		}
		if d, ok := depths[p.SpdxID]; ok {
			direct := d == 1
			comp.Direct, comp.Depth = &direct, &d
		}
		// The concluded license (else the declared one) is a single SPDX
		// expression already.
		if comp.License != "" {
			comp.LicenseTerms = []string{comp.License}
		}
		out.Components = append(out.Components, comp)
	}
	return out, nil
}

// spdxGraph walks DEPENDS_ON outward from the document's root package(s) to get
// each package's distance from the root, and reads the DEV/TEST/OPTIONAL
// dependency relationships to decide whether it ships. Packages the graph never
// reaches stay absent — unknown, not zero.
func spdxGraph(doc spdxDoc) (map[string]int, map[string]domain.DepScope) {
	edges := map[string][]string{}
	scopes := map[string]domain.DepScope{}
	for _, r := range doc.Relationships {
		switch strings.ToUpper(r.RelationshipType) {
		case "DEPENDS_ON":
			edges[r.SpdxElementID] = append(edges[r.SpdxElementID], r.RelatedSpdxElement)
		case "DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF":
			edges[r.RelatedSpdxElement] = append(edges[r.RelatedSpdxElement], r.SpdxElementID)
		// "X is a dev dependency of Y" — the scope belongs to X, the subject.
		case "DEV_DEPENDENCY_OF", "TEST_DEPENDENCY_OF", "BUILD_DEPENDENCY_OF":
			scopes[r.SpdxElementID] = domain.DepScopeDev
			edges[r.RelatedSpdxElement] = append(edges[r.RelatedSpdxElement], r.SpdxElementID)
		case "OPTIONAL_DEPENDENCY_OF":
			scopes[r.SpdxElementID] = domain.DepScopeOptional
			edges[r.RelatedSpdxElement] = append(edges[r.RelatedSpdxElement], r.SpdxElementID)
		}
	}

	roots := doc.DocumentDescribes
	if len(roots) == 0 {
		roots = []string{"SPDXRef-DOCUMENT"}
	}
	depths := map[string]int{}
	seen := map[string]bool{}
	var queue []string
	for _, r := range roots {
		seen[r] = true
		queue = append(queue, r)
	}
	if len(edges) == 0 {
		return nil, scopes
	}
	for depth := 1; len(queue) > 0; depth++ {
		var next []string
		for _, id := range queue {
			for _, child := range edges[id] {
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
	return depths, scopes
}

// spdxRoot is the synthetic graph root used when a document describes several
// packages (or none explicitly): the document itself.
const spdxRoot = "SPDXRef-DOCUMENT"

// spdxEdges flattens SPDX's relationships into parent → child dependency edges
// (every *_DEPENDENCY_OF is the reverse of DEPENDS_ON) and picks the graph root:
// the single described package, or the document when it describes several.
func spdxEdges(doc spdxDoc) (string, []Edge) {
	roots := append([]string(nil), doc.DocumentDescribes...)
	var edges []Edge
	for _, r := range doc.Relationships {
		switch strings.ToUpper(r.RelationshipType) {
		case "DEPENDS_ON":
			edges = append(edges, Edge{Parent: r.SpdxElementID, Child: r.RelatedSpdxElement})
		case "DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF", "DEV_DEPENDENCY_OF", "TEST_DEPENDENCY_OF",
			"BUILD_DEPENDENCY_OF", "OPTIONAL_DEPENDENCY_OF":
			edges = append(edges, Edge{Parent: r.RelatedSpdxElement, Child: r.SpdxElementID})
		case "DESCRIBES":
			if r.SpdxElementID == spdxRoot && !slices.Contains(roots, r.RelatedSpdxElement) {
				roots = append(roots, r.RelatedSpdxElement)
			}
		}
	}
	switch len(roots) {
	case 0:
		return "", edges
	case 1:
		return roots[0], edges
	}
	for _, r := range roots {
		edges = append(edges, Edge{Parent: spdxRoot, Child: r})
	}
	return spdxRoot, edges
}

func spdxPurl(refs []spdxExtRef) string {
	for _, ref := range refs {
		if strings.EqualFold(ref.ReferenceType, "purl") {
			return ref.ReferenceLocator
		}
	}
	return ""
}

// spdxCpe returns the package's CPE (SECURITY category), preferring the CPE
// 2.3 formatted string over a 2.2 URI.
func spdxCpe(refs []spdxExtRef) string {
	var cpe22 string
	for _, ref := range refs {
		switch strings.ToLower(ref.ReferenceType) {
		case "cpe23type":
			return ref.ReferenceLocator
		case "cpe22type":
			cpe22 = cmp.Or(cpe22, ref.ReferenceLocator)
		}
	}
	return cpe22
}

// spdxLicense prefers the concluded license, ignoring SPDX's NOASSERTION/NONE.
func spdxLicense(p spdxPackage) string {
	for _, l := range []string{p.LicenseConcluded, p.LicenseDeclared} {
		if l != "" && l != "NOASSERTION" && l != "NONE" {
			return l
		}
	}
	return ""
}

func spdxHashes(checksums []spdxChecksum) map[string]string {
	out := make(map[string]string, len(checksums))
	for _, c := range checksums {
		if c.Algorithm != "" {
			out[c.Algorithm] = c.ChecksumValue
		}
	}
	return out
}
