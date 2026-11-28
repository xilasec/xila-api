package sbom

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// cycloneDXNamespacePrefix is every CycloneDX XML schema's namespace prefix;
// the spec version is the suffix (http://cyclonedx.org/schema/bom/1.5 → "1.5").
const cycloneDXNamespacePrefix = "http://cyclonedx.org/schema/bom/"

// maxSbomXMLElements and maxSbomXMLDepth bound a CycloneDX XML upload before
// it is unmarshaled, independent of maxSbomBytes: a small, deeply-nested or
// highly-repetitive document could otherwise cost far more to decode than its
// byte size suggests. Go's encoding/xml never resolves a DTD or external
// entity at all (no billion-laughs, no XXE) — these are defense-in-depth on
// top of that, the same pattern internal/scanner's custom XML parser uses.
const (
	maxSbomXMLElements = 2_000_000
	maxSbomXMLDepth    = 200
)

// scanRootXML walks raw's tokens once, bounding its element count and nesting
// depth, and returns the root element's namespace and local name (without
// fully unmarshaling it) — used to identify the document before an
// xml.Unmarshal that trusts its shape.
func scanRootXML(raw []byte) (namespace, local string, err error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var depth, count int
	for {
		tok, terr := dec.Token()
		if terr != nil {
			if errors.Is(terr, io.EOF) {
				break
			}
			return "", "", fmt.Errorf("decode cyclonedx xml: %w", terr)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			count++
			depth++
			if local == "" {
				namespace, local = t.Name.Space, t.Name.Local
			}
			if count > maxSbomXMLElements {
				return "", "", fmt.Errorf("cyclonedx xml document has too many elements (max %d)", maxSbomXMLElements)
			}
			if depth > maxSbomXMLDepth {
				return "", "", fmt.Errorf("cyclonedx xml document is nested too deeply (max %d)", maxSbomXMLDepth)
			}
		case xml.EndElement:
			depth--
		}
	}
	if local == "" {
		return "", "", errors.New("cyclonedx xml document has no root element")
	}
	return namespace, local, nil
}

// --- CycloneDX XML schema (the subset we consume) ---

type cycloneXMLHash struct {
	Alg     string `xml:"alg,attr"`
	Content string `xml:",chardata"`
}

type cycloneXMLLicenseEntry struct {
	ID              string `xml:"id"`
	Name            string `xml:"name"`
	Acknowledgement string `xml:"acknowledgement,attr"`
}

// cycloneXMLLicenses is a licenseChoice: a list of licenses, or a single SPDX
// expression — CycloneDX XML keeps both as siblings under <licenses>, unlike
// JSON's array of {license}/{expression} entries.
type cycloneXMLLicenses struct {
	License         []cycloneXMLLicenseEntry `xml:"license"`
	Expression      string                   `xml:"expression"`
	Acknowledgement string                   `xml:"acknowledgement,attr"`
}

type cycloneXMLProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type cycloneXMLOccurrence struct {
	Location string `xml:"location"`
}

type cycloneXMLEvidence struct {
	Occurrences []cycloneXMLOccurrence `xml:"occurrences>occurrence"`
}

// cycloneXMLComponent mirrors cycloneComponent's JSON shape in XML idiom.
// Components may nest (a container image's layers, a library's bundled
// sub-components): Components flattens them into the document's flat list.
type cycloneXMLComponent struct {
	BomRef      string                `xml:"bom-ref,attr"`
	Type        string                `xml:"type,attr"`
	Scope       string                `xml:"scope"`
	Group       string                `xml:"group"`
	Name        string                `xml:"name"`
	Version     string                `xml:"version"`
	Purl        string                `xml:"purl"`
	Cpe         string                `xml:"cpe"`
	Publisher   string                `xml:"publisher"`
	Description string                `xml:"description"`
	Licenses    cycloneXMLLicenses    `xml:"licenses"`
	Hashes      []cycloneXMLHash      `xml:"hashes>hash"`
	Evidence    cycloneXMLEvidence    `xml:"evidence"`
	Properties  []cycloneXMLProperty  `xml:"properties>property"`
	Components  []cycloneXMLComponent `xml:"components>component"`
}

// cycloneXMLDependency is one <dependency ref="..."> node; CycloneDX XML
// nests a ref's dependencies as child <dependency> elements rather than
// JSON's flat dependsOn array, and the same ref may recur at any depth.
type cycloneXMLDependency struct {
	Ref          string                 `xml:"ref,attr"`
	Dependencies []cycloneXMLDependency `xml:"dependency"`
}

type cycloneXMLServiceData struct {
	Flow           string `xml:"flow,attr"`
	Classification string `xml:",chardata"`
}

type cycloneXMLServiceProvider struct {
	Name string   `xml:"name"`
	URL  []string `xml:"url>url"`
}

type cycloneXMLService struct {
	BomRef        string                     `xml:"bom-ref,attr"`
	Provider      *cycloneXMLServiceProvider `xml:"provider"`
	Group         string                     `xml:"group"`
	Name          string                     `xml:"name"`
	Version       string                     `xml:"version"`
	Description   string                     `xml:"description"`
	Endpoints     []string                   `xml:"endpoints>endpoint"`
	Authenticated *bool                      `xml:"authenticated"`
	TrustBoundary *bool                      `xml:"x-trust-boundary"`
	TrustZone     string                     `xml:"trustZone"`
	Data          []cycloneXMLServiceData    `xml:"data>classification"`
	Licenses      cycloneXMLLicenses         `xml:"licenses"`
	Properties    []cycloneXMLProperty       `xml:"properties>property"`
	Services      []cycloneXMLService        `xml:"services>service"`
}

type cycloneXMLDoc struct {
	XMLName      xml.Name `xml:"bom"`
	SerialNumber string   `xml:"serialNumber,attr"`
	Metadata     struct {
		Component cycloneXMLComponent `xml:"component"`
	} `xml:"metadata"`
	Components   []cycloneXMLComponent  `xml:"components>component"`
	Services     []cycloneXMLService    `xml:"services>service"`
	Dependencies []cycloneXMLDependency `xml:"dependencies>dependency"`
}

// parseCycloneDXXML decodes a CycloneDX XML BOM (spec 1.2 through 1.6/1.7,
// namespace http://cyclonedx.org/schema/bom/1.x) into the same Document the
// JSON parser returns, by converting the decoded XML tree into a cycloneDoc
// and running it through the one shared buildCycloneDocument walk.
func parseCycloneDXXML(raw []byte) (Document, error) {
	namespace, local, err := scanRootXML(raw)
	if err != nil {
		return Document{}, err
	}
	if local != "bom" || !strings.HasPrefix(namespace, cycloneDXNamespacePrefix) {
		return Document{}, fmt.Errorf("not a CycloneDX XML document (root element %q, namespace %q)", local, namespace)
	}
	specVersion := strings.TrimPrefix(namespace, cycloneDXNamespacePrefix)

	var x cycloneXMLDoc
	if err := xml.Unmarshal(raw, &x); err != nil {
		return Document{}, fmt.Errorf("decode cyclonedx xml: %w", err)
	}

	doc := cycloneDoc{
		BomFormat:    "CycloneDX",
		SpecVersion:  specVersion,
		SerialNumber: x.SerialNumber,
		Components:   flattenXMLComponents(x.Components),
		Services:     convertXMLServices(x.Services),
		Dependencies: convertXMLDependencies(x.Dependencies),
	}
	doc.Metadata.Component = convertXMLComponent(x.Metadata.Component)

	out, err := buildCycloneDocument(doc)
	if err != nil {
		return Document{}, err
	}
	out.XML = true
	return out, nil
}

// flattenXMLComponents walks (possibly nested) XML components depth-first,
// so a container image's layers or a library's bundled sub-components land
// in the document's flat Components list like the JSON parser's.
func flattenXMLComponents(comps []cycloneXMLComponent) []cycloneComponent {
	var out []cycloneComponent
	var walk func([]cycloneXMLComponent)
	walk = func(cs []cycloneXMLComponent) {
		for _, c := range cs {
			out = append(out, convertXMLComponent(c))
			if len(c.Components) > 0 {
				walk(c.Components)
			}
		}
	}
	walk(comps)
	return out
}

// XML text content keeps the whitespace a pretty-printed document puts around
// it (JSON values never carry it), so every scalar is trimmed on the way in.
func convertXMLComponent(c cycloneXMLComponent) cycloneComponent {
	tr := strings.TrimSpace
	out := cycloneComponent{
		BomRef:      tr(c.BomRef),
		Scope:       tr(c.Scope),
		Type:        tr(c.Type),
		Group:       tr(c.Group),
		Name:        tr(c.Name),
		Version:     tr(c.Version),
		Purl:        tr(c.Purl),
		Cpe:         tr(c.Cpe),
		Publisher:   tr(c.Publisher),
		Description: tr(c.Description),
		Licenses:    convertXMLLicenses(c.Licenses),
	}
	for _, h := range c.Hashes {
		out.Hashes = append(out.Hashes, cycloneHash{Alg: h.Alg, Content: strings.TrimSpace(h.Content)})
	}
	for _, occ := range c.Evidence.Occurrences {
		out.Evidence.Occurrences = append(out.Evidence.Occurrences, cycloneOccurrence{Location: strings.TrimSpace(occ.Location)})
	}
	for _, p := range c.Properties {
		out.Properties = append(out.Properties, cycloneProperty{Name: strings.TrimSpace(p.Name), Value: strings.TrimSpace(p.Value)})
	}
	return out
}

func convertXMLLicenses(l cycloneXMLLicenses) []cycloneLicense {
	var out []cycloneLicense
	for _, e := range l.License {
		var lic cycloneLicense
		lic.License.ID = strings.TrimSpace(e.ID)
		lic.License.Name = strings.TrimSpace(e.Name)
		lic.License.Acknowledgement = strings.TrimSpace(e.Acknowledgement)
		out = append(out, lic)
	}
	if expr := strings.TrimSpace(l.Expression); expr != "" {
		out = append(out, cycloneLicense{Expression: expr, Acknowledgement: strings.TrimSpace(l.Acknowledgement)})
	}
	return out
}

// convertXMLDependencies flattens CycloneDX XML's recursively-nested
// <dependency> elements into JSON's flat ref→dependsOn list: a ref's direct
// children are its dependsOn, and every ref seen (at any depth) gets its own
// entry, so a ref that recurs lower in the tree still contributes its edges,
// once each.
func convertXMLDependencies(deps []cycloneXMLDependency) []cycloneDependency {
	byRef := map[string][]string{}
	edge := map[[2]string]bool{}
	var order []string
	seen := map[string]bool{}
	var walk func(d cycloneXMLDependency)
	walk = func(d cycloneXMLDependency) {
		ref := strings.TrimSpace(d.Ref)
		if ref == "" {
			return
		}
		if !seen[ref] {
			seen[ref] = true
			order = append(order, ref)
		}
		for _, c := range d.Dependencies {
			child := strings.TrimSpace(c.Ref)
			if child != "" && !edge[[2]string{ref, child}] {
				edge[[2]string{ref, child}] = true
				byRef[ref] = append(byRef[ref], child)
			}
			walk(c)
		}
	}
	for _, d := range deps {
		walk(d)
	}
	out := make([]cycloneDependency, 0, len(order))
	for _, ref := range order {
		out = append(out, cycloneDependency{Ref: ref, DependsOn: byRef[ref]})
	}
	return out
}

func convertXMLServices(svcs []cycloneXMLService) []cycloneService {
	out := make([]cycloneService, 0, len(svcs))
	for _, s := range svcs {
		out = append(out, convertXMLService(s))
	}
	return out
}

func convertXMLService(s cycloneXMLService) cycloneService {
	tr := strings.TrimSpace
	out := cycloneService{
		BomRef:        tr(s.BomRef),
		Group:         tr(s.Group),
		Name:          tr(s.Name),
		Version:       tr(s.Version),
		Description:   tr(s.Description),
		Endpoints:     trimAll(s.Endpoints),
		Authenticated: s.Authenticated,
		TrustBoundary: s.TrustBoundary,
		TrustZone:     tr(s.TrustZone),
		Licenses:      convertXMLLicenses(s.Licenses),
	}
	if s.Provider != nil {
		out.Provider = &cycloneServiceProvider{Name: tr(s.Provider.Name), URL: trimAll(s.Provider.URL)}
	}
	for _, d := range s.Data {
		out.Data = append(out.Data, cycloneServiceData{Flow: tr(d.Flow), Classification: tr(d.Classification)})
	}
	for _, p := range s.Properties {
		out.Properties = append(out.Properties, Property{Name: tr(p.Name), Value: tr(p.Value)})
	}
	for _, c := range s.Services {
		out.Services = append(out.Services, convertXMLService(c))
	}
	return out
}

// trimAll trims each value and drops the ones left empty.
func trimAll(vs []string) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
