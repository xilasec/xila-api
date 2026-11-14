package sbom

import (
	"net/url"
	"slices"
	"strings"
)

// Component kinds: what an inventory row is, for the AI inventory (ML-BOM).
// The CycloneDX type stays in Component.Type; Kind is the coarse class the
// AI inventory and policies (`component.kind`) filter on.
const (
	KindSoftware  = "software"   // every ordinary component
	KindModel     = "model"      // CycloneDX type machine-learning-model
	KindDataset   = "dataset"    // CycloneDX type data
	KindAIService = "ai-service" // a service that serves a model (see aiService)
)

// KindAI is the component filter for every AI kind (the AI inventory).
const KindAI = "ai"

// Kinds lists every component kind.
var Kinds = []string{KindSoftware, KindModel, KindDataset, KindAIService}

// IsAIKind reports whether kind is one of the AI inventory's kinds.
func IsAIKind(kind string) bool {
	return kind == KindModel || kind == KindDataset || kind == KindAIService
}

// componentKind maps a CycloneDX component type to its kind.
func componentKind(cdxType string) string {
	switch strings.ToLower(cdxType) {
	case "machine-learning-model":
		return KindModel
	case "data":
		return KindDataset
	}
	return KindSoftware
}

// MLFacts are the model-card essentials of an AI component (stored as the
// component's `ml` jsonb; nil for software): who made it, what it does, what
// it was trained on, what it derives from and where it lives. Unset fields are
// unknown.
type MLFacts struct {
	// Organizations: CycloneDX supplier.name, manufacturer.name (1.6) and the
	// publisher string; for an AI service, its provider.
	Supplier     string `json:"supplier,omitempty"`
	Manufacturer string `json:"manufacturer,omitempty"`
	Publisher    string `json:"publisher,omitempty"`
	Description  string `json:"description,omitempty"`

	// modelCard.modelParameters.
	Approach           string      `json:"approach,omitempty"` // approach.type: supervised, unsupervised…
	Task               string      `json:"task,omitempty"`
	ArchitectureFamily string      `json:"architecture_family,omitempty"`
	ModelArchitecture  string      `json:"model_architecture,omitempty"`
	Datasets           []MLDataset `json:"datasets,omitempty"`
	Inputs             []string    `json:"inputs,omitempty"`  // formats
	Outputs            []string    `json:"outputs,omitempty"` // formats

	// Data is a dataset component's own contents (CycloneDX component.data).
	Data []MLDataset `json:"data,omitempty"`
	// Ancestors are pedigree.ancestors: the base models it was derived from.
	Ancestors []MLAncestor `json:"ancestors,omitempty"`
	// ExternalRefs carry the model hub / dataset URLs (distribution, website…).
	ExternalRefs []ExternalRef `json:"external_references,omitempty"`
	// Endpoints of an AI service.
	Endpoints []string `json:"endpoints,omitempty"`
}

// MLDataset is one dataset a model card names — inline, or a reference (Ref)
// to a data component of the same BOM, whose name is then copied into Name —
// or one entry of a data component's contents.
type MLDataset struct {
	Ref            string `json:"ref,omitempty"`
	Type           string `json:"type,omitempty"`
	Name           string `json:"name,omitempty"`
	Classification string `json:"classification,omitempty"`
	URL            string `json:"url,omitempty"`
	Description    string `json:"description,omitempty"`
}

// MLAncestor is one pedigree ancestor.
type MLAncestor struct {
	Type    string `json:"type,omitempty"`
	Group   string `json:"group,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Purl    string `json:"purl,omitempty"`
}

// Organizations are the facts' non-empty supplier, manufacturer and publisher.
func (m *MLFacts) Organizations() []string {
	if m == nil {
		return nil
	}
	var out []string
	for _, o := range []string{m.Supplier, m.Manufacturer, m.Publisher} {
		if o = strings.TrimSpace(o); o != "" && !slices.Contains(out, o) {
			out = append(out, o)
		}
	}
	return out
}

// DatasetNames are the names of the datasets a model card lists.
func (m *MLFacts) DatasetNames() []string {
	if m == nil {
		return nil
	}
	var out []string
	for _, d := range m.Datasets {
		if n := strings.TrimSpace(d.Name); n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// --- CycloneDX parsing ---

type cycloneOrg struct {
	Name string   `json:"name"`
	URL  []string `json:"url"`
}

type cycloneModelCard struct {
	ModelParameters struct {
		Approach struct {
			Type string `json:"type"`
		} `json:"approach"`
		Task               string               `json:"task"`
		ArchitectureFamily string               `json:"architectureFamily"`
		ModelArchitecture  string               `json:"modelArchitecture"`
		Datasets           []cycloneDataset     `json:"datasets"`
		Inputs             []cycloneInputOutput `json:"inputs"`
		Outputs            []cycloneInputOutput `json:"outputs"`
	} `json:"modelParameters"`
}

type cycloneInputOutput struct {
	Format string `json:"format"`
}

// cycloneDataset is CycloneDX's componentData — or, in a model card, a
// reference to a data component ({"ref": …}).
type cycloneDataset struct {
	Ref            string `json:"ref"`
	Type           string `json:"type"`
	Name           string `json:"name"`
	Classification string `json:"classification"`
	Description    string `json:"description"`
	Contents       *struct {
		URL string `json:"url"`
	} `json:"contents"`
}

type cyclonePedigree struct {
	Ancestors []MLAncestor `json:"ancestors"`
}

func (d cycloneDataset) facts() MLDataset {
	out := MLDataset{Ref: d.Ref, Type: d.Type, Name: d.Name, Classification: d.Classification, Description: d.Description}
	if d.Contents != nil {
		out.URL = d.Contents.URL
	}
	return out
}

// mlFacts extracts an AI component's model-card essentials; refs resolves
// a bom-ref to the name of the component that declares it.
func mlFacts(c cycloneComponent, refs map[string]string) *MLFacts {
	m := &MLFacts{Publisher: c.Publisher, Description: c.Description,
		ExternalRefs: slices.DeleteFunc(slices.Clone(c.ExternalReferences), func(r ExternalRef) bool { return r.URL == "" })}
	if c.Supplier != nil {
		m.Supplier = c.Supplier.Name
	}
	if c.Manufacturer != nil {
		m.Manufacturer = c.Manufacturer.Name
	}
	if c.Pedigree != nil {
		for _, a := range c.Pedigree.Ancestors {
			if a.Name != "" {
				m.Ancestors = append(m.Ancestors, a)
			}
		}
	}
	for _, d := range c.Data {
		m.Data = append(m.Data, d.facts())
	}
	if mc := c.ModelCard; mc != nil {
		p := mc.ModelParameters
		m.Approach, m.Task = p.Approach.Type, p.Task
		m.ArchitectureFamily, m.ModelArchitecture = p.ArchitectureFamily, p.ModelArchitecture
		for _, d := range p.Datasets {
			ds := d.facts()
			if ds.Ref != "" && ds.Name == "" {
				ds.Name = refs[ds.Ref]
			}
			m.Datasets = append(m.Datasets, ds)
		}
		for _, in := range p.Inputs {
			if in.Format != "" {
				m.Inputs = append(m.Inputs, in.Format)
			}
		}
		for _, out := range p.Outputs {
			if out.Format != "" {
				m.Outputs = append(m.Outputs, out.Format)
			}
		}
	}
	if len(m.ExternalRefs) == 0 {
		m.ExternalRefs = nil
	}
	return m
}

// aiAPIHosts are the hosted inference APIs of the major model providers; a
// service whose endpoint is on one of them is an AI service. A leading "*."
// matches any subdomain, "*" inside a label any run within it.
var aiAPIHosts = []string{
	"api.openai.com", "*.openai.azure.com", "api.anthropic.com",
	"generativelanguage.googleapis.com", "aiplatform.googleapis.com", "*-aiplatform.googleapis.com",
	"bedrock-runtime.*.amazonaws.com", "bedrock.*.amazonaws.com",
	"api.mistral.ai", "api.cohere.com", "api.cohere.ai", "api-inference.huggingface.co",
	"router.huggingface.co", "*.endpoints.huggingface.cloud", "api.groq.com", "api.together.xyz",
	"api.deepseek.com", "api.x.ai", "api.perplexity.ai", "api.replicate.com",
}

// isAIEndpoint reports whether endpoint's host is a known model provider API.
func isAIEndpoint(endpoint string) bool {
	u, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || u.Hostname() == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	for _, pattern := range aiAPIHosts {
		if hostMatches(pattern, host) {
			return true
		}
	}
	return false
}

// hostMatches matches host against pattern label by label; "*" in a pattern
// label matches any run of characters within one label, and a leading "*."
// any (non-empty) run of subdomains.
func hostMatches(pattern, host string) bool {
	if rest, ok := strings.CutPrefix(pattern, "*."); ok {
		return strings.HasSuffix(host, "."+rest)
	}
	pl, hl := strings.Split(pattern, "."), strings.Split(host, ".")
	if len(pl) != len(hl) {
		return false
	}
	for i := range pl {
		pre, suf, wild := strings.Cut(pl[i], "*")
		if !wild {
			if pl[i] != hl[i] {
				return false
			}
			continue
		}
		if len(hl[i]) < len(pre)+len(suf) || !strings.HasPrefix(hl[i], pre) || !strings.HasSuffix(hl[i], suf) {
			return false
		}
	}
	return true
}

// aiServices returns the AI inventory row of every service that serves a
// model: one linked to a model component of the BOM by a dependency edge
// (either way), or one calling a known model provider's API. The service
// itself stays in the snapshot's services; the row (kind ai-service, same
// bom-ref) is what puts it in the component inventory, search, diff and
// policies. Export skips these rows — the service is exported as a service.
func aiServices(comps []Component, svcs []BomService, edges []Edge) []Component {
	models := map[string]bool{}
	for _, c := range comps {
		if c.Kind == KindModel && c.BomRef != "" {
			models[c.BomRef] = true
		}
	}
	linked := map[string]bool{}
	for _, e := range edges {
		if models[e.Child] {
			linked[e.Parent] = true
		}
		if models[e.Parent] {
			linked[e.Child] = true
		}
	}
	var out []Component
	for _, s := range svcs {
		if !(s.BomRef != "" && linked[s.BomRef]) && !slices.ContainsFunc(s.Endpoints, isAIEndpoint) {
			continue
		}
		m := &MLFacts{Supplier: s.Provider, Description: s.Description, Endpoints: s.Endpoints}
		if len(s.ExternalRefs) > 0 {
			m.ExternalRefs = s.ExternalRefs
		}
		if len(m.Endpoints) == 0 {
			m.Endpoints = nil
		}
		out = append(out, Component{BomRef: s.BomRef, Type: "service", Kind: KindAIService,
			Group: s.Group, Name: s.Name, Version: s.Version, License: s.License,
			LicenseTerms: licenseTermsOf(s.License), Hashes: map[string]string{}, ML: m})
	}
	return out
}

// licenseTermsOf splits a flattened license string back into its terms.
func licenseTermsOf(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ", ") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
