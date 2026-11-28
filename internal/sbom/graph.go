package sbom

import "slices"

// Node is one vertex of a snapshot's dependency graph.
type Node struct {
	Ref string `json:"ref"`
	// Kind is "component" or "service" — what the document declares at Ref;
	// "" for a synthesized root and for missing refs.
	Kind        string  `json:"kind"`
	ComponentID *string `json:"component_id"` // nil for the root and for refs no component declares
	ServiceID   *string `json:"service_id"`   // set on service nodes
	Name        string  `json:"name"`
	Version     string  `json:"version"`
	Purl        string  `json:"purl"`
	Scope       string  `json:"scope"`
	Direct      *bool   `json:"direct"`
	Depth       *int    `json:"depth"`
	Root        bool    `json:"root"`
	// Missing: an edge points at a ref the document lists no component or
	// service for.
	Missing bool `json:"missing"`
	VulnState
}

// Graph is a snapshot's dependency graph with vulnerability state on every node.
type Graph struct {
	SbomID string `json:"sbom_id"`
	// Root is the subject's ref; "" when the document named none, in which case
	// the entry points are the nodes nothing depends on.
	Root  string `json:"root"`
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// unrefPrefix / unrefServicePrefix name components and services the document
// gave no node id, so they still appear (unconnected) in the graph.
const (
	unrefPrefix        = "component:"
	unrefServicePrefix = "service:"
)

// ComponentRef is a component's node id within its snapshot's dependency
// graph: its bom-ref, or — for a document that gave none — a synthetic id
// keyed by the component's own row id, so it still appears (unconnected) in
// the graph.
func ComponentRef(bomRef, id string) string {
	if bomRef != "" {
		return bomRef
	}
	return unrefPrefix + id
}

// BuildGraph assembles a snapshot's graph from its components, services and
// edges. The subject is usually not a listed component, so it is synthesized
// from the artifact name. Pure.
func BuildGraph(s Sbom, comps []ComponentHit, svcs []BomService, edges []Edge) Graph {
	g := Graph{SbomID: s.ID, Root: s.RootRef, Nodes: []Node{}, Edges: []Edge{}}
	index := map[string]int{}
	add := func(n Node) {
		if _, ok := index[n.Ref]; !ok {
			index[n.Ref] = len(g.Nodes)
			g.Nodes = append(g.Nodes, n)
		}
	}
	for _, c := range comps {
		if c.Kind == KindAIService {
			continue // the AI inventory row of a service: the service node is below
		}
		ref := ComponentRef(c.BomRef, c.ID)
		add(Node{
			Ref: ref, Kind: "component", ComponentID: &c.ID, Name: c.Name, Version: c.Version, Purl: c.Purl,
			Scope: string(c.Scope), Direct: c.Direct, Depth: c.Depth, Root: ref == s.RootRef,
			VulnState: c.VulnState,
		})
	}
	for _, sv := range svcs {
		ref := sv.BomRef
		if ref == "" {
			ref = unrefServicePrefix + sv.ID
		}
		add(Node{Ref: ref, Kind: "service", ServiceID: &sv.ID, Name: sv.Name, Version: sv.Version,
			Vulns: []string{}})
	}
	if s.RootRef != "" {
		if i, ok := index[s.RootRef]; ok {
			g.Nodes[i].Root = true
		} else {
			add(Node{Ref: s.RootRef, Name: s.Artifact, Version: s.Version, Root: true, Vulns: []string{}})
		}
	}
	for _, e := range edges {
		for _, ref := range []string{e.Parent, e.Child} {
			add(Node{Ref: ref, Name: ref, Missing: true, Vulns: []string{}})
		}
		g.Edges = append(g.Edges, e)
	}
	return g
}

// MaxPaths caps how many paths Paths returns; a package pulled in by many
// parents has combinatorially many routes, and the shortest few are what explain
// why it's there.
const MaxPaths = 20

// maxPathExpansions bounds the search itself on pathological graphs.
const maxPathExpansions = 50_000

// Paths returns up to limit shortest routes from an entry point (the root, or
// when there is none, any node nothing depends on) down to target, each as a
// list of refs starting at the entry point. Shortest first; cycles are not
// followed. Pure.
func (g Graph) Paths(target string, limit int) [][]string {
	parents := map[string][]string{}
	hasParent := map[string]bool{}
	for _, e := range g.Edges {
		parents[e.Child] = append(parents[e.Child], e.Parent)
		hasParent[e.Child] = true
	}
	for _, ps := range parents {
		slices.Sort(ps)
	}
	isEntry := func(ref string) bool {
		if g.Root != "" {
			return ref == g.Root
		}
		return !hasParent[ref]
	}

	// Breadth-first upward from the target over partial paths (target first):
	// every completed path is at least as short as the next one found.
	paths := [][]string{}
	queue := [][]string{{target}}
	for expanded := 0; len(queue) > 0 && len(paths) < limit && expanded < maxPathExpansions; expanded++ {
		p := queue[0]
		queue = queue[1:]
		head := p[len(p)-1]
		if isEntry(head) {
			out := slices.Clone(p)
			slices.Reverse(out)
			paths = append(paths, out)
			continue
		}
		for _, parent := range parents[head] {
			if slices.Contains(p, parent) {
				continue // a cycle
			}
			queue = append(queue, append(slices.Clone(p), parent))
		}
	}
	return paths
}
