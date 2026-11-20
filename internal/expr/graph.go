package expr

import (
	"regexp"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
)

// GraphNode is one vertex of a dependency graph: an opaque id unique within
// the graph, its exact-match subject (Base — e.g. a base purl; "" never
// matches an exact pattern) and its regex subject (Purl — the full purl; ""
// never matches a `re:` pattern).
type GraphNode struct {
	ID, Base, Purl string
}

// Graph is a directed "parent depends on child" dependency graph — one SBOM
// snapshot's graph, built once per evaluation run (see GraphFrame) and reused
// for every component the depends_on family of CEL functions evaluates
// against. The zero Graph has no nodes or edges.
type Graph struct {
	root     string
	nodes    map[string]GraphNode
	children map[string][]string
	parents  map[string][]string
}

// NewGraph starts an empty graph. root is the entry point ("" = none: every
// node with no parent is an entry point — the same fallback rule
// internal/sbom's Graph.Paths uses when a document names no subject).
func NewGraph(root string) *Graph {
	return &Graph{root: root, nodes: map[string]GraphNode{}, children: map[string][]string{}, parents: map[string][]string{}}
}

// AddNode registers n, first write wins.
func (g *Graph) AddNode(n GraphNode) {
	if _, ok := g.nodes[n.ID]; !ok {
		g.nodes[n.ID] = n
	}
}

// AddEdge records "parent depends on child". Either end may be a ref AddNode
// was never called for (a document's edge to a node it didn't declare); such
// a node simply matches no pattern.
func (g *Graph) AddEdge(parent, child string) {
	g.children[parent] = append(g.children[parent], child)
	g.parents[child] = append(g.parents[child], parent)
}

func (g *Graph) isEntry(ref string) bool {
	if g.root != "" {
		return ref == g.root
	}
	return len(g.parents[ref]) == 0
}

// matches reports whether pattern selects node ref: an exact match against
// its base subject, or — when pattern is "re:<regex>" — a regex match against
// its full subject. An unknown ref or a pattern with no subject to compare
// against never matches.
func (g *Graph) matches(ref, pattern string) bool {
	n, ok := g.nodes[ref]
	if !ok {
		return false
	}
	if rx, isRegex := strings.CutPrefix(pattern, "re:"); isRegex {
		re, err := regexp.Compile(rx)
		return err == nil && n.Purl != "" && re.MatchString(n.Purl)
	}
	return n.Base != "" && n.Base == pattern
}

// reaches reports whether, starting at self, following next (Children for
// dependencies, Parents for dependents) reaches a node matching pattern.
func reaches(next map[string][]string, matches func(string) bool, self string) bool {
	if self == "" {
		return false
	}
	seen := map[string]bool{self: true}
	queue := []string{self}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, n := range next[cur] {
			if matches(n) {
				return true
			}
			if !seen[n] {
				seen[n] = true
				queue = append(queue, n)
			}
		}
	}
	return false
}

// dependsOn reports whether self reaches — by any number of hops — a node
// matching pattern among its dependencies.
func (g *Graph) dependsOn(self, pattern string) bool {
	return reaches(g.children, func(n string) bool { return g.matches(n, pattern) }, self)
}

// isDependencyOf reports whether self reaches — by any number of hops — a
// node matching pattern among its dependents (the reverse graph): some
// package matching pattern depends, directly or transitively, on self.
func (g *Graph) isDependencyOf(self, pattern string) bool {
	return reaches(g.parents, func(n string) bool { return g.matches(n, pattern) }, self)
}

// isDirectDependencyOf reports whether some immediate parent of self matches
// pattern.
func (g *Graph) isDirectDependencyOf(self, pattern string) bool {
	for _, p := range g.parents[self] {
		if g.matches(p, pattern) {
			return true
		}
	}
	return false
}

// isExclusiveDependencyOf reports whether every path from the graph's root
// (or, without one, its entry points) to self passes through a node matching
// pattern: self is reachable from the root, but never without going through
// one. A self with no path to the root at all — matches or not — is not
// exclusive to anything.
func (g *Graph) isExclusiveDependencyOf(self, pattern string) bool {
	if self == "" {
		return false
	}
	if !g.reachableFrom(self, func(string) bool { return false }) {
		return false
	}
	return !g.reachableFrom(self, func(ref string) bool { return g.matches(ref, pattern) })
}

// reachableFrom reports whether self is reached by a breadth-first walk from
// the graph's entry points that does not expand past a node for which stop is
// true (the node itself still counts as reached).
func (g *Graph) reachableFrom(self string, stop func(ref string) bool) bool {
	visited := map[string]bool{}
	var queue []string
	for n := range g.allRefs() {
		if g.isEntry(n) {
			queue = append(queue, n)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if visited[cur] {
			continue
		}
		visited[cur] = true
		if cur == self {
			return true
		}
		if stop(cur) {
			continue
		}
		queue = append(queue, g.children[cur]...)
	}
	return false
}

// allRefs is every ref the graph mentions, as a node or as an edge endpoint.
func (g *Graph) allRefs() map[string]bool {
	out := make(map[string]bool, len(g.nodes))
	for ref := range g.nodes {
		out[ref] = true
	}
	for p, cs := range g.children {
		out[p] = true
		for _, c := range cs {
			out[c] = true
		}
	}
	for c, ps := range g.parents {
		out[c] = true
		for _, p := range ps {
			out[p] = true
		}
	}
	return out
}

// GraphFrame is the mutable state the depends_on family of CEL functions
// reads: which graph, and which node is "this" component. Expression
// evaluation is sequential — one Program.Match call at a time — so a caller
// safely updates Set before each component without recompiling the
// expressions that were bound to this frame at Compile time.
type GraphFrame struct {
	graph *Graph
	self  string
}

// NewGraphFrame returns an empty frame: with no graph set, every graph
// function is unknown and never matches — save-time validation, and a
// component whose snapshot carries no dependency graph, both use this.
func NewGraphFrame() *GraphFrame { return &GraphFrame{} }

// Set points frame at graph (nil clears it) and self, the id of the node
// about to be evaluated within it.
func (f *GraphFrame) Set(graph *Graph, self string) {
	f.graph, f.self = graph, self
}

// call adapts fn (a Graph method bound to frame's current graph/self) into a
// CEL unary function binding over the pattern argument. A malformed `re:`
// pattern is a CEL error — caught at save time by the dry run — not a quiet
// false; with no graph at all (frame.graph nil) the fact is simply unknown.
func (f *GraphFrame) call(fn func(g *Graph, self, pattern string) bool) func(ref.Val) ref.Val {
	return func(arg ref.Val) ref.Val {
		pattern, ok := arg.Value().(string)
		if !ok {
			return types.NewErr("pattern must be a string")
		}
		if rx, isRegex := strings.CutPrefix(pattern, "re:"); isRegex {
			if _, err := regexp.Compile(rx); err != nil {
				return types.NewErr("invalid regex pattern %q: %v", rx, err)
			}
		}
		if f.graph == nil {
			return types.False
		}
		return types.Bool(fn(f.graph, f.self, pattern))
	}
}

// GraphFuncs declares the depends_on family of CEL functions bound to frame:
//
//   - depends_on(pattern): self depends, directly or transitively, on a
//     component matching pattern.
//   - is_dependency_of(pattern): a component matching pattern depends,
//     directly or transitively, on self.
//   - is_direct_dependency_of(pattern): a component matching pattern directly
//     depends on self.
//   - is_exclusive_dependency_of(pattern): every path from the root to self
//     goes through a component matching pattern.
//
// pattern is an exact purl without version, or "re:<regex>" matched against
// the full purl. Include the result in a Schema's Extra to make the
// functions available to Compile/Load.
func GraphFuncs(frame *GraphFrame) []cel.EnvOption {
	mk := func(name string, fn func(*Graph, string, string) bool) cel.EnvOption {
		return cel.Function(name,
			cel.Overload(name+"_string", []*cel.Type{cel.StringType}, cel.BoolType,
				cel.UnaryBinding(frame.call(fn))))
	}
	return []cel.EnvOption{
		mk("depends_on", (*Graph).dependsOn),
		mk("is_dependency_of", (*Graph).isDependencyOf),
		mk("is_direct_dependency_of", (*Graph).isDirectDependencyOf),
		mk("is_exclusive_dependency_of", (*Graph).isExclusiveDependencyOf),
	}
}
