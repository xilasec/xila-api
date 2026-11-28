package expr

import "testing"

// chain: root -> a -> b -> c
//
//	-> d -> c   (c has two parents: b and d)
func testGraph() *Graph {
	g := NewGraph("root")
	g.AddNode(GraphNode{ID: "root", Base: "pkg:npm/app", Purl: "pkg:npm/app@1.0.0"})
	g.AddNode(GraphNode{ID: "a", Base: "pkg:npm/a", Purl: "pkg:npm/a@1.0.0"})
	g.AddNode(GraphNode{ID: "b", Base: "pkg:npm/b", Purl: "pkg:npm/b@1.0.0"})
	g.AddNode(GraphNode{ID: "c", Base: "pkg:npm/c", Purl: "pkg:npm/c@1.0.0"})
	g.AddNode(GraphNode{ID: "d", Base: "pkg:npm/d", Purl: "pkg:npm/d@1.0.0"})
	g.AddEdge("root", "a")
	g.AddEdge("a", "b")
	g.AddEdge("b", "c")
	g.AddEdge("root", "d")
	g.AddEdge("d", "c")
	return g
}

func TestGraphDependsOn(t *testing.T) {
	g := testGraph()
	if !g.dependsOn("a", "pkg:npm/b") {
		t.Error("a should depend on b")
	}
	if !g.dependsOn("a", "pkg:npm/c") {
		t.Error("a should transitively depend on c")
	}
	if g.dependsOn("b", "pkg:npm/a") {
		t.Error("b should not depend on a")
	}
	if !g.dependsOn("root", "re:^pkg:npm/[ab]@") {
		t.Error("root should match a regex pattern on one of its dependencies")
	}
	if g.dependsOn("c", "pkg:npm/a") {
		t.Error("c has no dependencies, so it depends on nothing")
	}
}

func TestGraphIsDependencyOf(t *testing.T) {
	g := testGraph()
	if !g.isDependencyOf("c", "pkg:npm/b") {
		t.Error("c should be a dependency of b")
	}
	if !g.isDependencyOf("c", "pkg:npm/app") {
		t.Error("c should transitively be a dependency of root")
	}
	if g.isDependencyOf("root", "pkg:npm/a") {
		t.Error("root is not a dependency of anything")
	}
}

func TestGraphIsDirectDependencyOf(t *testing.T) {
	g := testGraph()
	if !g.isDirectDependencyOf("b", "pkg:npm/a") {
		t.Error("b should be a direct dependency of a")
	}
	if g.isDirectDependencyOf("c", "pkg:npm/root") {
		t.Error("c is not a direct dependency of root (two hops via b or d)")
	}
	if !g.isDirectDependencyOf("c", "pkg:npm/b") || !g.isDirectDependencyOf("c", "pkg:npm/d") {
		t.Error("c should be a direct dependency of both its parents")
	}
}

func TestGraphIsExclusiveDependencyOf(t *testing.T) {
	g := testGraph()
	// b is reachable from root only via a: every path to b goes through a.
	if !g.isExclusiveDependencyOf("b", "pkg:npm/a") {
		t.Error("b should be an exclusive dependency of a")
	}
	// c is reachable via both a and d, so it is not exclusive to either.
	if g.isExclusiveDependencyOf("c", "pkg:npm/a") {
		t.Error("c should not be an exclusive dependency of a (also reachable via d)")
	}
	if g.isExclusiveDependencyOf("c", "pkg:npm/d") {
		t.Error("c should not be an exclusive dependency of d (also reachable via a)")
	}
	// a is reachable directly from root, so it has no exclusive gate.
	if g.isExclusiveDependencyOf("a", "pkg:npm/root") {
		t.Error("a is a direct child of root; root doesn't gate anything further")
	}
	// A node with no path to the root at all is not exclusive to anything.
	g.AddNode(GraphNode{ID: "orphan", Base: "pkg:npm/orphan", Purl: "pkg:npm/orphan@1.0.0"})
	if g.isExclusiveDependencyOf("orphan", "pkg:npm/a") {
		t.Error("an unreachable node should not be an exclusive dependency of anything")
	}
}

func TestGraphFrameEmptyIsUnknown(t *testing.T) {
	frame := NewGraphFrame()
	prg, err := Compile(Schema{Vars: []string{"x"}, Sample: map[string]any{"x": 1}, Frame: frame},
		`depends_on("pkg:npm/a")`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if prg.Match(t.Context(), map[string]any{"x": 1}) {
		t.Error("an empty frame should never match")
	}
}

func TestGraphFrameSetBetweenEvaluations(t *testing.T) {
	frame := NewGraphFrame()
	schema := Schema{Vars: []string{"x"}, Sample: map[string]any{"x": 1}, Frame: frame}
	prg, err := Compile(schema, `depends_on("pkg:npm/c")`)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	g := testGraph()
	frame.Set(g, "a")
	if !prg.Match(t.Context(), map[string]any{"x": 1}) {
		t.Error("a should depend on c once the frame points at a")
	}
	frame.Set(g, "c")
	if prg.Match(t.Context(), map[string]any{"x": 1}) {
		t.Error("c should not depend on c once the frame points at c")
	}
}

func TestGraphFrameInvalidRegexIsCompileError(t *testing.T) {
	frame := NewGraphFrame()
	schema := Schema{Vars: []string{"x"}, Sample: map[string]any{"x": 1}, Frame: frame}
	if _, err := Compile(schema, `depends_on("re:[")`); err == nil {
		t.Error("expected an invalid regex pattern to fail the dry run")
	}
}
