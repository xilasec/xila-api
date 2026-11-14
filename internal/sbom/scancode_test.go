package sbom

import (
	"os"
	"slices"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fixtures are ScanCode.io's own test data (github.com/aboutcode-org/scancode.io,
// Apache-2.0): scanpipe/tests/data/dependencies/resolved_dependencies_npm_inspect_packages.json
// and scanpipe/tests/data/asgiref/asgiref-3.3.0_scanpipe_output.json.

func parseScanCodeFixture(t *testing.T, name string) Document {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(raw) // through the content sniffing
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return doc
}

func scComponent(t *testing.T, doc Document, purl string) Component {
	t.Helper()
	i := slices.IndexFunc(doc.Components, func(c Component) bool { return c.Purl == purl })
	if i < 0 {
		t.Fatalf("no component %s", purl)
	}
	return doc.Components[i]
}

func TestScanCodeIOResolvedGraph(t *testing.T) {
	doc := parseScanCodeFixture(t, "scancodeio-npm-resolved.json")
	if doc.Format != "ScanCode.io" {
		t.Fatalf("format = %q", doc.Format)
	}
	if len(doc.Components) != 7 {
		t.Fatalf("components = %d, want the 7 packages", len(doc.Components))
	}
	// The project's own package.json is the root; athena-express is what it
	// asked for; csvtojson comes through athena-express; lodash through csvtojson.
	root := scComponent(t, doc, "pkg:npm/create-athena-partition@1.0.0")
	if doc.RootRef != root.BomRef {
		t.Fatalf("root = %q, want the project package %q", doc.RootRef, root.BomRef)
	}
	athena := scComponent(t, doc, "pkg:npm/athena-express@6.0.4")
	csv := scComponent(t, doc, "pkg:npm/csvtojson@2.0.10")
	lodash := scComponent(t, doc, "pkg:npm/lodash@4.17.21")
	for _, e := range []Edge{{root.BomRef, athena.BomRef}, {athena.BomRef, csv.BomRef}, {csv.BomRef, lodash.BomRef}} {
		if !slices.Contains(doc.Edges, e) {
			t.Errorf("missing edge %s → %s", e.Parent, e.Child)
		}
	}
	if len(doc.Edges) != 6 {
		t.Errorf("edges = %d, want 6 (one per resolved dependency)", len(doc.Edges))
	}
	if athena.Direct == nil || !*athena.Direct || *athena.Depth != 1 {
		t.Errorf("athena-express direct/depth = %v/%v, want direct at 1", athena.Direct, athena.Depth)
	}
	if lodash.Direct == nil || *lodash.Direct || *lodash.Depth != 3 {
		t.Errorf("lodash direct/depth = %v/%v, want transitive at 3", lodash.Direct, lodash.Depth)
	}
	if lodash.Scope != domain.DepScopeRuntime {
		t.Errorf("lodash scope = %q, want runtime", lodash.Scope)
	}
	if lodash.Hashes["SHA-1"] != "679591c564c3bffaae8454cf0b3df370c3d6911c" {
		t.Errorf("lodash hashes = %v", lodash.Hashes)
	}
	if root.License != "LicenseRef-scancode-unknown" {
		t.Errorf("root license = %q", root.License)
	}
}

func TestScanCodeIOLicensesAndDuplicates(t *testing.T) {
	doc := parseScanCodeFixture(t, "scancodeio-asgiref-3.3.0.json")
	// The wheel and its METADATA both report asgiref: one component.
	if len(doc.Components) != 1 {
		t.Fatalf("components = %d, want 1 (asgiref, deduplicated)", len(doc.Components))
	}
	c := doc.Components[0]
	if c.Name != "asgiref" || c.Version != "3.3.0" || c.License != "BSD-3-Clause" ||
		!slices.Equal(c.LicenseTerms, []string{"BSD-3-Clause"}) {
		t.Errorf("component = %s %s license %q terms %v", c.Name, c.Version, c.License, c.LicenseTerms)
	}
	// Its test extras (pytest, unpinned and unresolved) are declarations only.
	if len(doc.Edges) != 0 || doc.RootRef != "" || c.Depth != nil {
		t.Errorf("unexpected graph: root %q edges %v depth %v", doc.RootRef, doc.Edges, c.Depth)
	}
}
