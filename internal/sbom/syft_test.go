package sbom

import (
	"os"
	"strings"
	"testing"
)

// Fixture: real `syft scan dir:. -o json` output (Apache-2.0, syft v1.42.3)
// against a two-package npm project (syft-demo depending on leftpad),
// trimmed to artifacts/artifactRelationships/source/descriptor/schema — the
// fields parseSyft reads. Not hand-invented: generated with the real tool
// and only stripped of the unused cataloger-configuration block.
func parseSyftFixture(t *testing.T, name string) Document {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := parseSyft(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("parseSyft: %v", err)
	}
	return doc
}

func TestParseSyft(t *testing.T) {
	doc := parseSyftFixture(t, "syft_npm_demo.json")

	if doc.Format != "Syft" || doc.SpecVersion != "16.1.3" {
		t.Errorf("metadata = %+v", doc)
	}
	if len(doc.Components) != 2 {
		t.Fatalf("got %d components, want 2", len(doc.Components))
	}

	var leftpad, demo Component
	for _, c := range doc.Components {
		switch c.Name {
		case "leftpad":
			leftpad = c
		case "syft-demo":
			demo = c
		}
	}
	if leftpad.Version != "1.0.0" || leftpad.Purl != "pkg:npm/leftpad@1.0.0" || leftpad.Type != "npm" {
		t.Errorf("leftpad = %+v", leftpad)
	}
	if leftpad.License != "MIT" {
		t.Errorf("leftpad license = %q, want MIT (from spdxExpression)", leftpad.License)
	}
	if leftpad.FilePath != "/package-lock.json" {
		t.Errorf("leftpad file_path = %q", leftpad.FilePath)
	}
	if demo.Purl != "pkg:npm/syft-demo@1.0.0" {
		t.Errorf("syft-demo = %+v", demo)
	}

	// syft-demo depends on leftpad ("dependency-of" is leftpad -> syft-demo in
	// Syft's own parent/child orientation; Edge must come out the other way,
	// Parent depends on Child).
	found := false
	for _, e := range doc.Edges {
		if e.Parent == demo.BomRef && e.Child == leftpad.BomRef {
			found = true
		}
	}
	if !found {
		t.Errorf("edges = %+v, want syft-demo -> leftpad", doc.Edges)
	}
	// "contains" and "evident-by" relationships (source -> package, package ->
	// file) must not leak into the dependency graph.
	for _, e := range doc.Edges {
		if e.Parent == doc.RootRef {
			t.Errorf("a non-dependency relationship leaked into Edges: %+v", e)
		}
	}
}

func TestParseSyftRejectsNonSyft(t *testing.T) {
	if _, err := parseSyft(strings.NewReader(`{"bomFormat":"CycloneDX"}`)); err == nil {
		t.Error("expected rejection of a non-syft document")
	}
	if _, err := parseSyft(strings.NewReader(`not json`)); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestIsSyft(t *testing.T) {
	raw, err := os.ReadFile("testdata/syft_npm_demo.json")
	if err != nil {
		t.Fatal(err)
	}
	if !isSyft(raw) {
		t.Error("isSyft(syft fixture) = false, want true")
	}
	if isSyft([]byte(sampleCycloneDX)) {
		t.Error("isSyft(cyclonedx) = true, want false")
	}
}
