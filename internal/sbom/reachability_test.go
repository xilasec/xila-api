package sbom

import (
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
)

// A CycloneDX BOM with a dependency graph: the app depends on express and (for
// tests only) on jest; body-parser and ms come along transitively.
const cycloneWithGraph = `{
  "bomFormat": "CycloneDX", "specVersion": "1.5",
  "metadata": {"component": {"bom-ref": "app", "name": "web", "version": "1.0.0"}},
  "components": [
    {"bom-ref": "pkg:npm/express@4.18.2",     "name": "express",     "version": "4.18.2", "purl": "pkg:npm/express@4.18.2"},
    {"bom-ref": "pkg:npm/body-parser@1.20.1", "name": "body-parser", "version": "1.20.1", "purl": "pkg:npm/body-parser@1.20.1"},
    {"bom-ref": "pkg:npm/ms@2.1.3",           "name": "ms",          "version": "2.1.3",  "purl": "pkg:npm/ms@2.1.3"},
    {"bom-ref": "pkg:npm/jest@29.0.0",        "name": "jest",        "version": "29.0.0", "purl": "pkg:npm/jest@29.0.0", "scope": "excluded"},
    {"bom-ref": "pkg:npm/orphan@1.0.0",       "name": "orphan",      "version": "1.0.0",  "purl": "pkg:npm/orphan@1.0.0"}
  ],
  "dependencies": [
    {"ref": "app", "dependsOn": ["pkg:npm/express@4.18.2", "pkg:npm/jest@29.0.0"]},
    {"ref": "pkg:npm/express@4.18.2", "dependsOn": ["pkg:npm/body-parser@1.20.1"]},
    {"ref": "pkg:npm/body-parser@1.20.1", "dependsOn": ["pkg:npm/ms@2.1.3"]}
  ]
}`

func TestCycloneDXReachability(t *testing.T) {
	doc, err := parseCycloneDX(strings.NewReader(cycloneWithGraph))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byName := map[string]Component{}
	for _, c := range doc.Components {
		byName[c.Name] = c
	}

	// Distance from the root component is what separates "we asked for this" from
	// "it came along for the ride".
	assertDep(t, byName["express"], true, 1, domain.DepScopeUnknown)
	assertDep(t, byName["body-parser"], false, 2, domain.DepScopeUnknown)
	assertDep(t, byName["ms"], false, 3, domain.DepScopeUnknown)

	// A direct dependency that never ships: CycloneDX "excluded" scope.
	assertDep(t, byName["jest"], true, 1, domain.DepScopeDev)

	// A component the graph never reaches is *unknown*, not depth 0 — we must not
	// invent a fact the SBOM didn't state.
	if o := byName["orphan"]; o.Direct != nil || o.Depth != nil {
		t.Errorf("unreachable component should have no reachability data, got direct=%v depth=%v", o.Direct, o.Depth)
	}
}

// A BOM with no dependencies section at all (plenty of tools emit these) must
// leave every component unknown rather than guessing.
func TestCycloneDXWithoutGraphIsUnknown(t *testing.T) {
	const flat = `{"bomFormat":"CycloneDX","specVersion":"1.5",
		"components":[{"name":"express","version":"4.18.2","purl":"pkg:npm/express@4.18.2"}]}`
	doc, err := parseCycloneDX(strings.NewReader(flat))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	c := doc.Components[0]
	if c.Direct != nil || c.Depth != nil || c.Scope != domain.DepScopeUnknown {
		t.Errorf("a BOM with no graph must yield no reachability, got %+v", c)
	}
}

const spdxWithGraph = `{
  "spdxVersion": "SPDX-2.3", "name": "web",
  "documentDescribes": ["SPDXRef-Package-app"],
  "packages": [
    {"SPDXID": "SPDXRef-Package-app",     "name": "app",         "versionInfo": "1.0.0"},
    {"SPDXID": "SPDXRef-Package-express", "name": "express",     "versionInfo": "4.18.2"},
    {"SPDXID": "SPDXRef-Package-bp",      "name": "body-parser", "versionInfo": "1.20.1"},
    {"SPDXID": "SPDXRef-Package-jest",    "name": "jest",        "versionInfo": "29.0.0"}
  ],
  "relationships": [
    {"spdxElementId": "SPDXRef-Package-app", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Package-express"},
    {"spdxElementId": "SPDXRef-Package-express", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Package-bp"},
    {"spdxElementId": "SPDXRef-Package-jest", "relationshipType": "DEV_DEPENDENCY_OF", "relatedSpdxElement": "SPDXRef-Package-app"}
  ]
}`

func TestSPDXReachability(t *testing.T) {
	doc, err := parseSPDX(strings.NewReader(spdxWithGraph))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byName := map[string]Component{}
	for _, c := range doc.Components {
		byName[c.Name] = c
	}
	assertDep(t, byName["express"], true, 1, domain.DepScopeUnknown)
	assertDep(t, byName["body-parser"], false, 2, domain.DepScopeUnknown)
	// DEV_DEPENDENCY_OF points the other way (jest is a dev dep *of* app), and it
	// is both an edge (so jest is reachable at depth 1) and a scope.
	assertDep(t, byName["jest"], true, 1, domain.DepScopeDev)
}

func assertDep(t *testing.T, c Component, direct bool, depth int, scope domain.DepScope) {
	t.Helper()
	if c.Direct == nil || c.Depth == nil {
		t.Fatalf("%s: missing reachability (direct=%v depth=%v)", c.Name, c.Direct, c.Depth)
	}
	if *c.Direct != direct || *c.Depth != depth || c.Scope != scope {
		t.Errorf("%s: direct=%v depth=%d scope=%q, want direct=%v depth=%d scope=%q",
			c.Name, *c.Direct, *c.Depth, c.Scope, direct, depth, scope)
	}
}
