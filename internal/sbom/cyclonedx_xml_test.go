package sbom

import (
	"cmp"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// cyclonedx-php-composer wrote the same BOM as XML and as JSON (CycloneDX
// bom-examples, SBOM/laravel-7.12.0, bom.1.3.xml / bom.1.3.json): both must
// parse to the same document, so XML support can't drop or reshape a field
// the JSON parser keeps.
func TestCycloneDXXMLMatchesJSON(t *testing.T) {
	fromXML := parseFixture(t, "laravel-7.12.0.cdx.xml")
	fromJSON := parseFixture(t, "laravel-7.12.0.cdx.json")
	if !fromXML.XML || fromJSON.XML {
		t.Fatalf("XML flag: xml=%v json=%v", fromXML.XML, fromJSON.XML)
	}
	fromXML.XML = false
	// Edges are a graph: XML lists them in its nested walk order.
	for _, d := range []*Document{&fromXML, &fromJSON} {
		slices.SortFunc(d.Edges, func(a, b Edge) int {
			return cmp.Or(strings.Compare(a.Parent, b.Parent), strings.Compare(a.Child, b.Child))
		})
	}
	if len(fromXML.Edges) == 0 || !reflect.DeepEqual(fromXML, fromJSON) {
		t.Errorf("XML and JSON parse differently:\nxml  %+v\njson %+v", fromXML, fromJSON)
	}
}

// Schema 1.6 (the specification's own test BOM): hashes, an SPDX id, an
// expression and a free-text license name, CPE and scope all come through.
func TestCycloneDXXML16(t *testing.T) {
	doc := parseFixture(t, "valid-bom-1.6.cdx.xml")
	if len(doc.Components) != 3 {
		t.Fatalf("components = %d, want 3", len(doc.Components))
	}
	byName := map[string]Component{}
	for _, c := range doc.Components {
		byName[c.Name] = c
	}
	cat := byName["tomcat-catalina"]
	if cat.License != "Apache-2.0" || cat.Hashes["SHA-256"] == "" || cat.Scope != "runtime" {
		t.Errorf("tomcat-catalina = %+v", cat)
	}
	if lib := byName["mylibrary"]; lib.License != "EPL-2.0 OR GPL-2.0-with-classpath-exception" || lib.Cpe != "cpe:/a:example:myapplication:1.0.0" {
		t.Errorf("mylibrary = %+v", lib)
	}
	if fw := byName["myframework"]; fw.License != "Some random license" || fw.Type != "framework" {
		t.Errorf("myframework = %+v", fw)
	}
	dep := parseFixture(t, "valid-dependency-1.6.cdx.xml")
	if len(dep.Edges) != 1 || dep.Edges[0].Child != "library-c" {
		t.Errorf("nested <dependency> edges = %+v, want library-b -> library-c", dep.Edges)
	}
}

// A real tool-generated BOM (cyclonedx-php-composer, schema 1.3, CDATA
// values, a dependency graph).
func TestCycloneDXXMLLaravel(t *testing.T) {
	doc := parseFixture(t, "laravel-7.12.0.cdx.xml")
	if len(doc.Components) != 62 || len(doc.Edges) != 113 {
		t.Errorf("components=%d edges=%d, want 62 and 113", len(doc.Components), len(doc.Edges))
	}
	if doc.RootRef != "cyclonedx/cyclonedx-php-composer-demo-dev-master" {
		t.Errorf("root = %q", doc.RootRef)
	}
	var cors *Component
	for i := range doc.Components {
		c := &doc.Components[i]
		for field, v := range map[string]string{"name": c.Name, "version": c.Version, "purl": c.Purl, "license": c.License, "bom-ref": c.BomRef} {
			if v != strings.TrimSpace(v) {
				t.Errorf("%s %s = %q: untrimmed", c.Name, field, v)
			}
		}
		if c.Name == "stack-cors" {
			cors = c
		}
	}
	if cors == nil || cors.Group != "asm89" || cors.Version != "1.3.0" ||
		cors.Purl != "pkg:composer/asm89/stack-cors@1.3.0" || cors.License != "MIT" {
		t.Errorf("stack-cors = %+v", cors)
	}
}

// Pretty-printed XML pads text content; a license expression must come out as
// the expression, as it would from JSON.
func TestCycloneDXXMLTrimsText(t *testing.T) {
	doc := parseFixture(t, "valid-license-expression-1.6.cdx.xml")
	if len(doc.Components) != 1 || doc.Components[0].License != "EPL-2.0 OR GPL-2.0 WITH Classpath-exception-2.0" {
		t.Errorf("license = %q", doc.Components[0].License)
	}
}

// A ref repeated in the nested tree contributes its edges once.
func TestCycloneDXXMLDependencyEdgesOnce(t *testing.T) {
	deps := convertXMLDependencies([]cycloneXMLDependency{
		{Ref: "app", Dependencies: []cycloneXMLDependency{{Ref: "lib", Dependencies: []cycloneXMLDependency{{Ref: "util"}}}}},
		{Ref: "lib", Dependencies: []cycloneXMLDependency{{Ref: "util"}}},
	})
	for _, d := range deps {
		if d.Ref == "lib" && len(d.DependsOn) != 1 {
			t.Errorf("lib dependsOn = %v, want util once", d.DependsOn)
		}
	}
}

func TestCycloneDXXMLRejectsOtherXML(t *testing.T) {
	if _, err := Parse([]byte(`<?xml version="1.0"?><project xmlns="http://maven.apache.org/POM/4.0.0"></project>`)); err == nil {
		t.Error("a non-CycloneDX XML document parsed")
	}
}
