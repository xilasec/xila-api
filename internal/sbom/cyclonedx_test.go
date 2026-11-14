package sbom

import (
	"strings"
	"testing"
)

const sampleCycloneDX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 1,
  "metadata": {
    "component": { "type": "application", "name": "web", "version": "2.1.0" }
  },
  "components": [
    {
      "type": "library",
      "group": "org.apache.logging.log4j",
      "name": "log4j-core",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
      "licenses": [{ "license": { "id": "Apache-2.0" } }],
      "hashes": [{ "alg": "SHA-256", "content": "abc123" }],
      "evidence": { "occurrences": [{ "location": "pom.xml" }] }
    },
    {
      "name": "leftpad",
      "version": "1.0.0",
      "purl": "pkg:npm/leftpad@1.0.0",
      "licenses": [{ "expression": "MIT OR Apache-2.0" }],
      "properties": [{ "name": "syft:location:0:path", "value": "package-lock.json" }]
    },
    { "type": "library", "version": "0.0.0" }
  ]
}`

func TestParseCycloneDX(t *testing.T) {
	doc, err := parseCycloneDX(strings.NewReader(sampleCycloneDX))
	if err != nil {
		t.Fatalf("parseCycloneDX: %v", err)
	}

	if doc.Format != "CycloneDX" || doc.SpecVersion != "1.5" {
		t.Errorf("metadata wrong: %+v", doc)
	}
	if doc.Artifact != "web" || doc.Version != "2.1.0" {
		t.Errorf("subject = %q@%q, want web@2.1.0", doc.Artifact, doc.Version)
	}
	// The nameless component must be dropped.
	if len(doc.Components) != 2 {
		t.Fatalf("got %d components, want 2 (nameless dropped)", len(doc.Components))
	}

	log4j := doc.Components[0]
	if log4j.Name != "log4j-core" || log4j.Type != "library" {
		t.Errorf("component[0] = %+v", log4j)
	}
	if log4j.License != "Apache-2.0" {
		t.Errorf("license = %q, want Apache-2.0", log4j.License)
	}
	if log4j.Hashes["SHA-256"] != "abc123" {
		t.Errorf("hashes = %v", log4j.Hashes)
	}
	if log4j.FilePath != "pom.xml" { // from evidence.occurrences
		t.Errorf("file_path = %q, want pom.xml", log4j.FilePath)
	}
	if doc.Components[1].FilePath != "package-lock.json" { // from syft property
		t.Errorf("leftpad file_path = %q, want package-lock.json", doc.Components[1].FilePath)
	}

	if doc.Components[1].License != "MIT OR Apache-2.0" {
		t.Errorf("expression license = %q", doc.Components[1].License)
	}
}

func TestParseCycloneDXRejectsNonCycloneDX(t *testing.T) {
	if _, err := parseCycloneDX(strings.NewReader(`{"bomFormat":"SPDX"}`)); err == nil {
		t.Error("expected rejection of a non-CycloneDX document")
	}
	if _, err := parseCycloneDX(strings.NewReader(`not json`)); err == nil {
		t.Error("expected error for invalid JSON")
	}
}
