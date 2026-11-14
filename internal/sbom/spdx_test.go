package sbom

import "testing"

const sampleSPDX = `{
  "spdxVersion": "SPDX-2.3",
  "name": "web-app",
  "documentNamespace": "https://example.com/web-app",
  "packages": [
    {
      "name": "lodash",
      "versionInfo": "4.17.21",
      "SPDXID": "SPDXRef-Package-lodash",
      "licenseConcluded": "MIT",
      "licenseDeclared": "NOASSERTION",
      "externalRefs": [
        { "referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.21" }
      ],
      "checksums": [ { "algorithm": "SHA256", "checksumValue": "deadbeef" } ]
    },
    {
      "name": "unknown-license-pkg",
      "versionInfo": "1.0.0",
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NONE"
    },
    { "versionInfo": "9.9.9" }
  ]
}`

func TestParseSPDX(t *testing.T) {
	doc, err := Parse([]byte(sampleSPDX))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if doc.Format != "SPDX" || doc.SpecVersion != "SPDX-2.3" || doc.Artifact != "web-app" {
		t.Errorf("metadata wrong: %+v", doc)
	}
	if len(doc.Components) != 2 { // nameless package dropped
		t.Fatalf("components = %d, want 2", len(doc.Components))
	}

	lodash := doc.Components[0]
	if lodash.Version != "4.17.21" || lodash.Purl != "pkg:npm/lodash@4.17.21" {
		t.Errorf("lodash = %+v", lodash)
	}
	if lodash.License != "MIT" { // concluded preferred, NOASSERTION ignored
		t.Errorf("license = %q, want MIT", lodash.License)
	}
	if lodash.Hashes["SHA256"] != "deadbeef" {
		t.Errorf("hashes = %v", lodash.Hashes)
	}
	// NOASSERTION/NONE collapse to an empty license rather than leaking sentinels.
	if doc.Components[1].License != "" {
		t.Errorf("license = %q, want empty", doc.Components[1].License)
	}
}

func TestParseDetectsFormat(t *testing.T) {
	cdx, err := Parse([]byte(sampleCycloneDX))
	if err != nil || cdx.Format != "CycloneDX" {
		t.Errorf("CycloneDX detection failed: fmt=%q err=%v", cdx.Format, err)
	}
	spdx, err := Parse([]byte(sampleSPDX))
	if err != nil || spdx.Format != "SPDX" {
		t.Errorf("SPDX detection failed: fmt=%q err=%v", spdx.Format, err)
	}
	if _, err := Parse([]byte(`{"foo":"bar"}`)); err == nil {
		t.Error("expected error for unrecognized format")
	}
}
