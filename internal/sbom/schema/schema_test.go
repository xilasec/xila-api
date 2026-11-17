package schema

import (
	"encoding/json"
	"os"
	"testing"
)

// Real CycloneDX documents (Apache-2.0, see NOTICE) exercise every embedded
// schema version end to end, not just a hand-written minimal BOM.
func TestValidateCycloneDXValidFixtures(t *testing.T) {
	for _, path := range []string{
		"../testdata/licenses-maven.cdx.json",
		"../testdata/machine-learning-1.6.cdx.json",
	} {
		t.Run(path, func(t *testing.T) {
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			fields, err := ValidateCycloneDX(raw)
			if err != nil {
				t.Fatalf("ValidateCycloneDX: %v", err)
			}
			if len(fields) != 0 {
				t.Fatalf("expected a valid document, got %d field errors: %+v", len(fields), fields[:min(3, len(fields))])
			}
		})
	}
}

func TestValidateCycloneDXEverySupportedVersion(t *testing.T) {
	base := map[string]any{
		"bomFormat":  "CycloneDX",
		"version":    1,
		"metadata":   map[string]any{"component": map[string]any{"type": "application", "name": "demo", "version": "1.0.0"}},
		"components": []any{map[string]any{"type": "library", "name": "left-pad", "version": "1.0.0", "purl": "pkg:npm/left-pad@1.0.0"}},
	}
	for v := range cycloneDXSchema {
		t.Run(v, func(t *testing.T) {
			doc := map[string]any{}
			for k, val := range base {
				doc[k] = val
			}
			doc["specVersion"] = v
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			fields, err := ValidateCycloneDX(raw)
			if err != nil {
				t.Fatalf("ValidateCycloneDX(%s): %v", v, err)
			}
			if len(fields) != 0 {
				t.Fatalf("ValidateCycloneDX(%s): unexpected field errors: %+v", v, fields)
			}
		})
	}
}

// A component derived from licenses-maven.cdx.json, with its type set to a
// value outside the schema's enum — the field error JSON-pointers straight
// at it.
func TestValidateCycloneDXInvalid(t *testing.T) {
	doc := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.6",
		"version":     1,
		"metadata":    map[string]any{"component": map[string]any{"type": "application", "name": "demo"}},
		"components": []any{
			map[string]any{"type": "not-a-real-type", "name": "jackson-annotations", "version": "2.9.10"},
		},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := ValidateCycloneDX(raw)
	if err != nil {
		t.Fatalf("ValidateCycloneDX: %v", err)
	}
	if len(fields) == 0 {
		t.Fatal("expected field errors for an invalid document")
	}
	var sawType bool
	for _, f := range fields {
		t.Logf("%s: %s", f.Path, f.Message)
		if f.Path == "/components/0/type" {
			sawType = true
		}
	}
	if !sawType {
		t.Errorf("expected a field error at /components/0/type, got %+v", fields)
	}
}

func TestValidateCycloneDXUnsupportedSpecVersion(t *testing.T) {
	raw := []byte(`{"bomFormat":"CycloneDX","specVersion":"0.9","version":1}`)
	if _, err := ValidateCycloneDX(raw); err == nil {
		t.Fatal("expected an error for an unsupported specVersion")
	}
}

func TestValidateCycloneDXBadJSON(t *testing.T) {
	if _, err := ValidateCycloneDX([]byte("not json")); err == nil {
		t.Fatal("expected a decode error")
	}
}

func TestFlattenCapsErrors(t *testing.T) {
	// A document with far more than MaxFieldErrors invalid components, each
	// failing the "type" enum.
	components := make([]any, 0, MaxFieldErrors+20)
	for range MaxFieldErrors + 20 {
		components = append(components, map[string]any{"type": "not-a-real-type", "name": "x"})
	}
	doc := map[string]any{
		"bomFormat":   "CycloneDX",
		"specVersion": "1.6",
		"version":     1,
		"components":  components,
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	fields, err := ValidateCycloneDX(raw)
	if err != nil {
		t.Fatalf("ValidateCycloneDX: %v", err)
	}
	if len(fields) > MaxFieldErrors {
		t.Errorf("len(fields) = %d, want <= %d", len(fields), MaxFieldErrors)
	}
	if len(fields) == 0 {
		t.Fatal("expected field errors")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
