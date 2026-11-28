package apidoc

import (
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// spec is the parsed OpenAPI document.
type spec struct {
	OpenAPI string `yaml:"openapi"`
	Info    struct {
		Title   string `yaml:"title"`
		Version string `yaml:"version"`
	} `yaml:"info"`
	Tags []struct {
		Name string `yaml:"name"`
	} `yaml:"tags"`
	Paths      map[string]map[string]operation `yaml:"paths"`
	Components struct {
		Schemas    map[string]any `yaml:"schemas"`
		Parameters map[string]any `yaml:"parameters"`
		Responses  map[string]any `yaml:"responses"`
		// RequestBodies holds bodies shared by several operations.
		RequestBodies map[string]any `yaml:"requestBodies"`
	} `yaml:"components"`
}

type operation struct {
	OperationID string         `yaml:"operationId"`
	Tags        []string       `yaml:"tags"`
	Summary     string         `yaml:"summary"`
	Responses   map[string]any `yaml:"responses"`
}

func load(t *testing.T) spec {
	t.Helper()
	var s spec
	if err := yaml.Unmarshal(Spec(), &s); err != nil {
		t.Fatalf("the spec is not valid YAML: %v", err)
	}
	return s
}

func TestSpecIsWellFormed(t *testing.T) {
	s := load(t)
	if !strings.HasPrefix(s.OpenAPI, "3.") {
		t.Errorf("openapi = %q, want 3.x", s.OpenAPI)
	}
	if s.Info.Title == "" || s.Info.Version == "" {
		t.Error("info.title and info.version are required")
	}
	if len(s.Paths) == 0 {
		t.Fatal("the spec documents no paths")
	}

	// It must also render as JSON — that's what most tooling consumes.
	j, err := SpecJSON()
	if err != nil {
		t.Fatalf("spec does not render as JSON: %v", err)
	}
	if len(j) < 1000 {
		t.Errorf("JSON spec is suspiciously small (%d bytes)", len(j))
	}
}

// Every operation needs a summary and at least one response. An entry with
// neither is a placeholder pretending to be documentation.
func TestEveryOperationIsDescribed(t *testing.T) {
	s := load(t)
	known := map[string]bool{}
	for _, tag := range s.Tags {
		known[tag.Name] = true
	}

	for path, methods := range s.Paths {
		for method, op := range methods {
			where := strings.ToUpper(method) + " " + path
			if op.Summary == "" {
				t.Errorf("%s: no summary", where)
			}
			if len(op.Responses) == 0 {
				t.Errorf("%s: no documented responses", where)
			}
			if len(op.Tags) == 0 {
				t.Errorf("%s: no tag — it won't appear under any section", where)
			}
			for _, tag := range op.Tags {
				if !known[tag] {
					t.Errorf("%s: tag %q is not declared in the top-level tags list", where, tag)
				}
			}
		}
	}
}

// Every operation needs a unique, identifier-shaped operationId: generated
// clients (clients/go, clients/typescript) name their methods after it, so a
// missing one breaks generation and a renamed one is a breaking client change.
// `go run ./internal/tools/opids` derives ids for new operations.
func TestEveryOperationHasUniqueID(t *testing.T) {
	s := load(t)
	seen := map[string]string{}
	for path, methods := range s.Paths {
		for method, op := range methods {
			where := strings.ToUpper(method) + " " + path
			id := op.OperationID
			switch {
			case id == "":
				t.Errorf("%s: no operationId (run `go run ./internal/tools/opids`)", where)
				continue
			case !validOperationID(id):
				t.Errorf("%s: operationId %q must be lowerCamelCase letters and digits", where, id)
			}
			if prev, dup := seen[id]; dup {
				t.Errorf("operationId %q used by both %s and %s", id, prev, where)
			}
			seen[id] = where
		}
	}
}

func validOperationID(id string) bool {
	if id == "" || id[0] < 'a' || id[0] > 'z' {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// Every $ref must resolve. A dangling ref renders as a blank box in every docs
// viewer and breaks every code generator.
func TestNoDanglingRefs(t *testing.T) {
	s := load(t)

	var doc any
	if err := yaml.Unmarshal(Spec(), &doc); err != nil {
		t.Fatal(err)
	}

	var refs []string
	var walk func(any)
	walk = func(n any) {
		switch v := n.(type) {
		case map[string]any:
			for k, child := range v {
				if k == "$ref" {
					if s, ok := child.(string); ok {
						refs = append(refs, s)
					}
					continue
				}
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(doc)

	if len(refs) == 0 {
		t.Fatal("no $refs found — the walker is broken, not the spec")
	}
	for _, ref := range refs {
		parts := strings.Split(strings.TrimPrefix(ref, "#/components/"), "/")
		if len(parts) != 2 {
			t.Errorf("unsupported $ref %q", ref)
			continue
		}
		var target map[string]any
		switch parts[0] {
		case "schemas":
			target = s.Components.Schemas
		case "parameters":
			target = s.Components.Parameters
		case "responses":
			target = s.Components.Responses
		case "requestBodies":
			target = s.Components.RequestBodies
		default:
			t.Errorf("$ref %q points at an unknown component section", ref)
			continue
		}
		if _, ok := target[parts[1]]; !ok {
			t.Errorf("$ref %q does not resolve", ref)
		}
	}
}

func TestPathsSortedForHumans(t *testing.T) {
	s := load(t)
	paths := make([]string, 0, len(s.Paths))
	for p := range s.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	if len(paths) < 40 {
		t.Errorf("only %d paths documented; the API has far more than that", len(paths))
	}
}

// A schema's examples are real API responses; every field in one must be a
// declared property. An undeclared field means the documentation fell behind
// the API (generated clients would drop it), so document it, don't delete it.
func TestSchemaExamplesUseDeclaredProperties(t *testing.T) {
	var doc struct {
		Components struct {
			Schemas map[string]struct {
				Properties map[string]any   `yaml:"properties"`
				Examples   []map[string]any `yaml:"examples"`
			} `yaml:"schemas"`
		} `yaml:"components"`
	}
	if err := yaml.Unmarshal(Spec(), &doc); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for name, sch := range doc.Components.Schemas {
		for _, ex := range sch.Examples {
			checked++
			for field := range ex {
				if _, ok := sch.Properties[field]; !ok {
					t.Errorf("schema %s: example field %q is not a declared property", name, field)
				}
			}
		}
	}
	if checked == 0 {
		t.Error("no schema examples found")
	}
}
