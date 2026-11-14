package apidoc

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDowngrade30(t *testing.T) {
	in := []byte(`openapi: 3.1.0
paths:
  /x:
    get:
      responses:
        "200":
          content:
            application/json:
              examples:
                one: { summary: s, value: { a: 1 } }
              schema:
                type: object
                properties:
                  name: { type: [string, "null"], examples: [web, api] }
                  n: { type: integer }
                  v: { type: [string, number, "null"] }
                  e: { type: string, examples: [] }
`)
	out, err := downgrade30(in)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["openapi"] != "3.0.3" {
		t.Errorf("openapi = %v", doc["openapi"])
	}
	media := doc["paths"].(map[string]any)["/x"].(map[string]any)["get"].(map[string]any)["responses"].(map[string]any)["200"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)
	props := media["schema"].(map[string]any)["properties"].(map[string]any)
	name := props["name"].(map[string]any)
	if name["type"] != "string" || name["nullable"] != true || name["example"] != "web" || name["examples"] != nil {
		t.Errorf("name = %v", name)
	}
	if n := props["n"].(map[string]any); n["type"] != "integer" || n["nullable"] != nil {
		t.Errorf("n = %v", n)
	}
	if v := props["v"].(map[string]any); v["type"] != nil || v["nullable"] != true {
		t.Errorf("v = %v (several non-null types → any, nullable)", v)
	}
	if e := props["e"].(map[string]any); e["examples"] != nil || e["example"] != nil {
		t.Errorf("e = %v (empty examples dropped)", e)
	}
	// Named Example Objects at the media-type level are valid 3.0: untouched.
	if ex, ok := media["examples"].(map[string]any)["one"].(map[string]any); !ok || ex["summary"] != "s" {
		t.Errorf("media examples = %v", media["examples"])
	}
}

// The real spec must survive the rewrite with no 3.1-only shapes left.
func TestOpenAPI30OfRealSpec(t *testing.T) {
	out, err := OpenAPI30()
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.HasPrefix(s, "openapi: 3.0.3\n") {
		t.Errorf("starts %q", s[:40])
	}
	if strings.Contains(s, `- "null"`) || strings.Contains(s, "- 'null'") || strings.Contains(s, "type: [") {
		t.Error("a 3.1 type list survived the rewrite")
	}
}
