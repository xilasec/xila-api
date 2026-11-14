package apidoc

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"
)

// OpenAPI30 returns the spec rewritten as OpenAPI 3.0.3, for code generators
// that do not read 3.1 yet (the Go client in clients/go is generated from it).
// The hand-written spec stays 3.1; this is a mechanical, lossy view of it:
//
//   - `type: [T, "null"]` becomes `type: T` + `nullable: true`;
//   - a type list with several non-null members (`[string, number, "null"]`)
//     drops `type`, i.e. any value — 3.0 cannot say "string or number";
//   - a schema's `examples: [a, …]` (3.1 / JSON Schema) becomes `example: a`.
//
// Key order is preserved, so the generated client is stable across runs.
func OpenAPI30() ([]byte, error) { return downgrade30(specYAML) }

func downgrade30(spec []byte) ([]byte, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(spec, &doc); err != nil {
		return nil, fmt.Errorf("parse openapi spec: %w", err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("openapi spec: not a mapping")
	}
	root := doc.Content[0]
	if v := mapValue(root, "openapi"); v != nil {
		v.Value = "3.0.3"
	}
	walk30(root, false)

	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, fmt.Errorf("encode openapi 3.0 view: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// walk30 rewrites every schema-shaped mapping below n. underExamples marks the
// value of an operation-level `examples` map (named Example Objects), which is
// valid 3.0 and must be left alone.
func walk30(n *yaml.Node, underExamples bool) {
	switch n.Kind {
	case yaml.SequenceNode:
		for _, c := range n.Content {
			walk30(c, false)
		}
	case yaml.MappingNode:
		if !underExamples {
			rewriteSchema30(n)
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i], n.Content[i+1]
			// Media Type / Parameter `examples` is a map of Example Objects:
			// keep its shape, but still descend into the example values' siblings.
			walk30(val, key.Value == "examples" && val.Kind == yaml.MappingNode)
		}
	}
}

// rewriteSchema30 applies the 3.1 → 3.0 rewrites to one mapping, if it has
// the 3.1-only shapes.
func rewriteSchema30(m *yaml.Node) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		key, val := m.Content[i], m.Content[i+1]
		switch {
		case key.Value == "type" && val.Kind == yaml.SequenceNode:
			var types []string
			nullable := false
			for _, t := range val.Content {
				if t.Value == "null" {
					nullable = true
				} else {
					types = append(types, t.Value)
				}
			}
			if len(types) == 1 {
				m.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: types[0]}
			} else {
				// Several non-null types: 3.0 has no union of primitives.
				m.Content = append(m.Content[:i], m.Content[i+2:]...)
				i -= 2
			}
			if nullable && mapValue(m, "nullable") == nil {
				m.Content = append(m.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "nullable"},
					&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: "true"})
			}
		case key.Value == "examples" && val.Kind == yaml.SequenceNode:
			// A schema's JSON-Schema `examples` list; 3.0 has a single `example`.
			if len(val.Content) == 0 {
				m.Content = append(m.Content[:i], m.Content[i+2:]...)
				i -= 2
				continue
			}
			key.Value = "example"
			m.Content[i+1] = val.Content[0]
		}
	}
}

func mapValue(m *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
