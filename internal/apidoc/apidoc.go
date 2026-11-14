// Package apidoc serves the OpenAPI description of the API.
//
// The spec is hand-written (internal/apidoc/openapi.yaml) and embedded in the
// binary, so any instance describes itself — no hosted docs to drift out of sync
// with the version you actually run, and it works air-gapped.
//
// It cannot silently rot, either: openapi_test.go walks Fiber's real route table
// and fails if a route is undocumented or a documented path no longer exists.
// Documentation that isn't checked is documentation that lies.
package apidoc

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"gopkg.in/yaml.v3"
)

//go:embed openapi.yaml
var specYAML []byte

// Spec returns the OpenAPI document as YAML.
func Spec() []byte { return specYAML }

// SpecJSON returns the same document as JSON — what most tooling (Postman,
// Insomnia, Scalar, code generators) actually wants.
func SpecJSON() ([]byte, error) {
	var doc any
	if err := yaml.Unmarshal(specYAML, &doc); err != nil {
		return nil, fmt.Errorf("parse openapi spec: %w", err)
	}
	return json.Marshal(doc)
}

// Routes returns every operation the spec documents, keyed as
// "METHOD /api/v1/path" with OpenAPI's {param} rewritten to Fiber's :param — so
// it can be compared directly against the application's real route table. The
// server package's drift test does exactly that, in both directions.
func Routes() (map[string]bool, error) {
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(specYAML, &doc); err != nil {
		return nil, fmt.Errorf("parse openapi spec: %w", err)
	}

	out := make(map[string]bool, len(doc.Paths))
	for path, methods := range doc.Paths {
		fiberPath := path
		for {
			open := strings.Index(fiberPath, "{")
			closing := strings.Index(fiberPath, "}")
			if open < 0 || closing < open {
				break
			}
			fiberPath = fiberPath[:open] + ":" + fiberPath[open+1:closing] + fiberPath[closing+1:]
		}
		// The health probes are served at the root; everything else under /api/v1.
		full := "/api/v1" + fiberPath
		if fiberPath == "/health" || fiberPath == "/ready" {
			full = fiberPath
		}
		for method := range methods {
			out[strings.ToUpper(method)+" "+full] = true
		}
	}
	return out, nil
}

// Handler serves the spec.
type Handler struct {
	specJSON []byte
}

// NewHandler pre-renders the JSON form once. A malformed spec is a build-time
// mistake, not a runtime one, so it fails loudly here rather than serving broken
// documentation.
func NewHandler() (*Handler, error) {
	j, err := SpecJSON()
	if err != nil {
		return nil, err
	}
	return &Handler{specJSON: j}, nil
}

// Register mounts the spec routes. They are public: an API description is not a
// secret, and requiring a token to read it defeats the point of publishing one.
func (h *Handler) Register(app *fiber.App) {
	app.Get("/api/v1/openapi.json", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
		return c.Send(h.specJSON)
	})
	app.Get("/api/v1/openapi.yaml", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "application/yaml")
		return c.Send(specYAML)
	})
}
