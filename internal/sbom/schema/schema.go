// Package schema validates CycloneDX SBOM documents against the official
// CycloneDX JSON schemas (embedded, no network fetches) for strict upload
// validation (M12 12.14). Every schema is registered by its own `$id`, so the
// bom-*.schema.json files' relative $refs to spdx.schema.json and
// jsf-0.82.schema.json resolve against the embedded copies. See NOTICE for
// provenance and license.
package schema

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"golang.org/x/text/language"
	"golang.org/x/text/message"
)

// printer renders ErrorKind messages in English, the same default the
// library itself uses for Error()/BasicOutput().
var printer = message.NewPrinter(language.English)

//go:embed cyclonedx/*.json
var cyclonedxFS embed.FS

// FieldError is one schema violation, with the JSON pointer of the offending
// value (e.g. "/components/3/purl") and a human-readable message.
type FieldError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

// MaxFieldErrors caps how many FieldErrors ValidateCycloneDX returns for one
// document: enough to act on, small enough for a 400 body.
const MaxFieldErrors = 50

// cycloneDXSchema is one embedded bom-<version>.schema.json's own `$id`,
// keyed by the specVersion it declares.
var cycloneDXSchema = map[string]string{
	"1.2": "http://cyclonedx.org/schema/bom-1.2b.schema.json",
	"1.3": "http://cyclonedx.org/schema/bom-1.3a.schema.json",
	"1.4": "http://cyclonedx.org/schema/bom-1.4.schema.json",
	"1.5": "http://cyclonedx.org/schema/bom-1.5.schema.json",
	"1.6": "http://cyclonedx.org/schema/bom-1.6.schema.json",
	"1.7": "http://cyclonedx.org/schema/bom-1.7.schema.json",
}

var (
	compilerOnce sync.Once
	compiler     *jsonschema.Compiler
	compilerErr  error

	mu       sync.Mutex
	compiled = map[string]*jsonschema.Schema{}
)

// loadCompiler builds the one Compiler for every embedded schema file,
// registering each by its own `$id` so cross-file $refs resolve without a
// network fetch. Built once; compiledSchema below only reads from it.
func loadCompiler() (*jsonschema.Compiler, error) {
	compilerOnce.Do(func() {
		c := jsonschema.NewCompiler()
		compilerErr = fs.WalkDir(cyclonedxFS, "cyclonedx", func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			raw, err := cyclonedxFS.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read %s: %w", path, err)
			}
			doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
			if err != nil {
				return fmt.Errorf("decode %s: %w", path, err)
			}
			obj, _ := doc.(map[string]any)
			id, _ := obj["$id"].(string)
			if id == "" {
				return fmt.Errorf("%s: schema has no $id", path)
			}
			if err := c.AddResource(id, doc); err != nil {
				return fmt.Errorf("register %s (%s): %w", path, id, err)
			}
			return nil
		})
		compiler = c
	})
	return compiler, compilerErr
}

// compiledSchema returns the compiled schema for a CycloneDX specVersion,
// compiling (and caching) it on first use.
func compiledSchema(specVersion string) (*jsonschema.Schema, error) {
	id, ok := cycloneDXSchema[specVersion]
	if !ok {
		return nil, fmt.Errorf("unsupported CycloneDX specVersion %q for strict validation", specVersion)
	}
	mu.Lock()
	defer mu.Unlock()
	if sch, ok := compiled[id]; ok {
		return sch, nil
	}
	c, err := loadCompiler()
	if err != nil {
		return nil, fmt.Errorf("load cyclonedx schemas: %w", err)
	}
	sch, err := c.Compile(id)
	if err != nil {
		return nil, fmt.Errorf("compile cyclonedx %s schema: %w", specVersion, err)
	}
	compiled[id] = sch
	return sch, nil
}

// ValidateCycloneDX validates raw CycloneDX JSON (a whole BOM document)
// against the official schema for its own `specVersion` field. A nil slice
// with a nil error means the document is valid; a non-nil error means the
// document couldn't be checked at all (bad JSON, or an unsupported
// specVersion) rather than that it failed validation.
func ValidateCycloneDX(raw []byte) ([]FieldError, error) {
	var probe struct {
		SpecVersion string `json:"specVersion"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	sch, err := compiledSchema(probe.SpecVersion)
	if err != nil {
		return nil, err
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	if err := sch.Validate(inst); err != nil {
		ve, ok := err.(*jsonschema.ValidationError)
		if !ok {
			return nil, err
		}
		return flatten(ve), nil
	}
	return nil, nil
}

// flatten walks a jsonschema validation error tree to its genuine leaves
// (keyword failures with no causes of their own — "enum", "pattern",
// "required", …) rather than using BasicOutput's flattening, which labels
// each direct branch with its possibly-generic $ref/Schema wrapper kind
// instead of the real failing keyword. Capped at MaxFieldErrors, depth
// first, so a document with many broken components doesn't flood the
// response.
func flatten(ve *jsonschema.ValidationError) []FieldError {
	var errs []FieldError
	var walk func(e *jsonschema.ValidationError)
	walk = func(e *jsonschema.ValidationError) {
		if len(errs) >= MaxFieldErrors {
			return
		}
		if len(e.Causes) == 0 {
			errs = append(errs, FieldError{
				Path:    jsonPointer(e.InstanceLocation),
				Message: e.ErrorKind.LocalizedString(printer),
			})
			return
		}
		for _, cause := range e.Causes {
			walk(cause)
			if len(errs) >= MaxFieldErrors {
				return
			}
		}
	}
	walk(ve)
	if len(errs) == 0 {
		errs = append(errs, FieldError{Path: "/", Message: "schema validation failed"})
	}
	return errs
}

// jsonPointer renders instance-location tokens as a JSON Pointer (RFC 6901):
// "/" for the root document, "/components/3/purl" for a nested field.
func jsonPointer(tokens []string) string {
	if len(tokens) == 0 {
		return "/"
	}
	var sb strings.Builder
	for _, tok := range tokens {
		sb.WriteByte('/')
		sb.WriteString(strings.NewReplacer("~", "~0", "/", "~1").Replace(tok))
	}
	return sb.String()
}
