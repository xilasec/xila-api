package sbom

import (
	"fmt"

	"github.com/xilasec/xila-api/internal/sbom/schema"
)

// StrictValidationError is returned by Ingest when strict mode is on (per
// upload with ?strict=true, or instance-wide with SBOM_STRICT_VALIDATION) and
// a CycloneDX document fails the official JSON schema for its specVersion.
// Fields is capped at schema.MaxFieldErrors and carries a JSON-pointer Path
// for each violation (e.g. "/components/3/type").
type StrictValidationError struct {
	Fields []schema.FieldError
}

func (e *StrictValidationError) Error() string {
	if len(e.Fields) == 0 {
		return "cyclonedx schema validation failed"
	}
	return fmt.Sprintf("cyclonedx schema validation failed: %s: %s (and %d more)",
		e.Fields[0].Path, e.Fields[0].Message, len(e.Fields)-1)
}

// validateStrict checks raw against the CycloneDX schema for its own
// specVersion when doc is a CycloneDX document; every other format (SPDX,
// Syft, ScanCode.io) has no CycloneDX schema to check against and is left to
// its own parser's validation, strict or not.
func validateStrict(doc Document, raw []byte) error {
	if doc.Format != "CycloneDX" {
		return nil
	}
	fields, err := schema.ValidateCycloneDX(raw)
	if err != nil {
		return fmt.Errorf("strict validation: %w", err)
	}
	if len(fields) > 0 {
		return &StrictValidationError{Fields: fields}
	}
	return nil
}
