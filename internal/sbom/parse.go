package sbom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Parse detects the SBOM format (CycloneDX, SPDX, a ScanCode.io project's
// JSON results, or Syft's native JSON) and decodes it into a Document.
// Detection is by content, so callers don't have to declare the format on
// upload.
func Parse(raw []byte) (Document, error) {
	var probe struct {
		BomFormat   string `json:"bomFormat"`
		SpecVersion string `json:"specVersion"`
		SpdxVersion string `json:"spdxVersion"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return Document{}, fmt.Errorf("read sbom: %w", err)
	}

	switch {
	case strings.EqualFold(probe.BomFormat, "CycloneDX"):
		return parseCycloneDX(bytes.NewReader(raw))
	case probe.SpdxVersion != "":
		return parseSPDX(bytes.NewReader(raw))
	case isSyft(raw):
		return parseSyft(bytes.NewReader(raw))
	case isScanCodeIO(raw):
		return parseScanCodeIO(bytes.NewReader(raw))
	default:
		return Document{}, fmt.Errorf("unrecognized SBOM format (need CycloneDX, SPDX, Syft or ScanCode.io JSON)")
	}
}
