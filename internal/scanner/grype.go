package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Grype parses `grype -o json` output. Grype is the natural companion to Syft:
// Syft produces the SBOM, Grype matches it against advisories. Its native JSON
// carries the PURL, the fix version and CVSS, which SARIF drops — so prefer this
// over the SARIF path when both are available.
type Grype struct{}

// NewGrype constructs a Grype parser.
func NewGrype() Grype { return Grype{} }

// Scanner returns the tool identifier.
func (Grype) Scanner() string { return "grype" }

// PrimaryCategory is the scan-level category for Grype reports.
func (Grype) PrimaryCategory() domain.Category { return domain.CategorySCA }

type grypeReport struct {
	Source struct {
		Type   string `json:"type"`
		Target any    `json:"target"`
	} `json:"source"`
	Distro struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"distro"`
	Matches []struct {
		Vulnerability          grypeVuln   `json:"vulnerability"`
		RelatedVulnerabilities []grypeVuln `json:"relatedVulnerabilities"`
		Artifact               struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Purl      string `json:"purl"`
			Locations []struct {
				Path string `json:"path"`
			} `json:"locations"`
		} `json:"artifact"`
	} `json:"matches"`
}

type grypeVuln struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	DataSource  string `json:"dataSource"`
	Fix         struct {
		Versions []string `json:"versions"`
		State    string   `json:"state"`
	} `json:"fix"`
	CVSS []struct {
		Metrics struct {
			BaseScore float64 `json:"baseScore"`
		} `json:"metrics"`
	} `json:"cvss"`
}

// Parse converts a Grype report into findings.
func (Grype) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report grypeReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode grype report: %w", err)
	}

	// An image scan names the image and its distro: remediation groups the
	// image's distro packages as one base-image rebuild.
	image, osName := "", ""
	if report.Source.Type == "image" {
		switch t := report.Source.Target.(type) {
		case map[string]any:
			image, _ = t["userInput"].(string)
		case string:
			image = t
		}
		osName = strings.TrimSpace(report.Distro.Name + " " + report.Distro.Version)
	}
	out := make([]ParsedFinding, 0, len(report.Matches))
	for _, m := range report.Matches {
		v := m.Vulnerability

		// Grype's primary id may be a GHSA/DSA/vendor id, with the CVE listed as a
		// related vulnerability. Collect every CVE so cross-tool dedup can group
		// this with the same issue reported by another scanner.
		ids := []string{v.ID}
		for _, rel := range m.RelatedVulnerabilities {
			ids = append(ids, rel.ID)
		}

		f := ParsedFinding{
			Category:       domain.CategorySCA,
			RuleID:         v.ID,
			Title:          fmt.Sprintf("%s in %s", v.ID, m.Artifact.Name),
			Description:    v.Description,
			Severity:       normalizeSeverity(v.Severity),
			CVE:            cvesFrom(ids...),
			Package:        m.Artifact.Name,
			PackageVersion: m.Artifact.Version,
			Purl:           m.Artifact.Purl,
			URL:            v.DataSource,
			Metadata:       map[string]any{"fix_state": v.Fix.State},
		}
		if image != "" {
			f.Metadata["image"] = image
			if osName != "" {
				f.Metadata["os"] = osName
			}
		}
		if len(v.Fix.Versions) > 0 {
			f.FixedVersion = v.Fix.Versions[0]
		}
		if len(m.Artifact.Locations) > 0 {
			f.FilePath = m.Artifact.Locations[0].Path
		}
		if len(v.CVSS) > 0 && v.CVSS[0].Metrics.BaseScore > 0 {
			f.CVSS = floatPtr(v.CVSS[0].Metrics.BaseScore)
		}
		out = append(out, f)
	}
	return out, nil
}
