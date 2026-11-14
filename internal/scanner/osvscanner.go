package scanner

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/xilasec/xila-api/internal/domain"
)

// OSVScanner parses `osv-scanner --format json` output — Google's scanner over
// the same OSV.dev database Xila matches SBOMs against, so its findings dedup
// cleanly against ours.
type OSVScanner struct{}

// NewOSVScanner constructs an OSVScanner parser.
func NewOSVScanner() OSVScanner { return OSVScanner{} }

// Scanner returns the tool identifier.
func (OSVScanner) Scanner() string { return "osv-scanner" }

// PrimaryCategory is the scan-level category for osv-scanner reports.
func (OSVScanner) PrimaryCategory() domain.Category { return domain.CategorySCA }

type osvScannerReport struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID               string   `json:"id"`
				Summary          string   `json:"summary"`
				Details          string   `json:"details"`
				Aliases          []string `json:"aliases"`
				DatabaseSpecific struct {
					Severity string `json:"severity"`
				} `json:"database_specific"`
				Affected []struct {
					Ranges []struct {
						Events []struct {
							Fixed string `json:"fixed"`
						} `json:"events"`
					} `json:"ranges"`
				} `json:"affected"`
			} `json:"vulnerabilities"`
		} `json:"packages"`
	} `json:"results"`
}

// Parse converts an osv-scanner report into findings.
func (OSVScanner) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report osvScannerReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode osv-scanner report: %w", err)
	}

	var out []ParsedFinding
	for _, res := range report.Results {
		for _, p := range res.Packages {
			for _, v := range p.Vulnerabilities {
				f := ParsedFinding{
					Category:       domain.CategorySCA,
					RuleID:         v.ID,
					Title:          fmt.Sprintf("%s in %s", v.ID, p.Package.Name),
					Description:    firstNonEmptyStr(v.Summary, v.Details),
					Severity:       normalizeSeverity(v.DatabaseSpecific.Severity),
					CVE:            cvesFrom(append([]string{v.ID}, v.Aliases...)...),
					Package:        p.Package.Name,
					PackageVersion: p.Package.Version,
					FilePath:       res.Source.Path,
					URL:            "https://osv.dev/vulnerability/" + v.ID,
					Metadata:       map[string]any{"ecosystem": p.Package.Ecosystem},
				}
				f.FixedVersion = osvFixedVersion(v.Affected)
				out = append(out, f)
			}
		}
	}
	return out, nil
}

// osvFixedVersion picks the first "fixed" event OSV records for the package.
func osvFixedVersion(affected []struct {
	Ranges []struct {
		Events []struct {
			Fixed string `json:"fixed"`
		} `json:"events"`
	} `json:"ranges"`
}) string {
	for _, a := range affected {
		for _, rng := range a.Ranges {
			for _, e := range rng.Events {
				if e.Fixed != "" {
					return e.Fixed
				}
			}
		}
	}
	return ""
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
