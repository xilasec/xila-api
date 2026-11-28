package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Nancy parses Sonatype Nancy's `nancy sleuth --output=json` report — the Go
// module vulnerability scanner that checks a go.sum/go.list against OSS
// Index. The report lists every audited coordinate three ways: "audited"
// repeats all of them (vulnerable or not), "invalid" is coordinates Nancy
// couldn't parse (an invalid semver), and "vulnerable" is the subset with at
// least one vulnerability — only that last one is a finding.
type Nancy struct{}

// NewNancy constructs a Nancy parser.
func NewNancy() Nancy { return Nancy{} }

// Scanner returns the tool identifier.
func (Nancy) Scanner() string { return "nancy" }

// PrimaryCategory is the scan-level category for Nancy reports.
func (Nancy) PrimaryCategory() domain.Category { return domain.CategorySCA }

type nancyReport struct {
	Vulnerable []nancyPackage `json:"vulnerable"`
}

type nancyPackage struct {
	Coordinates     string      `json:"Coordinates"`
	Vulnerabilities []nancyVuln `json:"Vulnerabilities"`
}

type nancyVuln struct {
	ID          string `json:"Id"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	CvssScore   string `json:"CvssScore"`
	CvssVector  string `json:"CvssVector"`
	Cve         string `json:"Cve"`
	Reference   string `json:"Reference"`
	Excluded    bool   `json:"Excluded"`
}

// Parse implements Parser.
func (Nancy) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report nancyReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode nancy report: %w", err)
	}
	if report.Vulnerable == nil {
		return nil, errors.New(`decode nancy report: no "vulnerable" array — not a nancy sleuth JSON report`)
	}

	out := []ParsedFinding{}
	for _, pkg := range report.Vulnerable {
		name, version := splitGoPurl(pkg.Coordinates)
		for _, v := range pkg.Vulnerabilities {
			if v.Excluded {
				continue // excluded via a .nancy-ignore rule: not a finding
			}
			score, _ := strconv.ParseFloat(v.CvssScore, 64)
			f := ParsedFinding{
				Category:       domain.CategorySCA,
				RuleID:         v.ID,
				Title:          v.Title,
				Description:    v.Description,
				Severity:       severityFromCVSS(score),
				CVE:            cvesFrom(v.Cve),
				Package:        name,
				PackageVersion: version,
				Purl:           pkg.Coordinates,
				URL:            v.Reference,
				Metadata:       map[string]any{"cvss_vector": v.CvssVector},
			}
			if score > 0 {
				f.CVSS = new(score)
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// splitGoPurl extracts the module path and version from the purl-shaped
// coordinates Nancy reports ("pkg:golang/github.com/foo/bar@1.2.3"): the
// segment between the type and the version is the module import path, which
// Nancy never breaks out into separate fields of its own.
func splitGoPurl(coordinates string) (name, version string) {
	rest, ok := strings.CutPrefix(coordinates, "pkg:golang/")
	if !ok {
		return coordinates, ""
	}
	name, version, _ = strings.Cut(rest, "@")
	return name, version
}
