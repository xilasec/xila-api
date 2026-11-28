package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// DependencyCheck parses OWASP Dependency-Check's JSON report — the SCA scanner
// most entrenched in Java/enterprise builds.
type DependencyCheck struct{}

// NewDependencyCheck constructs a DependencyCheck parser.
func NewDependencyCheck() DependencyCheck { return DependencyCheck{} }

// Scanner returns the tool identifier.
func (DependencyCheck) Scanner() string { return "dependency-check" }

// PrimaryCategory is the scan-level category for Dependency-Check reports.
func (DependencyCheck) PrimaryCategory() domain.Category { return domain.CategorySCA }

type depCheckReport struct {
	Dependencies []struct {
		FileName string `json:"fileName"`
		FilePath string `json:"filePath"`
		Packages []struct {
			ID string `json:"id"` // a PURL
		} `json:"packages"`
		Vulnerabilities []struct {
			Name        string `json:"name"`
			Severity    string `json:"severity"`
			Description string `json:"description"`
			CvssV3      struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"cvssv3"`
			CvssV2 struct {
				Score float64 `json:"score"`
			} `json:"cvssv2"`
			Cwes []string `json:"cwes"`
		} `json:"vulnerabilities"`
	} `json:"dependencies"`
}

// Parse converts a Dependency-Check report into findings.
func (DependencyCheck) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report depCheckReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode dependency-check report: %w", err)
	}

	var out []ParsedFinding
	for _, dep := range report.Dependencies {
		var purl string
		if len(dep.Packages) > 0 {
			purl = dep.Packages[0].ID
		}
		name, version := purlNameVersion(purl, dep.FileName)

		for _, v := range dep.Vulnerabilities {
			score := v.CvssV3.BaseScore
			if score == 0 {
				score = v.CvssV2.Score
			}
			sev := normalizeSeverity(v.Severity)
			if v.Severity == "" && score > 0 {
				sev = severityFromCVSS(score)
			}

			f := ParsedFinding{
				Category:       domain.CategorySCA,
				RuleID:         v.Name,
				Title:          fmt.Sprintf("%s in %s", v.Name, name),
				Description:    v.Description,
				Severity:       sev,
				CVE:            cvesFrom(v.Name),
				Package:        name,
				PackageVersion: version,
				Purl:           purl,
				FilePath:       dep.FilePath,
			}
			if len(v.Cwes) > 0 {
				f.CWE = cweFrom(v.Cwes[0])
			}
			if score > 0 {
				f.CVSS = new(score)
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// purlNameVersion pulls the package name + version out of a PURL, falling back
// to the jar/file name Dependency-Check reports when there is no PURL.
func purlNameVersion(purl, fallback string) (string, string) {
	if purl == "" {
		return fallback, ""
	}
	body := strings.TrimPrefix(purl, "pkg:")
	if i := strings.Index(body, "?"); i >= 0 {
		body = body[:i]
	}
	name, version, _ := strings.Cut(body, "@")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if name == "" {
		return fallback, version
	}
	return name, version
}
