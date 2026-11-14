package scanner

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/xilasec/xila-api/internal/domain"
)

// NpmAudit parses `npm audit --json` (npm 7+ / "audit report v2"). It is the
// scanner every JavaScript project already runs, with no extra tooling to install.
type NpmAudit struct{}

// NewNpmAudit constructs an NpmAudit parser.
func NewNpmAudit() NpmAudit { return NpmAudit{} }

// Scanner returns the tool identifier.
func (NpmAudit) Scanner() string { return "npm-audit" }

// PrimaryCategory is the scan-level category for npm audit reports.
func (NpmAudit) PrimaryCategory() domain.Category { return domain.CategorySCA }

type npmAuditReport struct {
	// Keyed by package name.
	Vulnerabilities map[string]struct {
		Name         string            `json:"name"`
		Severity     string            `json:"severity"`
		Range        string            `json:"range"`
		Via          []json.RawMessage `json:"via"`
		FixAvailable json.RawMessage   `json:"fixAvailable"`
	} `json:"vulnerabilities"`
}

// npmVia is the object form of an entry in "via": the advisory itself. A string
// entry means the package is only vulnerable *through* another package — the
// advisory is reported on that one, so we don't duplicate it here.
type npmVia struct {
	Source   int      `json:"source"`
	Name     string   `json:"name"`
	Title    string   `json:"title"`
	URL      string   `json:"url"`
	Severity string   `json:"severity"`
	CWE      []string `json:"cwe"`
	CVSS     struct {
		Score float64 `json:"score"`
	} `json:"cvss"`
	Range string `json:"range"`
}

// Parse converts an npm audit report into findings.
func (NpmAudit) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report npmAuditReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode npm audit report: %w", err)
	}

	var out []ParsedFinding
	for pkg, v := range report.Vulnerabilities {
		for _, raw := range v.Via {
			var via npmVia
			if err := json.Unmarshal(raw, &via); err != nil || via.Title == "" {
				// A string entry: this package is vulnerable only because a dependency
				// is. The advisory is already reported against that dependency, so
				// emitting it again here would be a duplicate of the same issue.
				continue
			}

			sev := normalizeSeverity(firstNonEmptyStr(via.Severity, v.Severity))
			f := ParsedFinding{
				Category:       domain.CategorySCA,
				RuleID:         npmAdvisoryID(via),
				Title:          via.Title,
				Severity:       sev,
				Package:        firstNonEmptyStr(via.Name, v.Name, pkg),
				PackageVersion: firstNonEmptyStr(via.Range, v.Range),
				URL:            via.URL,
				Purl:           "pkg:npm/" + firstNonEmptyStr(via.Name, pkg),
				Metadata:       map[string]any{"vulnerable_range": v.Range},
			}
			if len(via.CWE) > 0 {
				f.CWE = cweFrom(via.CWE[0])
			}
			if via.CVSS.Score > 0 {
				f.CVSS = floatPtr(via.CVSS.Score)
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// npmAdvisoryID gives the finding a stable rule id. npm reports its own numeric
// advisory ids; the URL carries the same number and is what a human recognizes.
func npmAdvisoryID(via npmVia) string {
	if via.Source > 0 {
		return fmt.Sprintf("NPM-%d", via.Source)
	}
	return via.Title
}
