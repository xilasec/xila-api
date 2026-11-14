package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/xilasec/xila-api/internal/domain"
)

// PipAudit parses `pip-audit --format json`. Current versions wrap the result
// as {"dependencies":[…],"fixes":[…]}; pip-audit < 2.5 emitted the dependency
// array bare — both are accepted. pip-audit reports PYSEC/GHSA ids with the CVE
// among the aliases (--aliases, on by default for JSON), and rates nothing: it
// has no severity, so findings land as medium (unranked stays visible) until
// EPSS/KEV enrichment prioritizes them by CVE.
type PipAudit struct{}

// NewPipAudit constructs a PipAudit parser.
func NewPipAudit() PipAudit { return PipAudit{} }

// Scanner returns the tool identifier.
func (PipAudit) Scanner() string { return "pip-audit" }

// PrimaryCategory is the scan-level category for pip-audit reports.
func (PipAudit) PrimaryCategory() domain.Category { return domain.CategorySCA }

type pipAuditDep struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	SkipReason string `json:"skip_reason"`
	Vulns      []struct {
		ID          string   `json:"id"`
		FixVersions []string `json:"fix_versions"`
		Aliases     []string `json:"aliases"`
		Description string   `json:"description"`
	} `json:"vulns"`
}

// Parse converts a pip-audit JSON report into findings.
func (PipAudit) Parse(r io.Reader) ([]ParsedFinding, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read pip-audit report: %w", err)
	}
	var deps []pipAuditDep
	if data = bytes.TrimSpace(data); len(data) > 0 && data[0] == '[' {
		err = json.Unmarshal(data, &deps)
	} else {
		var doc struct {
			Dependencies *[]pipAuditDep `json:"dependencies"`
		}
		if err = json.Unmarshal(data, &doc); err == nil {
			if doc.Dependencies == nil {
				return nil, fmt.Errorf(`decode pip-audit report: no "dependencies" array`)
			}
			deps = *doc.Dependencies
		}
	}
	if err != nil {
		return nil, fmt.Errorf("decode pip-audit report: %w", err)
	}

	out := []ParsedFinding{}
	for _, d := range deps {
		if d.Name == "" {
			return nil, fmt.Errorf("pip-audit report: dependency without a name (not pip-audit JSON?)")
		}
		// pip-audit can list the same advisory twice for one package (once per
		// source it was found in); one finding per package+advisory.
		seen := map[string]bool{}
		for _, v := range d.Vulns {
			if seen[v.ID] {
				continue
			}
			seen[v.ID] = true
			out = append(out, ParsedFinding{
				Category:       domain.CategorySCA,
				RuleID:         v.ID,
				Title:          fmt.Sprintf("%s in %s", v.ID, d.Name),
				Description:    v.Description,
				Severity:       normalizeSeverity(""),
				CVE:            cvesFrom(append([]string{v.ID}, v.Aliases...)...),
				Package:        d.Name,
				PackageVersion: d.Version,
				FixedVersion:   nearestFix(d.Version, v.FixVersions),
				Purl:           ecosystemPurl("pypi", d.Name, d.Version),
				URL:            "https://osv.dev/vulnerability/" + v.ID,
				Metadata:       map[string]any{"aliases": v.Aliases, "fix_versions": v.FixVersions},
			})
		}
	}
	return mergeSameLocation(out), nil
}
