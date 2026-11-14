package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// BundlerAudit parses `bundle-audit check --format json` (bundler-audit 0.8+),
// matching a Gemfile.lock against ruby-advisory-db. Advisories are keyed by the
// advisory id (a CVE, or a GHSA for advisories without one); severity comes
// from the advisory's criticality, else its CVSS score, else stays unranked.
// An insecure gem source (plain http:// or git://) is reported as its own
// finding: it lets anyone on the path swap the gems you install.
type BundlerAudit struct{}

// NewBundlerAudit constructs a BundlerAudit parser.
func NewBundlerAudit() BundlerAudit { return BundlerAudit{} }

// Scanner returns the tool identifier.
func (BundlerAudit) Scanner() string { return "bundler-audit" }

// PrimaryCategory is the scan-level category for bundler-audit reports.
func (BundlerAudit) PrimaryCategory() domain.Category { return domain.CategorySCA }

type bundlerAuditReport struct {
	Version string `json:"version"`
	Results *[]struct {
		Type string `json:"type"`
		Gem  struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"gem"`
		Source   string `json:"source"`
		Advisory *struct {
			ID              string   `json:"id"`
			URL             string   `json:"url"`
			Title           string   `json:"title"`
			Date            string   `json:"date"`
			Description     string   `json:"description"`
			CVSSv2          *float64 `json:"cvss_v2"`
			CVSSv3          *float64 `json:"cvss_v3"`
			CVE             string   `json:"cve"`
			GHSA            string   `json:"ghsa"`
			Criticality     string   `json:"criticality"`
			PatchedVersions []string `json:"patched_versions"`
		} `json:"advisory"`
	} `json:"results"`
}

// Parse converts a bundler-audit JSON report into findings.
func (BundlerAudit) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report bundlerAuditReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode bundler-audit report: %w", err)
	}
	if report.Results == nil {
		return nil, errors.New(`decode bundler-audit report: no "results" array`)
	}

	out := []ParsedFinding{}
	for _, res := range *report.Results {
		switch res.Type {
		case "insecure_source":
			out = append(out, ParsedFinding{
				Category:    domain.CategorySCA,
				RuleID:      "bundler-audit:insecure-source",
				Title:       "Insecure gem source: " + res.Source,
				Description: "Gems are fetched over an unauthenticated transport (" + res.Source + "); an attacker on the network path can substitute them. Use https://.",
				Severity:    domain.SeverityMedium,
				FilePath:    "Gemfile.lock",
				URL:         res.Source,
				Metadata:    map[string]any{"source": res.Source},
			})
		case "unpatched_gem":
			a := res.Advisory
			if a == nil {
				continue
			}
			ids := []string{a.ID}
			if a.CVE != "" {
				ids = append(ids, "CVE-"+strings.TrimPrefix(strings.ToUpper(a.CVE), "CVE-"))
			}
			f := ParsedFinding{
				Category:       domain.CategorySCA,
				RuleID:         a.ID,
				Title:          fmt.Sprintf("%s in %s: %s", a.ID, res.Gem.Name, a.Title),
				Description:    a.Description,
				Severity:       normalizeSeverity(a.Criticality),
				CVE:            mergeStrings(nil, cvesFrom(ids...)),
				FilePath:       "Gemfile.lock",
				Package:        res.Gem.Name,
				PackageVersion: res.Gem.Version,
				FixedVersion:   strings.Join(a.PatchedVersions, ", "),
				Purl:           ecosystemPurl("gem", res.Gem.Name, res.Gem.Version),
				URL:            a.URL,
				Metadata:       map[string]any{"date": a.Date, "patched_versions": a.PatchedVersions},
			}
			if a.GHSA != "" {
				f.Metadata["ghsa"] = "GHSA-" + strings.TrimPrefix(a.GHSA, "GHSA-")
			}
			score := a.CVSSv3
			if score == nil {
				score = a.CVSSv2
			}
			if score != nil && *score > 0 {
				f.CVSS = floatPtr(*score)
				if a.Criticality == "" {
					f.Severity = severityFromCVSS(*score)
				}
			}
			out = append(out, f)
		}
	}
	return mergeSameLocation(out), nil
}
