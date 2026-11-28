package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Safety parses Safety's report JSON — `safety check --output json` (Safety 2.x,
// still available in 3.x). That format carries the CVE, CVSS and fix versions.
// Safety 3's `safety scan --output json` is a different schema that names only
// PyUp ids (no CVE or severity unless the run is authenticated and detailed),
// so it is rejected with a pointer to `safety check` rather than imported as
// unranked, un-dedupable findings.
//
// Vulnerabilities ignored by a Safety policy are imported as risk_accepted with
// the policy's reason and expiry (see setImportedStatus), so a migration keeps
// the decision instead of resurfacing it.
type Safety struct{}

// NewSafety constructs a Safety parser.
func NewSafety() Safety { return Safety{} }

// Scanner returns the tool identifier.
func (Safety) Scanner() string { return "safety" }

// PrimaryCategory is the scan-level category for Safety reports.
func (Safety) PrimaryCategory() domain.Category { return domain.CategorySCA }

type safetyReport struct {
	Vulnerabilities  *[]safetyVuln `json:"vulnerabilities"`
	AffectedPackages map[string]struct {
		Found string `json:"found"`
	} `json:"affected_packages"`
	ScanResults json.RawMessage `json:"scan_results"`
}

type safetyVuln struct {
	VulnerabilityID string          `json:"vulnerability_id"`
	PackageName     string          `json:"package_name"`
	AnalyzedVersion string          `json:"analyzed_version"`
	Advisory        string          `json:"advisory"`
	FixedVersions   []string        `json:"fixed_versions"`
	VulnerableSpec  flexStrings     `json:"vulnerable_spec"`
	CVE             json.RawMessage `json:"CVE"`
	Severity        json.RawMessage `json:"severity"`
	MoreInfoURL     string          `json:"more_info_url"`
	IsTransitive    bool            `json:"is_transitive"`
	Ignored         bool            `json:"ignored"`
	IgnoredReason   string          `json:"ignored_reason"`
	IgnoredExpires  string          `json:"ignored_expires"`
}

// safetyScore is the CVSS block Safety attaches to either "CVE" or "severity".
type safetyScore struct {
	Name   string `json:"name"`
	Source string `json:"source"`
	CVSSv3 *struct {
		BaseScore    float64 `json:"base_score"`
		BaseSeverity string  `json:"base_severity"`
	} `json:"cvssv3"`
	CVSSv2 *struct {
		BaseScore float64 `json:"base_score"`
	} `json:"cvssv2"`
}

// Parse converts a Safety JSON report into findings.
func (Safety) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report safetyReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode safety report: %w", err)
	}
	if report.Vulnerabilities == nil {
		if len(report.ScanResults) > 0 {
			return nil, errors.New("safety report: `safety scan` JSON is not supported (it carries no CVE or severity); upload `safety check --output json` instead")
		}
		return nil, errors.New(`decode safety report: no "vulnerabilities" array`)
	}

	out := []ParsedFinding{}
	seen := map[string]bool{}
	for _, v := range *report.Vulnerabilities {
		if v.VulnerabilityID == "" {
			return nil, errors.New("safety report: vulnerability without vulnerability_id (not safety JSON?)")
		}
		key := v.PackageName + "\x00" + v.AnalyzedVersion + "\x00" + v.VulnerabilityID
		if seen[key] {
			continue
		}
		seen[key] = true

		cveID, cveScore := safetyCVE(v.CVE)
		sevText, sevScore := safetySeverity(v.Severity)
		score := sevScore
		if score == nil {
			score = cveScore
		}
		f := ParsedFinding{
			Category:       domain.CategorySCA,
			RuleID:         "PYUP-" + v.VulnerabilityID,
			Title:          fmt.Sprintf("PYUP-%s in %s", v.VulnerabilityID, v.PackageName),
			Description:    v.Advisory,
			Severity:       normalizeSeverity(sevText),
			CVE:            cvesFrom(cveID),
			FilePath:       report.AffectedPackages[v.PackageName].Found,
			Package:        v.PackageName,
			PackageVersion: v.AnalyzedVersion,
			FixedVersion:   nearestFix(v.AnalyzedVersion, v.FixedVersions),
			Purl:           ecosystemPurl("pypi", v.PackageName, v.AnalyzedVersion),
			URL:            v.MoreInfoURL,
			CVSS:           score,
			Metadata: map[string]any{
				"vulnerable_spec": []string(v.VulnerableSpec),
				"transitive":      v.IsTransitive,
			},
		}
		if sevText == "" && score != nil {
			f.Severity = severityFromCVSS(*score)
		}
		if v.Ignored {
			reason := "ignored by Safety policy"
			if v.IgnoredReason != "" {
				reason += ": " + v.IgnoredReason
			}
			setImportedStatus(f.Metadata, domain.FindingRiskAccepted, reason, parseLooseTime(v.IgnoredExpires))
		}
		out = append(out, f)
	}
	return mergeSameLocation(out), nil
}

// safetyCVE reads the "CVE" field, which Safety writes as null, a bare id, or
// an object carrying the id and its CVSS scores.
func safetyCVE(raw json.RawMessage) (string, *float64) {
	var id string
	if err := json.Unmarshal(raw, &id); err == nil {
		return id, nil
	}
	var s safetyScore
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", nil
	}
	return s.Name, s.score()
}

// safetySeverity reads the "severity" field: null, a rating word, or an object
// with CVSS v3/v2 scores.
func safetySeverity(raw json.RawMessage) (string, *float64) {
	var word string
	if err := json.Unmarshal(raw, &word); err == nil {
		return word, nil
	}
	var s safetyScore
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", nil
	}
	if s.CVSSv3 != nil && s.CVSSv3.BaseSeverity != "" {
		return strings.ToLower(s.CVSSv3.BaseSeverity), s.score()
	}
	return "", s.score()
}

func (s safetyScore) score() *float64 {
	switch {
	case s.CVSSv3 != nil && s.CVSSv3.BaseScore > 0:
		return new(s.CVSSv3.BaseScore)
	case s.CVSSv2 != nil && s.CVSSv2.BaseScore > 0:
		return new(s.CVSSv2.BaseScore)
	}
	return nil
}
