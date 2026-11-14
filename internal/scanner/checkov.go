package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Checkov parses Checkov's native JSON (`checkov -d . -o json`). Checkov emits
// one report object when a single framework ran and a JSON array of them when
// several did (terraform + dockerfile + …); both are accepted. Only failed
// checks become findings, and the check id (CKV_AWS_161) is the rule_id so it
// can be mapped to compliance controls.
//
// Unlike the SARIF path, the native format keeps the check's severity (when the
// platform supplies one), the benchmark references and, for Checkov's SCA
// frameworks, the package, version, fix and CVE of each vulnerability.
type Checkov struct{}

// NewCheckov constructs a Checkov parser.
func NewCheckov() Checkov { return Checkov{} }

// Scanner returns the tool identifier.
func (Checkov) Scanner() string { return "checkov" }

// PrimaryCategory is the scan-level category for Checkov reports.
func (Checkov) PrimaryCategory() domain.Category { return domain.CategoryIaC }

type checkovReport struct {
	CheckType string `json:"check_type"`
	Results   *struct {
		FailedChecks []checkovCheck `json:"failed_checks"`
	} `json:"results"`
	// An empty run prints only the bare summary counters ("passed", "failed", …).
	Failed         *int   `json:"failed"`
	CheckovVersion string `json:"checkov_version"`
}

type checkovCheck struct {
	CheckID       string          `json:"check_id"`
	BCCheckID     string          `json:"bc_check_id"`
	CheckName     string          `json:"check_name"`
	FilePath      string          `json:"file_path"`
	FileLineRange []int           `json:"file_line_range"`
	Resource      string          `json:"resource"`
	Severity      *string         `json:"severity"`
	Guideline     string          `json:"guideline"`
	Description   *string         `json:"description"`
	BCCategory    *string         `json:"bc_category"`
	Benchmarks    json.RawMessage `json:"benchmarks"`
	CheckResult   struct {
		Result        string   `json:"result"`
		EvaluatedKeys []string `json:"evaluated_keys"`
	} `json:"check_result"`
	VulnerabilityDetails *struct {
		ID                 string   `json:"id"`
		PackageName        string   `json:"package_name"`
		PackageVersion     string   `json:"package_version"`
		LowestFixedVersion string   `json:"lowest_fixed_version"`
		FixedVersion       string   `json:"fixed_version"`
		CVSS               *float64 `json:"cvss"`
		Link               string   `json:"link"`
		Description        string   `json:"description"`
	} `json:"vulnerability_details"`
}

// Parse implements Parser.
func (Checkov) Parse(r io.Reader) ([]ParsedFinding, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read checkov report: %w", err)
	}
	var reports []checkovReport
	if trimmed := bytes.TrimSpace(raw); len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &reports); err != nil {
			return nil, fmt.Errorf("decode checkov report: %w", err)
		}
	} else {
		var one checkovReport
		if err := json.Unmarshal(trimmed, &one); err != nil {
			return nil, fmt.Errorf("decode checkov report: %w", err)
		}
		reports = []checkovReport{one}
	}

	var out []ParsedFinding
	for _, rep := range reports {
		if rep.Results == nil {
			if rep.Failed == nil && rep.CheckovVersion == "" {
				return nil, errors.New("decode checkov report: no check_type/results — not a Checkov JSON report")
			}
			continue // an empty run: summary counters only
		}
		for _, c := range rep.Results.FailedChecks {
			if !strings.EqualFold(c.CheckResult.Result, "FAILED") {
				continue
			}
			out = append(out, checkovFinding(rep.CheckType, c))
		}
	}
	return out, nil
}

func checkovFinding(checkType string, c checkovCheck) ParsedFinding {
	f := ParsedFinding{
		Category:    checkovCategory(checkType),
		RuleID:      c.CheckID,
		Title:       firstNonEmpty(c.CheckName, c.CheckID),
		Description: c.Resource,
		Severity:    normalizeSeverity(strOrEmpty(c.Severity)), // null without a platform key → medium
		FilePath:    strings.TrimPrefix(c.FilePath, "/"),
		URL:         c.Guideline,
		Metadata: map[string]any{
			"check_type": checkType,
			"resource":   c.Resource,
		},
	}
	if d := strOrEmpty(c.Description); d != "" {
		f.Description = strings.TrimSpace(d + "\n" + c.Resource)
	}
	if len(c.FileLineRange) > 0 && c.FileLineRange[0] > 0 {
		f.Line = intPtr(c.FileLineRange[0])
	}
	if c.BCCheckID != "" {
		f.Metadata["bc_check_id"] = c.BCCheckID
	}
	if cat := strOrEmpty(c.BCCategory); cat != "" {
		f.Metadata["bc_category"] = cat
	}
	if len(c.CheckResult.EvaluatedKeys) > 0 {
		f.Metadata["evaluated_keys"] = c.CheckResult.EvaluatedKeys
	}
	if len(c.Benchmarks) > 0 && string(c.Benchmarks) != "null" {
		var b map[string]any
		if json.Unmarshal(c.Benchmarks, &b) == nil && len(b) > 0 {
			f.Metadata["benchmarks"] = b
		}
	}
	if v := c.VulnerabilityDetails; v != nil {
		// Checkov's SCA frameworks name the check CKV_CVE_2022_1234 — the CVE
		// itself lives in vulnerability_details and is what dedup groups on.
		f.CVE = cvesFrom(v.ID)
		f.Package = v.PackageName
		f.PackageVersion = v.PackageVersion
		f.FixedVersion = firstNonEmpty(v.LowestFixedVersion, v.FixedVersion)
		f.URL = firstNonEmpty(v.Link, f.URL)
		if v.CVSS != nil && *v.CVSS > 0 {
			f.CVSS = floatPtr(*v.CVSS)
		}
		if v.Description != "" {
			f.Description = v.Description
		}
		if v.ID != "" {
			f.Title = fmt.Sprintf("%s in %s", v.ID, v.PackageName)
		}
	}
	return f
}

// checkovCategory maps Checkov's framework (check_type) onto our categories.
func checkovCategory(checkType string) domain.Category {
	switch t := strings.ToLower(checkType); {
	case t == "secrets":
		return domain.CategorySecret
	case t == "sca_image":
		return domain.CategoryContainer
	case strings.HasPrefix(t, "sca_"):
		return domain.CategorySCA
	default: // terraform, cloudformation, kubernetes, helm, dockerfile, arm, …
		return domain.CategoryIaC
	}
}

// strOrEmpty reads an optional (JSON null-able) string.
func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
