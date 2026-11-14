package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/xilasec/xila-api/internal/domain"
)

// Terrascan parses Terrascan's JSON (`terrascan scan -o json`). Only
// `results.violations` are findings — skipped violations were waived in the
// code and passed rules are not issues. The policy id (AC_AWS_0214, or the older
// accurics.gcp.NS.109) is the rule id.
type Terrascan struct{}

// NewTerrascan constructs a Terrascan parser.
func NewTerrascan() Terrascan { return Terrascan{} }

// Scanner returns the tool identifier.
func (Terrascan) Scanner() string { return "terrascan" }

// PrimaryCategory is the scan-level category for Terrascan reports.
func (Terrascan) PrimaryCategory() domain.Category { return domain.CategoryIaC }

type terrascanReport struct {
	Results *struct {
		Violations []struct {
			RuleName     string  `json:"rule_name"`
			Description  string  `json:"description"`
			RuleID       string  `json:"rule_id"`
			Severity     string  `json:"severity"`
			Category     string  `json:"category"`
			ResourceName *string `json:"resource_name"`
			ResourceType *string `json:"resource_type"`
			File         string  `json:"file"`
			PlanRoot     string  `json:"plan_root"`
			Line         int     `json:"line"`
		} `json:"violations"`
	} `json:"results"`
}

// Parse implements Parser.
func (Terrascan) Parse(r io.Reader) ([]ParsedFinding, error) {
	var rep terrascanReport
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode terrascan report: %w", err)
	}
	if rep.Results == nil {
		return nil, errors.New("decode terrascan report: no results object — not a Terrascan JSON report")
	}

	out := make([]ParsedFinding, 0, len(rep.Results.Violations))
	for _, v := range rep.Results.Violations {
		resource := strOrEmpty(v.ResourceType)
		if name := strOrEmpty(v.ResourceName); name != "" && resource != "" {
			resource += "." + name
		} else if name != "" {
			resource = name
		}
		f := ParsedFinding{
			Category:    domain.CategoryIaC,
			RuleID:      firstNonEmpty(v.RuleID, v.RuleName),
			Title:       firstNonEmpty(v.Description, v.RuleName),
			Description: resource,
			Severity:    normalizeSeverity(v.Severity),
			FilePath:    v.File,
			Metadata: map[string]any{
				"rule_name": v.RuleName,
				"category":  v.Category,
				"resource":  resource,
			},
		}
		if v.Line > 0 {
			f.Line = intPtr(v.Line)
		}
		out = append(out, f)
	}
	return out, nil
}
