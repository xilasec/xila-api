package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Tfsec parses tfsec's JSON (`tfsec . --format json`). Both the current schema
// (rule_id "aws-vpc-no-public-egress-sgr" + legacy_rule_id, "status") and the
// legacy one (rule_id "AWS007", "passed") are accepted. The rule id is the
// rule_id; passed and ignored results are not findings.
type Tfsec struct{}

// NewTfsec constructs a tfsec parser.
func NewTfsec() Tfsec { return Tfsec{} }

// Scanner returns the tool identifier.
func (Tfsec) Scanner() string { return "tfsec" }

// PrimaryCategory is the scan-level category for tfsec reports.
func (Tfsec) PrimaryCategory() domain.Category { return domain.CategoryIaC }

type tfsecReport struct {
	Results *[]struct {
		RuleID          string   `json:"rule_id"`
		LegacyRuleID    string   `json:"legacy_rule_id"`
		LongID          string   `json:"long_id"`
		RuleDescription string   `json:"rule_description"`
		RuleProvider    string   `json:"rule_provider"`
		RuleService     string   `json:"rule_service"`
		Impact          string   `json:"impact"`
		Resolution      string   `json:"resolution"`
		Links           []string `json:"links"`
		Link            string   `json:"link"`
		Description     string   `json:"description"`
		Severity        string   `json:"severity"`
		Status          string   `json:"status"` // "failed" | "passed" | "ignored" (current)
		Passed          bool     `json:"passed"` // legacy
		Resource        string   `json:"resource"`
		Location        struct {
			Filename  string `json:"filename"`
			StartLine int    `json:"start_line"`
			EndLine   int    `json:"end_line"`
		} `json:"location"`
	} `json:"results"`
}

// Parse implements Parser.
func (Tfsec) Parse(r io.Reader) ([]ParsedFinding, error) {
	var raw map[string]json.RawMessage
	if err := json.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decode tfsec report: %w", err)
	}
	if _, ok := raw["results"]; !ok {
		return nil, errors.New("decode tfsec report: no results key — not a tfsec JSON report")
	}
	var rep tfsecReport
	if err := json.Unmarshal(raw["results"], &rep.Results); err != nil {
		return nil, fmt.Errorf("decode tfsec report: %w", err)
	}
	if rep.Results == nil { // "results": null — a clean run
		return nil, nil
	}

	var out []ParsedFinding
	for _, res := range *rep.Results {
		if res.Passed || (res.Status != "" && !strings.EqualFold(res.Status, "failed")) {
			continue
		}
		f := ParsedFinding{
			Category:    domain.CategoryIaC,
			RuleID:      firstNonEmpty(res.RuleID, res.LongID, res.LegacyRuleID),
			Title:       firstNonEmpty(res.RuleDescription, res.RuleID),
			Description: strings.TrimSpace(res.Description + "\n" + res.Impact),
			Severity:    normalizeSeverity(res.Severity), // CRITICAL/HIGH/MEDIUM/LOW; legacy ERROR/WARNING/INFO
			FilePath:    res.Location.Filename,
			URL:         tfsecLegacyLink(res.Link),
			Metadata: map[string]any{
				"provider":   res.RuleProvider,
				"resolution": res.Resolution,
			},
		}
		if len(res.Links) > 0 {
			f.URL = res.Links[0]
		}
		if res.Location.StartLine > 0 {
			f.Line = intPtr(res.Location.StartLine)
		}
		if res.LegacyRuleID != "" && res.LegacyRuleID != f.RuleID {
			f.Metadata["legacy_rule_id"] = res.LegacyRuleID
		}
		if res.Resource != "" {
			f.Metadata["resource"] = res.Resource
		}
		if res.RuleService != "" {
			f.Metadata["service"] = res.RuleService
		}
		out = append(out, f)
	}
	return out, nil
}

// tfsecLegacyLink extracts the URL from the legacy prose form
// "See https://tfsec.dev/docs/general/GEN003/ for more information.".
func tfsecLegacyLink(s string) string {
	for _, field := range strings.Fields(s) {
		if strings.HasPrefix(field, "http://") || strings.HasPrefix(field, "https://") {
			return field
		}
	}
	return ""
}
