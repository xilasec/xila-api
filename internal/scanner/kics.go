package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// KICS parses the JSON report of Checkmarx KICS (`kics scan -p <dir>
// --report-formats json -o <out>`, results.json). Each query lists every file
// location it matched; each location is one finding whose rule_id is the
// query id (a UUID). INFO and TRACE queries are skipped. Several matches of one
// query on the same line (one per offending RBAC verb, say) are folded together.
type KICS struct{}

// NewKICS constructs a KICS parser.
func NewKICS() KICS { return KICS{} }

// Scanner returns the tool identifier.
func (KICS) Scanner() string { return "kics" }

// PrimaryCategory is the scan-level category for KICS reports.
func (KICS) PrimaryCategory() domain.Category { return domain.CategoryIaC }

type kicsReport struct {
	Queries *[]kicsQuery `json:"queries"`
}

type kicsQuery struct {
	QueryName   string `json:"query_name"`
	QueryID     string `json:"query_id"`
	QueryURL    string `json:"query_url"`
	Severity    string `json:"severity"`
	Platform    string `json:"platform"`
	Category    string `json:"category"`
	Description string `json:"description"`
	CWE         string `json:"cwe"`
	Files       []struct {
		FileName      string  `json:"file_name"`
		SimilarityID  string  `json:"similarity_id"`
		Line          int     `json:"line"`
		IssueType     string  `json:"issue_type"`
		SearchKey     string  `json:"search_key"`
		ExpectedValue *string `json:"expected_value"`
		ActualValue   *string `json:"actual_value"`
	} `json:"files"`
}

// Parse converts a KICS JSON report into findings.
func (KICS) Parse(r io.Reader) ([]ParsedFinding, error) {
	var rep kicsReport
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode kics report: %w", err)
	}
	if rep.Queries == nil {
		return nil, errors.New("decode kics report: no queries array")
	}
	out := []ParsedFinding{}
	for _, q := range *rep.Queries {
		switch strings.ToUpper(q.Severity) {
		case "INFO", "TRACE":
			continue
		}
		for _, loc := range q.Files {
			expected, actual := kicsStr(loc.ExpectedValue), kicsStr(loc.ActualValue)
			desc := q.Description
			if expected != "" {
				desc += "\nExpected: " + expected
			}
			if actual != "" {
				desc += "\nActual: " + actual
			}
			f := ParsedFinding{
				Category:    domain.CategoryIaC,
				RuleID:      q.QueryID,
				Title:       q.QueryName,
				Description: strings.TrimSpace(desc),
				Severity:    normalizeSeverity(q.Severity),
				CWE:         cweFrom(q.CWE),
				FilePath:    loc.FileName,
				Metadata: map[string]any{
					"platform":       q.Platform,
					"kics_category":  q.Category,
					"issue_type":     loc.IssueType,
					"search_key":     loc.SearchKey,
					"expected_value": expected,
					"actual_value":   actual,
					"similarity_id":  loc.SimilarityID,
					"references":     q.QueryURL,
				},
			}
			if loc.Line > 0 {
				f.Line = new(loc.Line)
			}
			out = append(out, f)
		}
	}
	return mergeSameLocation(out), nil
}

func kicsStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
