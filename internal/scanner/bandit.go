package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Bandit parses `bandit -f json` (Python SAST). Bandit rates each issue's severity
// and, separately, its confidence that the match is real; the severity is
// kept as reported and the confidence goes to metadata, where triage rules and
// humans can weigh it. The CWE (Bandit 1.7.3+) and the test id are kept.
type Bandit struct{}

// NewBandit constructs a Bandit parser.
func NewBandit() Bandit { return Bandit{} }

// Scanner returns the tool identifier.
func (Bandit) Scanner() string { return "bandit" }

// PrimaryCategory is the scan-level category for Bandit reports.
func (Bandit) PrimaryCategory() domain.Category { return domain.CategorySAST }

type banditReport struct {
	Results *[]struct {
		Code            string `json:"code"`
		Filename        string `json:"filename"`
		IssueConfidence string `json:"issue_confidence"`
		IssueSeverity   string `json:"issue_severity"`
		IssueCWE        *struct {
			ID   int    `json:"id"`
			Link string `json:"link"`
		} `json:"issue_cwe"`
		IssueText  string `json:"issue_text"`
		LineNumber int    `json:"line_number"`
		MoreInfo   string `json:"more_info"`
		TestID     string `json:"test_id"`
		TestName   string `json:"test_name"`
	} `json:"results"`
}

// Parse converts a Bandit JSON report into findings.
func (Bandit) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report banditReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode bandit report: %w", err)
	}
	if report.Results == nil {
		return nil, errors.New(`decode bandit report: no "results" array`)
	}

	out := make([]ParsedFinding, 0, len(*report.Results))
	for i, res := range *report.Results {
		if res.TestID == "" {
			return nil, fmt.Errorf("bandit report: result %d has no test_id (not bandit -f json output?)", i)
		}
		f := ParsedFinding{
			Category:    domain.CategorySAST,
			RuleID:      res.TestID,
			Title:       fmt.Sprintf("%s: %s", res.TestID, strings.TrimSpace(res.IssueText)),
			Description: strings.TrimSpace(res.IssueText),
			Severity:    normalizeSeverity(res.IssueSeverity),
			FilePath:    strings.ReplaceAll(res.Filename, `\`, "/"),
			URL:         res.MoreInfo,
			Metadata: map[string]any{
				"test_name":  res.TestName,
				"confidence": strings.ToLower(res.IssueConfidence),
				"code":       res.Code,
			},
		}
		if res.IssueCWE != nil && res.IssueCWE.ID > 0 {
			f.CWE = new(res.IssueCWE.ID)
		}
		if res.LineNumber > 0 {
			f.Line = new(res.LineNumber)
		}
		out = append(out, f)
	}
	return mergeSameLocation(out), nil
}
