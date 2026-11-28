package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/xilasec/xila-api/internal/domain"
)

// ESLint parses the output of ESLint's built-in JSON formatter
// (`eslint -f json .`), typically run with security plugins such as
// eslint-plugin-security. Every lint message is a finding at its file and line;
// rule_id is the ESLint rule ("security/detect-object-injection"), or "eslint"
// for parser errors that carry no rule. ESLint severity 2 (error) is medium and
// 1 (warning) low.
type ESLint struct{}

// NewESLint constructs an ESLint parser.
func NewESLint() ESLint { return ESLint{} }

// Scanner returns the tool identifier.
func (ESLint) Scanner() string { return "eslint" }

// PrimaryCategory is the scan-level category for ESLint reports.
func (ESLint) PrimaryCategory() domain.Category { return domain.CategorySAST }

type eslintFile struct {
	FilePath *string `json:"filePath"`
	Messages []struct {
		RuleID    *string `json:"ruleId"`
		Severity  int     `json:"severity"`
		Message   string  `json:"message"`
		Line      int     `json:"line"`
		Column    int     `json:"column"`
		EndLine   int     `json:"endLine"`
		Fatal     bool    `json:"fatal"`
		NodeType  string  `json:"nodeType"`
		MessageID string  `json:"messageId"`
	} `json:"messages"`
}

// Parse converts an ESLint JSON report into findings.
func (ESLint) Parse(r io.Reader) ([]ParsedFinding, error) {
	var files []eslintFile
	if err := json.NewDecoder(r).Decode(&files); err != nil {
		return nil, fmt.Errorf("decode eslint report: %w", err)
	}
	out := []ParsedFinding{}
	for _, file := range files {
		if file.FilePath == nil {
			return nil, errors.New("decode eslint report: entry without filePath")
		}
		for _, m := range file.Messages {
			var sev domain.Severity
			switch m.Severity {
			case 2:
				sev = domain.SeverityMedium
			case 1:
				sev = domain.SeverityLow
			default:
				continue // 0 = rule off
			}
			rule := "eslint"
			if m.RuleID != nil && *m.RuleID != "" {
				rule = *m.RuleID
			}
			f := ParsedFinding{
				Category:    domain.CategorySAST,
				RuleID:      rule,
				Title:       rule + ": " + m.Message,
				Description: m.Message,
				Severity:    sev,
				FilePath:    *file.FilePath,
				Metadata:    map[string]any{"column": m.Column},
			}
			if m.Line > 0 {
				f.Line = new(m.Line)
			}
			if m.EndLine > 0 {
				f.Metadata["end_line"] = m.EndLine
			}
			if m.NodeType != "" {
				f.Metadata["node_type"] = m.NodeType
			}
			if m.Fatal {
				f.Metadata["fatal"] = true
			}
			out = append(out, f)
		}
	}
	return mergeSameLocation(out), nil
}
