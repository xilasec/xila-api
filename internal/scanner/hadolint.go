package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Hadolint parses the JSON output of the Hadolint Dockerfile linter
// (`hadolint -f json Dockerfile`): a flat array of rule violations, each with
// its rule code (DL3008, SC2086), file, line and level.
//
// Hadolint's levels are lint levels, not risk ratings, so they are mapped
// conservatively: "error" is medium, "warning" low, and "info"/"style" notes
// are skipped — they are style advice, not security findings.
type Hadolint struct{}

// NewHadolint constructs a Hadolint parser.
func NewHadolint() Hadolint { return Hadolint{} }

// Scanner returns the tool identifier.
func (Hadolint) Scanner() string { return "hadolint" }

// PrimaryCategory is the scan-level category for Hadolint reports.
func (Hadolint) PrimaryCategory() domain.Category { return domain.CategoryIaC }

type hadolintIssue struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Column  int    `json:"column"`
	Level   string `json:"level"`
}

// Parse converts a Hadolint JSON report into findings.
func (Hadolint) Parse(r io.Reader) ([]ParsedFinding, error) {
	var issues []hadolintIssue
	if err := json.NewDecoder(r).Decode(&issues); err != nil {
		return nil, fmt.Errorf("decode hadolint report: %w", err)
	}
	out := []ParsedFinding{}
	for _, is := range issues {
		if is.Code == "" || is.Level == "" {
			return nil, errors.New("decode hadolint report: entry without code/level")
		}
		var sev domain.Severity
		switch strings.ToLower(is.Level) {
		case "error":
			sev = domain.SeverityMedium
		case "warning":
			sev = domain.SeverityLow
		case "info", "style", "ignore", "none":
			continue
		default:
			sev = normalizeSeverity(is.Level)
		}
		f := ParsedFinding{
			Category:    domain.CategoryIaC,
			RuleID:      is.Code,
			Title:       is.Code + ": " + is.Message,
			Description: is.Message,
			Severity:    sev,
			FilePath:    is.File,
			Metadata: map[string]any{
				"level":      is.Level,
				"references": hadolintRuleURL(is.Code),
			},
		}
		if is.Line > 0 {
			f.Line = intPtr(is.Line)
		}
		if is.Column > 0 {
			f.Metadata["column"] = is.Column
		}
		out = append(out, f)
	}
	return mergeSameLocation(out), nil
}

// hadolintRuleURL links a rule to its documentation: DL rules live in the
// Hadolint wiki, SC rules are ShellCheck's.
func hadolintRuleURL(code string) string {
	if strings.HasPrefix(code, "SC") {
		return "https://www.shellcheck.net/wiki/" + code
	}
	return "https://github.com/hadolint/hadolint/wiki/" + code
}
