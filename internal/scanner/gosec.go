package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Gosec parses `gosec -fmt json` (Go SAST). The rule id (G101…), CWE, severity
// and confidence map directly. Issues suppressed in source — `#nosec` with
// -track-suppressions, or an external exclusion — are imported as false
// positives carrying the developer's justification, so the audit trail shows
// who silenced what and why instead of the finding silently vanishing.
type Gosec struct{}

// NewGosec constructs a Gosec parser.
func NewGosec() Gosec { return Gosec{} }

// Scanner returns the tool identifier.
func (Gosec) Scanner() string { return "gosec" }

// PrimaryCategory is the scan-level category for gosec reports.
func (Gosec) PrimaryCategory() domain.Category { return domain.CategorySAST }

type gosecReport struct {
	Issues *[]struct {
		Severity   string `json:"severity"`
		Confidence string `json:"confidence"`
		CWE        *struct {
			ID  flexInt `json:"id"`
			URL string  `json:"url"`
		} `json:"cwe"`
		RuleID       string `json:"rule_id"`
		Details      string `json:"details"`
		File         string `json:"file"`
		Code         string `json:"code"`
		Line         string `json:"line"`
		Column       string `json:"column"`
		NoSec        bool   `json:"nosec"`
		Suppressions []struct {
			Kind          string `json:"kind"`
			Justification string `json:"justification"`
		} `json:"suppressions"`
	} `json:"Issues"`
	GosecVersion string `json:"GosecVersion"`
}

// Parse converts a gosec JSON report into findings.
func (Gosec) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report gosecReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode gosec report: %w", err)
	}
	if report.Issues == nil {
		return nil, errors.New(`decode gosec report: no "Issues" array`)
	}

	out := make([]ParsedFinding, 0, len(*report.Issues))
	for _, is := range *report.Issues {
		f := ParsedFinding{
			Category:    domain.CategorySAST,
			RuleID:      is.RuleID,
			Title:       fmt.Sprintf("%s: %s", is.RuleID, is.Details),
			Description: is.Details,
			Severity:    normalizeSeverity(is.Severity),
			FilePath:    is.File,
			Line:        gosecLine(is.Line),
			Metadata: map[string]any{
				"confidence": strings.ToLower(is.Confidence),
				"code":       is.Code,
			},
		}
		if is.CWE != nil {
			f.CWE = is.CWE.ID.ptr()
			f.URL = is.CWE.URL
		}
		if is.Column != "" {
			f.Metadata["column"] = is.Column
		}
		if is.NoSec || len(is.Suppressions) > 0 {
			reason := "suppressed in source (#nosec)"
			var reasonSb87 strings.Builder
			for _, s := range is.Suppressions {
				if s.Justification != "" {
					reasonSb87.WriteString(": " + s.Justification)
					break
				}
			}
			reason += reasonSb87.String()
			setImportedStatus(f.Metadata, domain.FindingFalsePositive, reason, zeroTime)
		}
		out = append(out, f)
	}
	return mergeSameLocation(out), nil
}

// gosecLine reads gosec's line, a string that is a range ("36-39") for
// multi-line matches; the first line is where to look.
func gosecLine(s string) *int {
	start, _, _ := strings.Cut(s, "-")
	if n, err := strconv.Atoi(strings.TrimSpace(start)); err == nil && n > 0 {
		return &n
	}
	return nil
}
