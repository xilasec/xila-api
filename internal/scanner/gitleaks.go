package scanner

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/xilasec/xila-api/internal/domain"
)

// Gitleaks parses `gitleaks detect --report-format json` output (a flat array).
// The native format carries the commit, author and entropy that SARIF drops —
// and for a leaked secret, "who committed it and when" is most of the triage.
type Gitleaks struct{}

// NewGitleaks constructs a Gitleaks parser.
func NewGitleaks() Gitleaks { return Gitleaks{} }

// Scanner returns the tool identifier.
func (Gitleaks) Scanner() string { return "gitleaks" }

// PrimaryCategory is the scan-level category for Gitleaks reports.
func (Gitleaks) PrimaryCategory() domain.Category { return domain.CategorySecret }

type gitleaksFinding struct {
	Description string  `json:"Description"`
	RuleID      string  `json:"RuleID"`
	File        string  `json:"File"`
	StartLine   int     `json:"StartLine"`
	Commit      string  `json:"Commit"`
	Author      string  `json:"Author"`
	Email       string  `json:"Email"`
	Date        string  `json:"Date"`
	Entropy     float64 `json:"Entropy"`
	Match       string  `json:"Match"`
}

// Parse converts a Gitleaks report into findings.
//
// Every leaked credential is high severity: unlike a CVE, there is no "maybe" —
// the secret is in the history and must be rotated. Gitleaks itself emits no
// severity, so inventing a gradient here would be false precision.
func (Gitleaks) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report []gitleaksFinding
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode gitleaks report: %w", err)
	}

	out := make([]ParsedFinding, 0, len(report))
	for _, g := range report {
		f := ParsedFinding{
			Category:    domain.CategorySecret,
			RuleID:      g.RuleID,
			Title:       firstNonEmptyStr(g.Description, g.RuleID),
			Severity:    domain.SeverityHigh,
			FilePath:    g.File,
			Description: "Secret detected in " + g.File,
			Metadata: map[string]any{
				"commit":  g.Commit,
				"author":  g.Author,
				"email":   g.Email,
				"date":    g.Date,
				"entropy": g.Entropy,
			},
		}
		if g.StartLine > 0 {
			f.Line = new(g.StartLine)
		}
		out = append(out, f)
	}
	return out, nil
}
