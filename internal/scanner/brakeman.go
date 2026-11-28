package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Brakeman parses `brakeman -f json` (Rails SAST). Brakeman has no severity
// scale — confidence (High/Medium/Weak) is its only ranking, and it uses it as
// one — so it maps onto high/medium/low. The rule id is the check name plus the
// warning code ("SQL/0"…), which is stable across Brakeman versions; the CVE is
// lifted from the message of the dependency checks ("Rails 3.2.3 contains a SQL
// injection vulnerability (CVE-2013-6417)"). Warnings listed in brakeman.ignore
// (ignored_warnings) are imported as false positives with the ignore note.
type Brakeman struct{}

// NewBrakeman constructs a Brakeman parser.
func NewBrakeman() Brakeman { return Brakeman{} }

// Scanner returns the tool identifier.
func (Brakeman) Scanner() string { return "brakeman" }

// PrimaryCategory is the scan-level category for Brakeman reports.
func (Brakeman) PrimaryCategory() domain.Category { return domain.CategorySAST }

type brakemanWarning struct {
	WarningType string  `json:"warning_type"`
	WarningCode int     `json:"warning_code"`
	Fingerprint string  `json:"fingerprint"`
	CheckName   string  `json:"check_name"`
	Message     string  `json:"message"`
	File        string  `json:"file"`
	Line        *int    `json:"line"`
	Link        string  `json:"link"`
	Code        *string `json:"code"`
	UserInput   *string `json:"user_input"`
	Confidence  string  `json:"confidence"`
	CWEID       []int   `json:"cwe_id"`
	Location    *struct {
		Type   string `json:"type"`
		Class  string `json:"class"`
		Method string `json:"method"`
	} `json:"location"`
}

type brakemanReport struct {
	ScanInfo *struct {
		BrakemanVersion string `json:"brakeman_version"`
	} `json:"scan_info"`
	Warnings        []brakemanWarning `json:"warnings"`
	IgnoredWarnings []brakemanWarning `json:"ignored_warnings"`
}

// Parse converts a Brakeman JSON report into findings.
func (Brakeman) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report brakemanReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode brakeman report: %w", err)
	}
	if report.ScanInfo == nil {
		return nil, errors.New(`decode brakeman report: no "scan_info" (expected brakeman -f json output)`)
	}

	out := make([]ParsedFinding, 0, len(report.Warnings)+len(report.IgnoredWarnings))
	for _, w := range report.Warnings {
		out = append(out, brakemanFinding(w))
	}
	for _, w := range report.IgnoredWarnings {
		f := brakemanFinding(w)
		setImportedStatus(f.Metadata, domain.FindingFalsePositive, "ignored in brakeman.ignore", zeroTime)
		out = append(out, f)
	}
	return mergeSameLocation(out), nil
}

func brakemanFinding(w brakemanWarning) ParsedFinding {
	f := ParsedFinding{
		Category:    domain.CategorySAST,
		RuleID:      fmt.Sprintf("%s/%d", w.CheckName, w.WarningCode),
		Title:       fmt.Sprintf("%s: %s", w.WarningType, w.Message),
		Description: w.Message,
		Severity:    brakemanSeverity(w.Confidence),
		CVE:         cvesInText(w.Message),
		FilePath:    w.File,
		Line:        w.Line,
		URL:         w.Link,
		Metadata: map[string]any{
			"warning_type":         w.WarningType,
			"confidence":           strings.ToLower(w.Confidence),
			"brakeman_fingerprint": w.Fingerprint,
		},
	}
	if len(w.CWEID) > 0 && w.CWEID[0] > 0 {
		f.CWE = new(w.CWEID[0])
	}
	if w.Code != nil {
		f.Metadata["code"] = *w.Code
	}
	if w.UserInput != nil {
		f.Metadata["user_input"] = *w.UserInput
	}
	if w.Location != nil && w.Location.Class != "" {
		f.Metadata["location"] = strings.TrimSuffix(w.Location.Class+"#"+w.Location.Method, "#")
	}
	return f
}

func brakemanSeverity(confidence string) domain.Severity {
	switch strings.ToLower(confidence) {
	case "high":
		return domain.SeverityHigh
	case "weak", "low":
		return domain.SeverityLow
	}
	return domain.SeverityMedium
}
