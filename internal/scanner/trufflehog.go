package scanner

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/xilasec/xila-api/internal/domain"
)

// TruffleHog parses `trufflehog … --json` output (one JSON object per line).
type TruffleHog struct{}

// NewTruffleHog constructs a TruffleHog parser.
func NewTruffleHog() TruffleHog { return TruffleHog{} }

// Scanner returns the tool identifier.
func (TruffleHog) Scanner() string { return "trufflehog" }

// PrimaryCategory is the scan-level category for TruffleHog reports.
func (TruffleHog) PrimaryCategory() domain.Category { return domain.CategorySecret }

type truffleFinding struct {
	DetectorName   string `json:"DetectorName"`
	Verified       bool   `json:"Verified"`
	Raw            string `json:"Raw"`
	SourceName     string `json:"SourceName"`
	SourceMetadata struct {
		Data struct {
			Git struct {
				File       string `json:"file"`
				Line       int    `json:"line"`
				Commit     string `json:"commit"`
				Email      string `json:"email"`
				Repository string `json:"repository"`
			} `json:"Git"`
			Filesystem struct {
				File string `json:"file"`
				Line int    `json:"line"`
			} `json:"Filesystem"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

// Parse converts a TruffleHog JSONL stream into findings.
//
// TruffleHog's distinguishing feature is *verification*: it calls the provider to
// check whether the credential still works. A verified secret is a live, usable
// credential — that is a critical, not a "maybe". An unverified one is a
// plausible string that may be a test fixture, so it lands as high.
func (TruffleHog) Parse(r io.Reader) ([]ParsedFinding, error) {
	var out []ParsedFinding
	err := decodeJSONLines(r, func(raw json.RawMessage) error {
		var t truffleFinding
		if err := json.Unmarshal(raw, &t); err != nil {
			return fmt.Errorf("decode trufflehog finding: %w", err)
		}
		if t.DetectorName == "" {
			return nil // progress/chaff lines
		}

		file, line := t.SourceMetadata.Data.Git.File, t.SourceMetadata.Data.Git.Line
		if file == "" {
			file, line = t.SourceMetadata.Data.Filesystem.File, t.SourceMetadata.Data.Filesystem.Line
		}

		severity := domain.SeverityHigh
		title := "Potential " + t.DetectorName + " secret"
		if t.Verified {
			severity = domain.SeverityCritical
			title = "Verified " + t.DetectorName + " secret (credential is live)"
		}

		f := ParsedFinding{
			Category:    domain.CategorySecret,
			RuleID:      t.DetectorName,
			Title:       title,
			Description: "Secret detected in " + file,
			Severity:    severity,
			FilePath:    file,
			Metadata: map[string]any{
				"verified":   t.Verified,
				"detector":   t.DetectorName,
				"commit":     t.SourceMetadata.Data.Git.Commit,
				"repository": t.SourceMetadata.Data.Git.Repository,
			},
		}
		if line > 0 {
			f.Line = new(line)
		}
		out = append(out, f)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
