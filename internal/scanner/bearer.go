package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Bearer parses the JSON security report of Bearer CLI
// (`bearer scan . --report security --format json --output report.json`). The
// report is an object keyed by severity ("critical", "high", "medium", "low",
// "warning"), each holding the findings Bearer raised at that level; a clean
// scan is an empty object. Each finding names its rule, CWEs and the exact
// file/line it was found on.
type Bearer struct{}

// NewBearer constructs a Bearer parser.
func NewBearer() Bearer { return Bearer{} }

// Scanner returns the tool identifier.
func (Bearer) Scanner() string { return "bearer" }

// PrimaryCategory is the scan-level category for Bearer reports.
func (Bearer) PrimaryCategory() domain.Category { return domain.CategorySAST }

type bearerFinding struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Description      string   `json:"description"`
	DocumentationURL string   `json:"documentation_url"`
	CWEIDs           []string `json:"cwe_ids"`
	LineNumber       int      `json:"line_number"`
	FullFilename     string   `json:"full_filename"`
	Filename         string   `json:"filename"`
	CategoryGroups   []string `json:"category_groups"`
	Snippet          string   `json:"snippet"`
	CodeExtract      string   `json:"code_extract"`
	Fingerprint      string   `json:"fingerprint"`
	Source           struct {
		Column struct {
			Start int `json:"start"`
		} `json:"column"`
	} `json:"source"`
}

// bearerSeverities are the report's top-level keys, most severe first.
// "warning" is Bearer's lowest level, below "low".
var bearerSeverities = map[string]domain.Severity{
	"critical": domain.SeverityCritical,
	"high":     domain.SeverityHigh,
	"medium":   domain.SeverityMedium,
	"low":      domain.SeverityLow,
	"warning":  domain.SeverityLow,
}

// Parse converts a Bearer CLI security report into findings.
func (Bearer) Parse(r io.Reader) ([]ParsedFinding, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read bearer report: %w", err)
	}
	if data = bytes.TrimSpace(data); len(data) == 0 || data[0] != '{' {
		return nil, errors.New("decode bearer report: expected a JSON object keyed by severity")
	}
	var groups map[string]json.RawMessage
	if err := json.Unmarshal(data, &groups); err != nil {
		return nil, fmt.Errorf("decode bearer report: %w", err)
	}
	out := []ParsedFinding{}
	for _, level := range []string{"critical", "high", "medium", "low", "warning"} {
		raw, ok := groups[level]
		if !ok {
			continue
		}
		var items []bearerFinding
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, fmt.Errorf("decode bearer report %q findings: %w", level, err)
		}
		for _, it := range items {
			if it.ID == "" {
				return nil, errors.New("bearer report: finding without a rule id (not bearer --format json output?)")
			}
			out = append(out, bearerToFinding(it, bearerSeverities[level]))
		}
	}
	for key := range groups {
		if _, known := bearerSeverities[key]; !known {
			return nil, fmt.Errorf("decode bearer report: unexpected key %q (expected severity groups)", key)
		}
	}
	return mergeSameLocation(out), nil
}

func bearerToFinding(it bearerFinding, sev domain.Severity) ParsedFinding {
	meta := map[string]any{}
	if it.DocumentationURL != "" {
		meta["references"] = []string{it.DocumentationURL}
	}
	if it.Fingerprint != "" {
		meta["fingerprint"] = it.Fingerprint
	}
	if len(it.CategoryGroups) > 0 {
		meta["category_groups"] = it.CategoryGroups
	}
	if snippet := firstNonEmpty(strings.TrimSpace(it.CodeExtract), it.Snippet); snippet != "" {
		meta["snippet"] = snippet
	}
	if it.Source.Column.Start > 0 {
		meta["column"] = it.Source.Column.Start
	}
	if len(it.CWEIDs) > 1 {
		meta["cwes"] = it.CWEIDs
	}
	f := ParsedFinding{
		Category:    domain.CategorySAST,
		RuleID:      it.ID,
		Title:       firstNonEmpty(it.Title, it.ID),
		Description: it.Description,
		Severity:    sev,
		CWE:         cweFirst(it.CWEIDs...),
		FilePath:    firstNonEmpty(it.FullFilename, it.Filename),
		Metadata:    meta,
	}
	if it.LineNumber > 0 {
		f.Line = new(it.LineNumber)
	}
	return f
}
