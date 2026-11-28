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

// DrHeader parses the JSON output of drHEADer (`drheader scan single
// <url> --output json`, or `scan bulk` for several URLs), which audits HTTP
// security headers against a rule set. A single-URL report is a list of rule
// violations; a bulk report is a list of {"url", "report": [...]}. Every
// violation is a finding: the rule id is the header, the location the URL
// (when the report has one). One header can fail several ways at one URL (a
// CSP missing a directive and containing a forbidden one), so those fold into
// one finding with every message.
type DrHeader struct{}

// NewDrHeader constructs a drHEADer parser.
func NewDrHeader() DrHeader { return DrHeader{} }

// Scanner returns the tool identifier.
func (DrHeader) Scanner() string { return "drheader" }

// PrimaryCategory is the scan-level category for drHEADer reports.
func (DrHeader) PrimaryCategory() domain.Category { return domain.CategoryDAST }

type drHeaderRule struct {
	Rule     string   `json:"rule"`
	Severity string   `json:"severity"`
	Message  string   `json:"message"`
	Value    *string  `json:"value"`
	Expected []string `json:"expected"`
	Avoid    []string `json:"avoid"`
	Anomaly  []string `json:"anomalies"`
}

// Parse implements Parser.
func (DrHeader) Parse(r io.Reader) ([]ParsedFinding, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read drheader json: %w", err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return []ParsedFinding{}, nil // drHEADer writes nothing for a clean URL
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, fmt.Errorf("decode drheader json: %w", err)
	}
	out := []ParsedFinding{}
	for _, item := range items {
		var probe struct {
			URL    *string        `json:"url"`
			Report []drHeaderRule `json:"report"`
			drHeaderRule
		}
		if err := json.Unmarshal(item, &probe); err != nil {
			return nil, fmt.Errorf("decode drheader json: %w", err)
		}
		if probe.URL != nil { // bulk report entry
			for _, v := range probe.Report {
				if f, ok := drHeaderFinding(v, *probe.URL); ok {
					out = append(out, f)
				}
			}
			continue
		}
		if probe.Rule == "" {
			return nil, errors.New("decode drheader json: entry without a rule — not a drHEADer report")
		}
		if f, ok := drHeaderFinding(probe.drHeaderRule, ""); ok {
			out = append(out, f)
		}
	}
	return mergeSameLocation(out), nil
}

func drHeaderFinding(v drHeaderRule, url string) (ParsedFinding, bool) {
	rule := strings.TrimSpace(v.Rule)
	if rule == "" {
		return ParsedFinding{}, false
	}
	var desc strings.Builder
	desc.WriteString(v.Message)
	if v.Value != nil && *v.Value != "" {
		desc.WriteString("\nObserved: " + *v.Value)
	}
	if len(v.Expected) > 0 {
		desc.WriteString("\nExpected: " + strings.Join(v.Expected, "; "))
	}
	if len(v.Avoid) > 0 {
		desc.WriteString("\nMust avoid: " + strings.Join(v.Avoid, "; "))
	}
	if len(v.Anomaly) > 0 {
		desc.WriteString("\nAnomalies: " + strings.Join(v.Anomaly, "; "))
	}
	meta := map[string]any{"header": rule, "message": v.Message}
	if len(v.Expected) > 0 {
		meta["expected"] = v.Expected
	}
	return ParsedFinding{
		Category:    domain.CategoryDAST,
		RuleID:      rule,
		Title:       "Header " + rule + ": " + v.Message,
		Description: desc.String(),
		Severity:    normalizeSeverity(v.Severity),
		CWE:         new(drHeaderCWE(rule)),
		FilePath:    url,
		URL:         url,
		Metadata:    meta,
	}, true
}

// drHeaderCWE maps a header rule to its weakness: caching headers to
// sensitive data in a cache, cookies to missing flags, banner headers to
// information exposure, every other security header to a missing protection.
func drHeaderCWE(rule string) int {
	switch strings.ToLower(rule) {
	case "cache-control", "pragma", "expires":
		return 525
	case "set-cookie":
		return 614
	case "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator":
		return 200
	}
	return 693
}
