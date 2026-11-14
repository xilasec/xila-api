package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Wapiti parses Wapiti's JSON report (`wapiti -u <url> -f json -o out.json`).
// Findings come from the "vulnerabilities" and "anomalies" sections (one per
// entry; "additionals" are informational fingerprints like detected
// technologies and are skipped, as is "suppressed_findings"). The rule id is
// the vulnerability category ("Reflected Cross Site Scripting") — Wapiti has no
// finer stable check id — and the CWE comes from the category's references.
//
// Severity is Wapiti's own level: 4 critical, 3 high, 2 medium, 1 low, 0 info
// (an integer since 3.1, a string in 3.0).
type Wapiti struct{}

// NewWapiti constructs a Wapiti parser.
func NewWapiti() Wapiti { return Wapiti{} }

// Scanner returns the tool identifier.
func (Wapiti) Scanner() string { return "wapiti" }

// PrimaryCategory is the scan-level category for Wapiti reports.
func (Wapiti) PrimaryCategory() domain.Category { return domain.CategoryDAST }

type wapitiEntry struct {
	Method      string          `json:"method"`
	Path        string          `json:"path"`
	Info        string          `json:"info"`
	Level       json.RawMessage `json:"level"`
	Parameter   *string         `json:"parameter"`
	Module      string          `json:"module"`
	HTTPRequest string          `json:"http_request"`
	CurlCommand string          `json:"curl_command"`
	WSTG        []string        `json:"wstg"`
}

type wapitiReport struct {
	Classifications map[string]struct {
		Desc string            `json:"desc"`
		Sol  string            `json:"sol"`
		Ref  map[string]string `json:"ref"`
	} `json:"classifications"`
	Vulnerabilities map[string][]wapitiEntry `json:"vulnerabilities"`
	Anomalies       map[string][]wapitiEntry `json:"anomalies"`
	Infos           *struct {
		Target  string `json:"target"`
		Version string `json:"version"`
	} `json:"infos"`
}

// Parse implements Parser.
func (Wapiti) Parse(r io.Reader) ([]ParsedFinding, error) {
	var rep wapitiReport
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode wapiti report: %w", err)
	}
	if rep.Infos == nil || (rep.Vulnerabilities == nil && rep.Anomalies == nil) {
		return nil, errors.New("decode wapiti report: no infos/vulnerabilities — not a Wapiti JSON report")
	}
	target := strings.TrimRight(rep.Infos.Target, "/")
	if i := strings.Index(target, "://"); i >= 0 {
		if j := strings.IndexByte(target[i+3:], '/'); j >= 0 {
			target = target[:i+3+j] // scheme://host — entry paths are absolute
		}
	}

	var out []ParsedFinding
	for _, section := range []struct {
		name    string
		entries map[string][]wapitiEntry
	}{{"vulnerability", rep.Vulnerabilities}, {"anomaly", rep.Anomalies}} {
		for _, category := range slices.Sorted(maps.Keys(section.entries)) {
			class := rep.Classifications[category]
			var cwe *int
			var refs []string
			for _, name := range slices.Sorted(maps.Keys(class.Ref)) {
				refs = append(refs, class.Ref[name])
				if m := cweRe.FindStringSubmatch(name); m != nil && cwe == nil {
					cwe = cweFrom(m[1])
				}
			}
			for _, e := range section.entries[category] {
				f := ParsedFinding{
					Category:    domain.CategoryDAST,
					RuleID:      category,
					Title:       category,
					Description: strings.TrimSpace(e.Info + "\n\n" + class.Desc),
					Severity:    wapitiSeverity(e.Level),
					CWE:         cwe,
					FilePath:    target + e.Path,
					URL:         target,
					Metadata: map[string]any{
						"kind":     section.name,
						"method":   e.Method,
						"module":   e.Module,
						"request":  e.HTTPRequest,
						"curl":     e.CurlCommand,
						"wstg":     e.WSTG,
						"solution": class.Sol,
					},
				}
				if e.Parameter != nil && *e.Parameter != "" {
					f.Metadata["param"] = *e.Parameter
					// One category on one page in two parameters is two issues.
					f.FilePath += " [" + *e.Parameter + "]"
				}
				if len(refs) > 0 {
					f.Metadata["references"] = refs
				}
				out = append(out, f)
			}
		}
	}
	return mergeSameLocation(out), nil
}

// wapitiSeverity maps Wapiti's 0–4 level (int, or string before 3.1).
func wapitiSeverity(raw json.RawMessage) domain.Severity {
	s := strings.Trim(string(raw), `"`)
	n, err := strconv.Atoi(s)
	if err != nil {
		return domain.SeverityMedium // unknown level stays visible
	}
	switch {
	case n >= 4:
		return domain.SeverityCritical
	case n == 3:
		return domain.SeverityHigh
	case n == 2:
		return domain.SeverityMedium
	case n == 1:
		return domain.SeverityLow
	}
	return domain.SeverityInfo
}
