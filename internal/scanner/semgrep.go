package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Semgrep parses Semgrep's native JSON (`semgrep scan --json`). Over the SARIF
// path it keeps the rule's confidence/likelihood/impact, the OWASP mapping,
// the suggested autofix, and — for Semgrep Supply Chain results — the
// vulnerable dependency, its version, transitivity and whether the vulnerable
// code is reachable. A result suppressed in source (`nosemgrep`, reported with
// is_ignored when --include-ignored is set) is imported as a false positive.
type Semgrep struct{}

// NewSemgrep constructs a Semgrep parser.
func NewSemgrep() Semgrep { return Semgrep{} }

// Scanner returns the tool identifier.
func (Semgrep) Scanner() string { return "semgrep" }

// PrimaryCategory is the scan-level category for Semgrep reports.
func (Semgrep) PrimaryCategory() domain.Category { return domain.CategorySAST }

type semgrepReport struct {
	Results *[]struct {
		CheckID string `json:"check_id"`
		Path    string `json:"path"`
		Start   struct {
			Line int `json:"line"`
		} `json:"start"`
		Extra struct {
			Message   string         `json:"message"`
			Severity  string         `json:"severity"`
			Metadata  map[string]any `json:"metadata"`
			Fix       string         `json:"fix"`
			IsIgnored bool           `json:"is_ignored"`
			SCAInfo   *struct {
				Reachable       bool `json:"reachable"`
				DependencyMatch struct {
					DependencyPattern struct {
						SemverRange string `json:"semver_range"`
					} `json:"dependency_pattern"`
					FoundDependency struct {
						Ecosystem    string `json:"ecosystem"`
						Package      string `json:"package"`
						Version      string `json:"version"`
						Transitivity string `json:"transitivity"`
						LockfilePath string `json:"lockfile_path"`
						LineNumber   int    `json:"line_number"`
					} `json:"found_dependency"`
				} `json:"dependency_match"`
			} `json:"sca_info"`
		} `json:"extra"`
	} `json:"results"`
}

// Parse converts a Semgrep JSON report into findings.
func (Semgrep) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report semgrepReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode semgrep report: %w", err)
	}
	if report.Results == nil {
		return nil, errors.New(`decode semgrep report: no "results" array (expected semgrep --json output)`)
	}

	out := make([]ParsedFinding, 0, len(*report.Results))
	for i, res := range *report.Results {
		if res.CheckID == "" {
			return nil, fmt.Errorf("semgrep report: result %d has no check_id (not semgrep --json output?)", i)
		}
		md := res.Extra.Metadata
		f := ParsedFinding{
			Category:    domain.CategorySAST,
			RuleID:      res.CheckID,
			Title:       semgrepTitle(res.CheckID, res.Extra.Message),
			Description: strings.TrimSpace(res.Extra.Message),
			Severity:    semgrepSeverity(res.Extra.Severity),
			CWE:         cweFirst(metaStrings(md, "cwe")...),
			CVE:         cvesInText(metaStrings(md, "sca-vuln-database-identifier", "cve", "references")...),
			FilePath:    res.Path,
			URL:         firstNonEmpty(metaString(md, "source"), metaString(md, "shortlink")),
			Metadata:    map[string]any{},
		}
		if res.Start.Line > 0 {
			f.Line = new(res.Start.Line)
		}
		for _, k := range []string{"confidence", "likelihood", "impact", "category", "subcategory"} {
			if v := metaString(md, k); v != "" {
				f.Metadata[k] = v
			}
		}
		if owasp := metaStrings(md, "owasp"); len(owasp) > 0 {
			f.Metadata["owasp"] = owasp
		}
		if res.Extra.Fix != "" {
			f.Metadata["fix"] = res.Extra.Fix
		}
		if sca := res.Extra.SCAInfo; sca != nil {
			dep := sca.DependencyMatch.FoundDependency
			f.Category = domain.CategorySCA
			f.Package, f.PackageVersion = dep.Package, dep.Version
			f.Purl = ecosystemPurl(dep.Ecosystem, dep.Package, dep.Version)
			f.FixedVersion = strings.Join(metaStrings(md, "sca-fix-versions"), ", ")
			f.Metadata["reachable"] = sca.Reachable
			f.Metadata["transitivity"] = dep.Transitivity
			f.Metadata["lockfile"] = dep.LockfilePath
			f.Metadata["vulnerable_range"] = sca.DependencyMatch.DependencyPattern.SemverRange
			if f.Title == "" || f.Title == res.CheckID {
				f.Title = fmt.Sprintf("%s in %s", res.CheckID, dep.Package)
			}
		}
		if res.Extra.IsIgnored {
			setImportedStatus(f.Metadata, domain.FindingFalsePositive, "suppressed in source (nosemgrep)", zeroTime)
		}
		out = append(out, f)
	}
	return mergeSameLocation(out), nil
}

// semgrepSeverity maps rule severities: the classic ERROR/WARNING/INFO scale
// and the newer CRITICAL/HIGH/MEDIUM/LOW one. INFO is Semgrep's lowest rating
// for a security rule that matched, so it is low, not informational.
func semgrepSeverity(s string) domain.Severity {
	switch strings.ToUpper(s) {
	case "ERROR":
		return domain.SeverityHigh
	case "INFO":
		return domain.SeverityLow
	}
	return normalizeSeverity(s)
}

// semgrepTitle is the message's first line, falling back to the rule's short
// name (the last dotted segment of the check id).
func semgrepTitle(checkID, message string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(message), "\n")
	if line = strings.TrimSpace(line); line != "" {
		if r := []rune(line); len(r) > 200 {
			line = string(r[:200]) + "…"
		}
		return line
	}
	if _, after, ok := strings.CutLast(checkID, "."); ok {
		return after
	}
	return checkID
}

// metaString reads a scalar metadata value.
func metaString(md map[string]any, key string) string {
	if s, ok := md[key].(string); ok {
		return s
	}
	return ""
}

// metaStrings reads metadata values that rules write either as a string or a
// list of strings.
func metaStrings(md map[string]any, keys ...string) []string {
	var out []string
	for _, k := range keys {
		switch v := md[k].(type) {
		case string:
			out = append(out, v)
		case []any:
			for _, e := range v {
				if s, ok := e.(string); ok {
					out = append(out, s)
				}
			}
		}
	}
	return out
}
