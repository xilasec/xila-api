// Package scanner normalizes third-party scanner output into findings.
//
// Adding support for a new tool means implementing Parser and registering it —
// nothing else in the system needs to change.
package scanner

import (
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// ParsedFinding is a scanner-agnostic finding produced by a Parser. It carries
// no persistence concerns (no IDs, no fingerprint) — the ingestion service
// derives those. JSON tags exist only for internal/customparser's dry-run
// preview endpoint (no other caller serializes a ParsedFinding).
type ParsedFinding struct {
	Category       domain.Category `json:"category"`
	RuleID         string          `json:"rule_id"`
	Title          string          `json:"title"`
	Description    string          `json:"description"`
	Severity       domain.Severity `json:"severity"`
	CWE            *int            `json:"cwe"`
	CVE            []string        `json:"cve"`
	FilePath       string          `json:"file_path"`
	Line           *int            `json:"line"`
	Package        string          `json:"package"`
	PackageVersion string          `json:"package_version"`
	FixedVersion   string          `json:"fixed_version"`
	Purl           string          `json:"purl"`
	URL            string          `json:"url"`
	CVSS           *float64        `json:"cvss"`
	Metadata       map[string]any  `json:"metadata,omitempty"`
}

// Parser converts one tool's raw output into normalized findings.
type Parser interface {
	// Scanner is the stable identifier used in the API (e.g. "trivy").
	Scanner() string
	// PrimaryCategory is the scan-level category recorded for this tool.
	PrimaryCategory() domain.Category
	// Parse reads raw output and returns normalized findings.
	Parse(r io.Reader) ([]ParsedFinding, error)
}

// Registry maps scanner identifiers to their parsers.
type Registry struct {
	parsers map[string]Parser
}

// NewRegistry builds a Registry from the given parsers.
func NewRegistry(parsers ...Parser) *Registry {
	reg := &Registry{parsers: make(map[string]Parser, len(parsers))}
	for _, p := range parsers {
		reg.parsers[p.Scanner()] = p
	}
	return reg
}

// Get returns the parser for a scanner identifier.
func (r *Registry) Get(scanner string) (Parser, bool) {
	p, ok := r.parsers[scanner]
	return p, ok
}

// Supported lists the registered scanner identifiers.
func (r *Registry) Supported() []string {
	out := make([]string, 0, len(r.parsers))
	for name := range r.parsers {
		out = append(out, name)
	}
	return out
}

// intPtr is a small helper for optional integer fields.
func intPtr(v int) *int { return &v }

// normalizeSeverity maps the severity vocabularies tools actually emit onto our
// enum. Every scanner spells this differently ("moderate", "negligible", "note",
// "warning", "informational"), so the mapping lives here once rather than being
// re-guessed in each parser.
//
// An unrecognized value becomes medium, not info: a finding we can't rank must
// stay visible. Silently dropping it to info is how real issues get missed.
func normalizeSeverity(s string) domain.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit", "fatal":
		return domain.SeverityCritical
	case "high", "important", "error":
		return domain.SeverityHigh
	case "medium", "moderate", "warning", "warn":
		return domain.SeverityMedium
	case "low", "minor", "note", "negligible":
		return domain.SeverityLow
	case "info", "informational", "information", "none", "unknown":
		return domain.SeverityInfo
	}
	return domain.SeverityMedium
}

// severityFromCVSS derives a severity from a CVSS base score, for tools that
// report a score but no rating.
func severityFromCVSS(score float64) domain.Severity {
	switch {
	case score >= 9.0:
		return domain.SeverityCritical
	case score >= 7.0:
		return domain.SeverityHigh
	case score >= 4.0:
		return domain.SeverityMedium
	case score > 0:
		return domain.SeverityLow
	}
	return domain.SeverityInfo
}

// cweFrom extracts the numeric id from the many ways tools write a CWE:
// "CWE-79", "79", "cwe-79".
func cweFrom(s string) *int {
	s = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(s)), "CWE-")
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return &n
	}
	return nil
}

// cvesFrom keeps only the entries that look like CVE ids (tools mix CVEs with
// GHSA/OSV/vendor ids in the same alias list, and the CVE is what dedup and
// enrichment key on).
func cvesFrom(ids ...string) []string {
	var out []string
	for _, id := range ids {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			out = append(out, strings.ToUpper(id))
		}
	}
	return out
}

// floatPtr is a small helper for optional score fields.
func floatPtr(v float64) *float64 { return &v }

// decodeJSONLines walks a newline-delimited JSON stream, calling fn per object.
// Several tools (TruffleHog, Nuclei, govulncheck) stream one object per line.
func decodeJSONLines(r io.Reader, fn func(json.RawMessage) error) error {
	dec := json.NewDecoder(r)
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := fn(raw); err != nil {
			return err
		}
	}
}

// HostOf is the machine a finding is about, as infrastructure parsers record
// it (metadata host, else hostname, else ip; lowercased), or "" when the
// finding names none. A split-assets scan files the finding under that host's
// asset.
func HostOf(pf ParsedFinding) string {
	for _, k := range []string{"host", "hostname", "ip"} {
		if v, ok := pf.Metadata[k].(string); ok {
			if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
				return v
			}
		}
	}
	return ""
}
