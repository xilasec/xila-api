package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// CargoAudit parses `cargo audit --json` (RustSec). RustSec rates an advisory
// only by its CVSS vector, when it has one; the v3 base score is computed from
// the vector (it's fully determined by it), and advisories without a v3 vector
// stay unranked (medium). Informational advisories from "warnings"
// (unmaintained, unsound, notice) are kept at low — they are supply-chain risk,
// not exploitable vulnerabilities. Yanked-crate warnings carry no advisory and
// are skipped.
type CargoAudit struct{}

// NewCargoAudit constructs a CargoAudit parser.
func NewCargoAudit() CargoAudit { return CargoAudit{} }

// Scanner returns the tool identifier.
func (CargoAudit) Scanner() string { return "cargo-audit" }

// PrimaryCategory is the scan-level category for cargo-audit reports.
func (CargoAudit) PrimaryCategory() domain.Category { return domain.CategorySCA }

type cargoAuditReport struct {
	Vulnerabilities *struct {
		List []cargoAuditEntry `json:"list"`
	} `json:"vulnerabilities"`
	Warnings map[string][]cargoAuditEntry `json:"warnings"`
}

type cargoAuditEntry struct {
	Kind     string `json:"kind"`
	Advisory *struct {
		ID            string   `json:"id"`
		Title         string   `json:"title"`
		Description   string   `json:"description"`
		Date          string   `json:"date"`
		Aliases       []string `json:"aliases"`
		Categories    []string `json:"categories"`
		CVSS          string   `json:"cvss"`
		URL           string   `json:"url"`
		References    []string `json:"references"`
		Informational string   `json:"informational"`
	} `json:"advisory"`
	Versions *struct {
		Patched []string `json:"patched"`
	} `json:"versions"`
	Package struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"package"`
}

// Parse converts a cargo-audit JSON report into findings.
func (CargoAudit) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report cargoAuditReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode cargo-audit report: %w", err)
	}
	if report.Vulnerabilities == nil {
		return nil, errors.New(`decode cargo-audit report: no "vulnerabilities" object`)
	}

	out := []ParsedFinding{}
	for _, e := range report.Vulnerabilities.List {
		if f, ok := cargoAuditFinding(e, false); ok {
			out = append(out, f)
		}
	}
	for _, kind := range []string{"unsound", "unmaintained", "notice"} {
		for _, e := range report.Warnings[kind] {
			if f, ok := cargoAuditFinding(e, true); ok {
				out = append(out, f)
			}
		}
	}
	return mergeSameLocation(out), nil
}

func cargoAuditFinding(e cargoAuditEntry, warning bool) (ParsedFinding, bool) {
	a := e.Advisory
	if a == nil || a.ID == "" {
		return ParsedFinding{}, false
	}
	f := ParsedFinding{
		Category:       domain.CategorySCA,
		RuleID:         a.ID,
		Title:          fmt.Sprintf("%s: %s", a.ID, a.Title),
		Description:    a.Description,
		Severity:       normalizeSeverity(""),
		CVE:            cvesFrom(a.Aliases...),
		Package:        e.Package.Name,
		PackageVersion: e.Package.Version,
		Purl:           ecosystemPurl("cargo", e.Package.Name, e.Package.Version),
		URL:            "https://rustsec.org/advisories/" + a.ID,
		Metadata: map[string]any{
			"aliases":    a.Aliases,
			"categories": a.Categories,
			"date":       a.Date,
		},
	}
	if a.URL != "" {
		f.Metadata["advisory_url"] = a.URL
	}
	if e.Versions != nil && len(e.Versions.Patched) > 0 {
		f.FixedVersion = strings.Join(e.Versions.Patched, " || ")
	}
	if a.CVSS != "" {
		f.Metadata["cvss_vector"] = a.CVSS
		if s, ok := cvss3BaseScore(a.CVSS); ok {
			f.CVSS = floatPtr(s)
			f.Severity = severityFromCVSS(s)
		}
	}
	if warning {
		f.Severity = domain.SeverityLow
		f.Metadata["warning"] = firstNonEmpty(a.Informational, e.Kind)
	}
	return f, true
}
