package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// MobSF parses Mobile Security Framework JSON reports: the static-analysis
// report of an APK/IPA (`POST /api/v1/report_json`, or "Download JSON" in the
// web UI), and the output of its CLI sibling mobsfscan
// (`mobsfscan --json -o report.json <src>`), which share an import in most
// pipelines. From the app report the security-relevant sections are mapped —
// manifest analysis, code analysis, binary analysis (ELF libraries, iOS Mach-O
// and the binary-findings table) and certificate analysis; items MobSF rates
// info, secure, good or suppressed are not findings. Inventory sections
// (permissions, URLs, trackers, strings) are not mapped.
type MobSF struct{}

// NewMobSF constructs a MobSF parser.
func NewMobSF() MobSF { return MobSF{} }

// Scanner returns the tool identifier.
func (MobSF) Scanner() string { return "mobsf" }

// PrimaryCategory is the scan-level category for MobSF reports.
func (MobSF) PrimaryCategory() domain.Category { return domain.CategorySAST }

type mobsfReport struct {
	FileName            string          `json:"file_name"`
	AppType             string          `json:"app_type"`
	MD5                 string          `json:"md5"`
	ManifestAnalysis    json.RawMessage `json:"manifest_analysis"`
	CodeAnalysis        json.RawMessage `json:"code_analysis"`
	BinaryAnalysis      json.RawMessage `json:"binary_analysis"`
	MachoAnalysis       json.RawMessage `json:"macho_analysis"`
	CertificateAnalysis json.RawMessage `json:"certificate_analysis"`

	// mobsfscan
	Results          map[string]mobsfScanResult `json:"results"`
	MobsfscanVersion string                     `json:"mobsfscan_version"`
}

// mobsfRule is the rule metadata MobSF attaches to code findings (and
// mobsfscan to its results).
type mobsfRule struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	CVSS        float64 `json:"cvss"`
	CWE         string  `json:"cwe"`
	OWASPMobile string  `json:"owasp-mobile"`
	MASVS       string  `json:"masvs"`
	Ref         string  `json:"ref"`
	Reference   string  `json:"reference"`
}

type mobsfCodeEntry struct {
	Files    map[string]string `json:"files"`
	Metadata *mobsfRule        `json:"metadata"`
}

type mobsfManifestItem struct {
	Rule        string          `json:"rule"`
	Title       string          `json:"title"`
	Name        string          `json:"name"`
	Severity    string          `json:"severity"`
	Stat        string          `json:"stat"`
	Description string          `json:"description"`
	Desc        string          `json:"desc"`
	Component   json.RawMessage `json:"component"`
}

type mobsfBinaryCheck struct {
	Severity     string  `json:"severity"`
	Description  string  `json:"description"`
	DetailedDesc string  `json:"detailed_desc"`
	CVSS         float64 `json:"cvss"`
	CWE          string  `json:"cwe"`
	OWASPMobile  string  `json:"owasp-mobile"`
	MASVS        string  `json:"masvs"`
}

type mobsfScanResult struct {
	Files []struct {
		FilePath    string `json:"file_path"`
		MatchLines  []int  `json:"match_lines"`
		MatchString string `json:"match_string"`
	} `json:"files"`
	Metadata mobsfRule `json:"metadata"`
}

// Parse converts a MobSF app report or a mobsfscan report into findings.
func (MobSF) Parse(r io.Reader) ([]ParsedFinding, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read mobsf report: %w", err)
	}
	if data = bytes.TrimSpace(data); len(data) == 0 || data[0] != '{' {
		return nil, errors.New("decode mobsf report: expected a JSON object (MobSF report_json or mobsfscan --json)")
	}
	var rep mobsfReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("decode mobsf report: %w", err)
	}
	if rep.Results != nil || rep.MobsfscanVersion != "" {
		return mobsfScanFindings(rep.Results), nil
	}
	if rep.FileName == "" && rep.AppType == "" && rep.MD5 == "" &&
		rep.ManifestAnalysis == nil && rep.CodeAnalysis == nil && rep.BinaryAnalysis == nil {
		return nil, errors.New("decode mobsf report: no MobSF analysis sections (expected report_json or mobsfscan output)")
	}

	out := []ParsedFinding{}
	for _, step := range []func(mobsfReport) ([]ParsedFinding, error){
		mobsfManifest, mobsfCode, mobsfBinary, mobsfCertificate,
	} {
		fs, err := step(rep)
		if err != nil {
			return nil, err
		}
		out = append(out, fs...)
	}
	return mergeSameLocation(out), nil
}

// mobsfSeverity maps MobSF's ratings; ok is false for the levels that report
// a passed or neutral check.
func mobsfSeverity(s string) (domain.Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info", "secure", "good", "suppressed":
		return "", false
	case "hotspot":
		return domain.SeverityLow, true
	}
	return normalizeSeverity(s), true
}

func mobsfManifest(rep mobsfReport) ([]ParsedFinding, error) {
	raw := bytes.TrimSpace(rep.ManifestAnalysis)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var items []mobsfManifestItem
	if raw[0] == '[' {
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, fmt.Errorf("decode mobsf manifest_analysis: %w", err)
		}
	} else {
		var wrapped struct {
			Findings []mobsfManifestItem `json:"manifest_findings"`
		}
		if err := json.Unmarshal(raw, &wrapped); err != nil {
			return nil, fmt.Errorf("decode mobsf manifest_analysis: %w", err)
		}
		items = wrapped.Findings
	}
	var out []ParsedFinding
	for _, it := range items {
		sev, ok := mobsfSeverity(firstNonEmpty(it.Severity, it.Stat))
		if !ok {
			continue
		}
		title := mobsfText(firstNonEmpty(it.Title, it.Name))
		meta := map[string]any{"section": "manifest"}
		path := "AndroidManifest.xml"
		var component []string
		if json.Unmarshal(it.Component, &component) == nil && len(component) > 0 {
			meta["component"] = component
			// A finding about one declared component (Activity, Service,
			// Provider…) is located at that component, so two exported
			// activities stay two findings.
			if len(component) == 2 && strings.Contains(component[1], ".") {
				path = component[1]
				meta["component_type"] = component[0]
			}
		}
		out = append(out, ParsedFinding{
			Category:    domain.CategorySAST,
			RuleID:      firstNonEmpty(it.Rule, mobsfText(it.Name), title),
			Title:       title,
			Description: firstNonEmpty(it.Description, it.Desc),
			Severity:    sev,
			FilePath:    path,
			Metadata:    meta,
		})
	}
	return out, nil
}

func mobsfCode(rep mobsfReport) ([]ParsedFinding, error) {
	raw := bytes.TrimSpace(rep.CodeAnalysis)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var entries map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, fmt.Errorf("decode mobsf code_analysis: %w", err)
	}
	// Newer reports wrap the rules as {"findings": {...}, "summary": {...}}.
	if inner, ok := entries["findings"]; ok {
		if _, hasSummary := entries["summary"]; hasSummary {
			entries = nil
			if err := json.Unmarshal(inner, &entries); err != nil {
				return nil, fmt.Errorf("decode mobsf code_analysis findings: %w", err)
			}
		}
	}
	var out []ParsedFinding
	for _, id := range slices.Sorted(maps.Keys(entries)) {
		var e mobsfCodeEntry
		if err := json.Unmarshal(entries[id], &e); err != nil || e.Metadata == nil {
			continue // not a rule entry
		}
		sev, ok := mobsfSeverity(e.Metadata.Severity)
		if !ok {
			continue
		}
		base := mobsfRuleFinding(firstNonEmpty(e.Metadata.ID, id), *e.Metadata, sev)
		base.Metadata["section"] = "code"
		if len(e.Files) == 0 {
			out = append(out, base)
			continue
		}
		for _, file := range slices.Sorted(maps.Keys(e.Files)) {
			f := base
			f.Metadata = maps.Clone(base.Metadata)
			f.FilePath = file
			f.Line = mobsfFirstLine(e.Files[file])
			if lines := strings.TrimSpace(e.Files[file]); lines != "" {
				f.Metadata["lines"] = lines
			}
			out = append(out, f)
		}
	}
	return out, nil
}

func mobsfBinary(rep mobsfReport) ([]ParsedFinding, error) {
	var out []ParsedFinding
	raw := bytes.TrimSpace(rep.BinaryAnalysis)
	switch {
	case len(raw) == 0 || string(raw) == "null":
	case raw[0] == '[':
		// Android: one entry per native library, one object per hardening check.
		var libs []map[string]json.RawMessage
		if err := json.Unmarshal(raw, &libs); err != nil {
			return nil, fmt.Errorf("decode mobsf binary_analysis: %w", err)
		}
		for _, lib := range libs {
			out = append(out, mobsfBinaryChecks(lib)...)
		}
	default:
		var table map[string]json.RawMessage
		if err := json.Unmarshal(raw, &table); err != nil {
			return nil, fmt.Errorf("decode mobsf binary_analysis: %w", err)
		}
		if inner, ok := table["findings"]; ok {
			table = nil
			if err := json.Unmarshal(inner, &table); err != nil {
				return nil, fmt.Errorf("decode mobsf binary_analysis findings: %w", err)
			}
		}
		for _, title := range slices.Sorted(maps.Keys(table)) {
			var c mobsfBinaryCheck
			if err := json.Unmarshal(table[title], &c); err != nil {
				continue // e.g. the "summary" counts
			}
			sev, ok := mobsfSeverity(c.Severity)
			if !ok {
				continue
			}
			f := ParsedFinding{
				Category:    domain.CategorySAST,
				RuleID:      title,
				Title:       title,
				Description: firstNonEmpty(c.DetailedDesc, c.Description),
				Severity:    sev,
				CWE:         cweFirst(c.CWE),
				FilePath:    rep.FileName,
				Metadata:    mobsfStandards("binary", c.CVSS, c.OWASPMobile, c.MASVS),
			}
			out = append(out, f)
		}
	}
	// iOS: the Mach-O hardening checks of the main executable.
	if raw := bytes.TrimSpace(rep.MachoAnalysis); len(raw) > 0 && raw[0] == '{' {
		var macho map[string]json.RawMessage
		if err := json.Unmarshal(raw, &macho); err != nil {
			return nil, fmt.Errorf("decode mobsf macho_analysis: %w", err)
		}
		out = append(out, mobsfBinaryChecks(macho)...)
	}
	return out, nil
}

// mobsfBinaryChecks maps one binary's hardening checks ({"name": …, "nx":
// {"severity", "description"}, …}).
func mobsfBinaryChecks(bin map[string]json.RawMessage) []ParsedFinding {
	var name string
	_ = json.Unmarshal(bin["name"], &name)
	var out []ParsedFinding
	for _, check := range slices.Sorted(maps.Keys(bin)) {
		if check == "name" {
			continue
		}
		var c mobsfBinaryCheck
		if err := json.Unmarshal(bin[check], &c); err != nil {
			continue
		}
		sev, ok := mobsfSeverity(c.Severity)
		if !ok {
			continue
		}
		desc := firstNonEmpty(c.Description, c.DetailedDesc)
		out = append(out, ParsedFinding{
			Category:    domain.CategorySAST,
			RuleID:      check,
			Title:       firstNonEmpty(mobsfSentence(desc), check),
			Description: desc,
			Severity:    sev,
			CWE:         cweFirst(c.CWE),
			FilePath:    name,
			Metadata:    mobsfStandards("binary", c.CVSS, c.OWASPMobile, c.MASVS),
		})
	}
	return out
}

func mobsfCertificate(rep mobsfReport) ([]ParsedFinding, error) {
	raw := bytes.TrimSpace(rep.CertificateAnalysis)
	if len(raw) == 0 || raw[0] != '{' {
		return nil, nil
	}
	var cert struct {
		Info     string     `json:"certificate_info"`
		Findings [][]string `json:"certificate_findings"`
	}
	if err := json.Unmarshal(raw, &cert); err != nil {
		return nil, fmt.Errorf("decode mobsf certificate_analysis: %w", err)
	}
	var out []ParsedFinding
	for _, row := range cert.Findings {
		// [severity, description, title] (older reports: [severity, description]).
		if len(row) < 2 {
			continue
		}
		sev, ok := mobsfSeverity(row[0])
		if !ok {
			continue
		}
		title := row[1]
		if len(row) >= 3 && row[2] != "" {
			title = row[2]
		}
		meta := map[string]any{"section": "certificate"}
		if cert.Info != "" {
			meta["certificate_info"] = cert.Info
		}
		out = append(out, ParsedFinding{
			Category:    domain.CategorySAST,
			RuleID:      title,
			Title:       title,
			Description: row[1],
			Severity:    sev,
			FilePath:    rep.FileName,
			Metadata:    meta,
		})
	}
	return out, nil
}

// mobsfScanFindings maps mobsfscan results: one finding per matched file.
func mobsfScanFindings(results map[string]mobsfScanResult) []ParsedFinding {
	out := []ParsedFinding{}
	for _, id := range slices.Sorted(maps.Keys(results)) {
		res := results[id]
		var sev domain.Severity
		switch strings.ToUpper(res.Metadata.Severity) {
		case "ERROR":
			sev = domain.SeverityHigh
		case "WARNING":
			sev = domain.SeverityMedium
		case "INFO":
			sev = domain.SeverityLow
		default:
			sev = normalizeSeverity(res.Metadata.Severity)
		}
		base := mobsfRuleFinding(id, res.Metadata, sev)
		if len(res.Files) == 0 {
			out = append(out, base)
			continue
		}
		for _, file := range res.Files {
			f := base
			f.Metadata = maps.Clone(base.Metadata)
			f.FilePath = file.FilePath
			if len(file.MatchLines) > 0 && file.MatchLines[0] > 0 {
				f.Line = new(file.MatchLines[0])
			}
			if file.MatchString != "" {
				f.Metadata["snippet"] = file.MatchString
			}
			out = append(out, f)
		}
	}
	return mergeSameLocation(out)
}

func mobsfRuleFinding(id string, m mobsfRule, sev domain.Severity) ParsedFinding {
	meta := mobsfStandards("", m.CVSS, m.OWASPMobile, m.MASVS)
	if ref := firstNonEmpty(m.Ref, m.Reference); ref != "" {
		meta["references"] = []string{ref}
	}
	return ParsedFinding{
		Category:    domain.CategorySAST,
		RuleID:      id,
		Title:       firstNonEmpty(mobsfSentence(m.Description), id),
		Description: m.Description,
		Severity:    sev,
		CWE:         cweFirst(m.CWE),
		Metadata:    meta,
	}
}

func mobsfStandards(section string, cvss float64, owasp, masvs string) map[string]any {
	meta := map[string]any{}
	if section != "" {
		meta["section"] = section
	}
	if cvss > 0 {
		meta["mobsf_cvss"] = cvss
	}
	if owasp != "" {
		meta["owasp_mobile"] = owasp
	}
	if masvs != "" {
		meta["masvs"] = masvs
	}
	return meta
}

// mobsfFirstLine returns the lowest line of MobSF's "12,7,30" line list.
func mobsfFirstLine(lines string) *int {
	best := 0
	for s := range strings.SplitSeq(lines, ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n > 0 && (best == 0 || n < best) {
			best = n
		}
	}
	if best == 0 {
		return nil
	}
	return new(best)
}

// mobsfSentence is the first sentence of a MobSF description, used as the
// title of rule-based findings.
func mobsfSentence(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if i := strings.Index(s, ". "); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSuffix(s, ".")
}

var (
	mobsfBreakRe = regexp.MustCompile(`(?i)<br\s*/?>`)
	mobsfTagRe   = regexp.MustCompile(`<[^>]+>`)
)

// mobsfText flattens the HTML MobSF puts in manifest titles
// ("<strong>Activity</strong> (x) is not Protected.<br>…").
func mobsfText(s string) string {
	s = mobsfBreakRe.ReplaceAllString(s, " ")
	s = mobsfTagRe.ReplaceAllString(s, "")
	return strings.Join(strings.Fields(s), " ")
}
