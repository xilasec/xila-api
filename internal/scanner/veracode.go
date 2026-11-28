package scanner

import (
	"bufio"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/xilasec/xila-api/internal/domain"
)

// Veracode parses the Veracode Detailed Report XML (<detailedreport>), as
// downloaded from the Veracode platform (Triage Flaws → Detailed Report → XML)
// or via the Results API (`detailedreport.do?build_id=…`).
//
// Static flaws become SAST findings at their source file and line; dynamic
// flaws (DAST) become findings on the flaw's URL; and vulnerable components from
// the software composition analysis become SCA findings, one per CVE. Veracode
// grades 0–5: 5 very high → critical, 4 high, 3 medium, 2 low, 1 and 0
// (very low / informational) → info. Flaws whose remediation status is Fixed
// are not reported. An accepted mitigation is carried as remote triage: risk
// accepted, or false positive when the mitigation was proposed as a false
// positive.
type Veracode struct{}

// NewVeracode constructs a Veracode parser.
func NewVeracode() Veracode { return Veracode{} }

// Scanner returns the tool identifier.
func (Veracode) Scanner() string { return "veracode" }

// PrimaryCategory is the scan-level category for Veracode reports.
func (Veracode) PrimaryCategory() domain.Category { return domain.CategorySAST }

type veracodeReport struct {
	XMLName    xml.Name `xml:"detailedreport"`
	AppName    string   `xml:"app_name,attr"`
	Severities []struct {
		Categories []struct {
			ID              string           `xml:"categoryid,attr"`
			Name            string           `xml:"categoryname,attr"`
			Desc            []veracodePara   `xml:"desc>para"`
			Recommendations []veracodePara   `xml:"recommendations>para"`
			CWEs            []veracodeCWEBox `xml:"cwe"`
		} `xml:"category"`
	} `xml:"severity"`
	Components []struct {
		FileName  string `xml:"file_name,attr"`
		Library   string `xml:"library,attr"`
		LibraryID string `xml:"library_id,attr"`
		Version   string `xml:"version,attr"`
		Vendor    string `xml:"vendor,attr"`
		FilePaths []struct {
			Value string `xml:"value,attr"`
		} `xml:"file_paths>file_path"`
		Vulnerabilities []struct {
			CVE            string               `xml:"cve_id,attr"`
			CVSS           string               `xml:"cvss_score,attr"`
			Severity       string               `xml:"severity,attr"`
			CWE            string               `xml:"cwe_id,attr"`
			Summary        string               `xml:"cve_summary,attr"`
			Mitigation     string               `xml:"mitigation,attr"`
			MitigationType string               `xml:"mitigation_type,attr"`
			Mitigations    []veracodeMitigation `xml:"mitigations>mitigation"`
		} `xml:"vulnerabilities>vulnerability"`
	} `xml:"software_composition_analysis>vulnerable_components>component"`
}

type veracodePara struct {
	Text    string `xml:"text,attr"`
	Bullets []struct {
		Text string `xml:"text,attr"`
	} `xml:"bulletitem"`
}

type veracodeCWEBox struct {
	ID           string         `xml:"cweid,attr"`
	Name         string         `xml:"cwename,attr"`
	StaticFlaws  []veracodeFlaw `xml:"staticflaws>flaw"`
	DynamicFlaws []veracodeFlaw `xml:"dynamicflaws>flaw"`
}

type veracodeFlaw struct {
	Severity          string               `xml:"severity,attr"`
	CategoryName      string               `xml:"categoryname,attr"`
	CategoryID        string               `xml:"categoryid,attr"`
	IssueID           string               `xml:"issueid,attr"`
	Module            string               `xml:"module,attr"`
	Type              string               `xml:"type,attr"`
	Description       string               `xml:"description,attr"`
	CWE               string               `xml:"cweid,attr"`
	ExploitLevel      string               `xml:"exploitLevel,attr"`
	RemediationStatus string               `xml:"remediation_status,attr"`
	MitigationStatus  string               `xml:"mitigation_status,attr"`
	SourceFile        string               `xml:"sourcefile,attr"`
	SourceFilePath    string               `xml:"sourcefilepath,attr"`
	Line              string               `xml:"line,attr"`
	FunctionPrototype string               `xml:"functionprototype,attr"`
	URL               string               `xml:"url,attr"`
	VulnParameter     string               `xml:"vuln_parameter,attr"`
	Mitigations       []veracodeMitigation `xml:"mitigations>mitigation"`
}

type veracodeMitigation struct {
	Action      string `xml:"action,attr"`
	Description string `xml:"description,attr"`
}

// Parse implements Parser.
func (Veracode) Parse(r io.Reader) ([]ParsedFinding, error) {
	dec := xml.NewDecoder(r)
	dec.CharsetReader = veracodeCharsetReader
	var rep veracodeReport
	if err := dec.Decode(&rep); err != nil {
		if _, ok := errors.AsType[xml.UnmarshalError](err); ok {
			return nil, errors.New("decode veracode report: no <detailedreport> root — not a Veracode detailed XML report")
		}
		return nil, fmt.Errorf("decode veracode report: %w", err)
	}

	out := []ParsedFinding{}
	for _, sev := range rep.Severities {
		for _, cat := range sev.Categories {
			mitigation := veracodeText(cat.Recommendations)
			for _, cwe := range cat.CWEs {
				for _, fl := range cwe.StaticFlaws {
					if f, ok := veracodeFlawFinding(fl, cwe, mitigation); ok {
						f.FilePath = path.Join(fl.SourceFilePath, fl.SourceFile)
						if n, err := strconv.Atoi(fl.Line); err == nil && n > 0 {
							f.Line = new(n)
						}
						f.Metadata["module"] = fl.Module
						f.Metadata["function"] = fl.FunctionPrototype
						out = append(out, f)
					}
				}
				for _, fl := range cwe.DynamicFlaws {
					if f, ok := veracodeFlawFinding(fl, cwe, mitigation); ok {
						f.Category = domain.CategoryDAST
						f.FilePath, f.URL = fl.URL, fl.URL
						if fl.VulnParameter != "" {
							f.Metadata["parameter"] = fl.VulnParameter
						}
						out = append(out, f)
					}
				}
			}
		}
	}

	for _, c := range rep.Components {
		pkg, purl := c.Library, ""
		// library_id is "maven:group:artifact:version:" for Maven components.
		if parts := strings.Split(c.LibraryID, ":"); len(parts) >= 3 && parts[0] == "maven" {
			pkg = parts[1] + ":" + parts[2]
			purl = ecosystemPurl("maven", pkg, c.Version)
		}
		file := c.FileName
		if len(c.FilePaths) > 0 && c.FilePaths[0].Value != "" {
			file = c.FilePaths[0].Value
		}
		for _, v := range c.Vulnerabilities {
			meta := map[string]any{"component_file": c.FileName, "vendor": c.Vendor}
			if strings.EqualFold(v.Mitigation, "true") {
				veracodeTriage(meta, v.MitigationType, v.Mitigations)
			}
			f := ParsedFinding{
				Category:       domain.CategorySCA,
				RuleID:         v.CVE,
				Title:          fmt.Sprintf("%s in %s %s", v.CVE, firstNonEmpty(pkg, c.FileName), c.Version),
				Description:    strings.TrimSpace(v.Summary),
				Severity:       veracodeSeverity(v.Severity),
				CWE:            cweFrom(v.CWE),
				CVE:            cvesFrom(v.CVE),
				FilePath:       file,
				Package:        pkg,
				PackageVersion: c.Version,
				Purl:           purl,
				Metadata:       meta,
			}
			if score, err := strconv.ParseFloat(v.CVSS, 64); err == nil {
				f.CVSS = new(score)
				if v.Severity == "" {
					f.Severity = severityFromCVSS(score)
				}
			}
			out = append(out, f)
		}
	}
	return mergeSameLocation(out), nil
}

// veracodeFlawFinding maps the parts static and dynamic flaws share.
func veracodeFlawFinding(fl veracodeFlaw, cwe veracodeCWEBox, mitigation string) (ParsedFinding, bool) {
	if strings.EqualFold(fl.RemediationStatus, "Fixed") {
		return ParsedFinding{}, false
	}
	meta := map[string]any{
		"issue_id":           fl.IssueID,
		"flaw_type":          fl.Type,
		"remediation_status": fl.RemediationStatus,
		"mitigation_status":  fl.MitigationStatus,
	}
	if mitigation != "" {
		meta["mitigation"] = mitigation
	}
	if fl.ExploitLevel != "" {
		meta["exploit_level"] = fl.ExploitLevel
	}
	if strings.EqualFold(fl.MitigationStatus, "accepted") {
		veracodeTriage(meta, "", fl.Mitigations)
	}
	return ParsedFinding{
		Category:    domain.CategorySAST,
		RuleID:      firstNonEmpty(fl.CategoryID, fl.CWE),
		Title:       firstNonEmpty(fl.CategoryName, cwe.Name),
		Description: fl.Description,
		Severity:    veracodeSeverity(fl.Severity),
		CWE:         cweFrom(firstNonEmpty(fl.CWE, cwe.ID)),
		CVE:         cvesInText(fl.Description),
		Metadata:    meta,
	}, true
}

// veracodeTriage records an accepted mitigation. The mitigation's kind is the
// proposal (mitigation_type, or the proposing action in the mitigation
// history, e.g. "Mitigate by Design" or "Potential False Positive"); the
// approving action ("Accepted", "Approve Mitigation") is not a kind.
func veracodeTriage(meta map[string]any, kind string, history []veracodeMitigation) {
	reason := ""
	for _, m := range history {
		a := strings.ToLower(m.Action)
		if a == "accepted" || strings.HasPrefix(a, "approve") || a == "comment" {
			continue
		}
		if kind == "" {
			kind = m.Action
		}
		if reason == "" {
			reason = m.Description
		}
	}
	status := domain.FindingRiskAccepted
	if strings.Contains(strings.ToLower(kind), "false positive") {
		status = domain.FindingFalsePositive
	}
	text := "Veracode: mitigation accepted"
	if kind != "" {
		text += " (" + kind + ")"
	}
	if reason != "" {
		text += ": " + reason
	}
	setImportedStatus(meta, status, text, zeroTime)
}

// veracodeSeverity maps Veracode's 0–5 scale.
func veracodeSeverity(s string) domain.Severity {
	switch strings.TrimSpace(s) {
	case "5":
		return domain.SeverityCritical
	case "4":
		return domain.SeverityHigh
	case "3":
		return domain.SeverityMedium
	case "2":
		return domain.SeverityLow
	case "1", "0":
		return domain.SeverityInfo
	}
	return normalizeSeverity(s)
}

// veracodeText flattens <para text=…><bulletitem text=…/></para> blocks.
func veracodeText(paras []veracodePara) string {
	var b strings.Builder
	for _, p := range paras {
		if p.Text != "" {
			b.WriteString(p.Text)
			b.WriteByte('\n')
		}
		for _, bi := range p.Bullets {
			b.WriteString("- " + bi.Text + "\n")
		}
	}
	return strings.TrimSpace(b.String())
}

// veracodeCharsetReader decodes ISO-8859-1, the encoding Veracode declares.
func veracodeCharsetReader(charset string, in io.Reader) (io.Reader, error) {
	switch strings.ToLower(charset) {
	case "iso-8859-1", "latin1", "latin-1", "us-ascii":
		return &veracodeLatin1{r: bufio.NewReader(in)}, nil
	}
	return nil, fmt.Errorf("unsupported charset %q", charset)
}

// veracodeLatin1 transcodes ISO-8859-1 bytes (each a code point) to UTF-8.
type veracodeLatin1 struct{ r *bufio.Reader }

func (l *veracodeLatin1) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		c, err := l.r.ReadByte()
		if err != nil {
			if n > 0 {
				return n, nil
			}
			return 0, err
		}
		if c >= utf8.RuneSelf && n+2 > len(p) {
			_ = l.r.UnreadByte()
			if n == 0 {
				return 0, io.ErrShortBuffer
			}
			break
		}
		n += utf8.EncodeRune(p[n:], rune(c))
	}
	return n, nil
}
