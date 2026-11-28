package scanner

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Fortify parses Fortify Static Code Analyzer's FVDL (audit.fvdl) — the
// vulnerability detail XML Fortify itself writes for every finding — either
// as a bare XML file or (the common case) zipped inside the project's .fpr
// results archive alongside source snapshots and the human audit trail. We
// already accept many SAST tools' SARIF output, but Fortify's SARIF export
// carries neither the taint source/sink nor the engine's own severity model,
// so the native FVDL is worth a dedicated parser.
type Fortify struct{}

// NewFortify constructs a Fortify parser.
func NewFortify() Fortify { return Fortify{} }

// Scanner returns the tool identifier.
func (Fortify) Scanner() string { return "fortify" }

// PrimaryCategory is the scan-level category for Fortify reports.
func (Fortify) PrimaryCategory() domain.Category { return domain.CategorySAST }

type fortifyFVDL struct {
	XMLName         xml.Name               `xml:"FVDL"`
	Vulnerabilities []fortifyVulnerability `xml:"Vulnerabilities>Vulnerability"`
	Descriptions    []fortifyDescription   `xml:"Description"`
	EngineData      struct {
		RuleInfo []fortifyRule `xml:"RuleInfo>Rule"`
	} `xml:"EngineData"`
}

type fortifyVulnerability struct {
	ClassInfo struct {
		ClassID         string `xml:"ClassID"`
		Kingdom         string `xml:"Kingdom"`
		Type            string `xml:"Type"`
		Subtype         string `xml:"Subtype"`
		DefaultSeverity string `xml:"DefaultSeverity"`
	} `xml:"ClassInfo"`
	InstanceInfo struct {
		InstanceID       string `xml:"InstanceID"`
		InstanceSeverity string `xml:"InstanceSeverity"`
		Confidence       string `xml:"Confidence"`
	} `xml:"InstanceInfo"`
	AnalysisInfo struct {
		Unified struct {
			Trace struct {
				Primary struct {
					Entry []struct {
						Node struct {
							SourceLocation struct {
								Path string `xml:"path,attr"`
								Line string `xml:"line,attr"`
							} `xml:"SourceLocation"`
						} `xml:"Node"`
					} `xml:"Entry"`
				} `xml:"Primary"`
			} `xml:"Trace"`
		} `xml:"Unified"`
	} `xml:"AnalysisInfo"`
}

type fortifyDescription struct {
	ClassID    string `xml:"classID,attr"`
	Abstract   string `xml:"Abstract"`
	References struct {
		Reference []struct {
			Title string `xml:"Title"`
		} `xml:"Reference"`
	} `xml:"References"`
}

// fortifyRule is one EngineData/RuleInfo/Rule: the rule metadata (impact,
// accuracy, probability, CWE mapping) behind a vulnerability's ClassID. Not
// every FVDL carries EngineData — fortifySeverity/fortifyCWE fall back when
// it's absent.
type fortifyRule struct {
	ID       string `xml:"id,attr"`
	MetaInfo struct {
		Group []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:",chardata"`
		} `xml:"Group"`
	} `xml:"MetaInfo"`
}

func (r fortifyRule) group(name string) (float64, bool) {
	for _, g := range r.MetaInfo.Group {
		if g.Name == name {
			v, err := strconv.ParseFloat(strings.TrimSpace(g.Value), 64)
			return v, err == nil
		}
	}
	return 0, false
}

func (r fortifyRule) cwe() string {
	for _, g := range r.MetaInfo.Group {
		if g.Name == "altcategoryCWE" {
			return g.Value
		}
	}
	return ""
}

var fortifyCWEInText = regexp.MustCompile(`CWE ID (\d+)`)
var fortifyTagRe = regexp.MustCompile(`<[^>]*>`)

// Parse implements Parser.
func (Fortify) Parse(r io.Reader) ([]ParsedFinding, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read fortify report: %w", err)
	}
	fvdl, err := readFVDL(raw)
	if err != nil {
		return nil, err
	}

	rules := make(map[string]fortifyRule, len(fvdl.EngineData.RuleInfo))
	for _, rule := range fvdl.EngineData.RuleInfo {
		rules[rule.ID] = rule
	}
	descByClass := make(map[string]fortifyDescription, len(fvdl.Descriptions))
	for _, d := range fvdl.Descriptions {
		descByClass[d.ClassID] = d
	}

	type classInfo struct{ kingdom, typ, subtype, defaultSeverity string }
	seen := map[string]classInfo{}

	out := make([]ParsedFinding, 0, len(fvdl.Vulnerabilities))
	for _, v := range fvdl.Vulnerabilities {
		classID := v.ClassInfo.ClassID
		ci := classInfo{v.ClassInfo.Kingdom, v.ClassInfo.Type, v.ClassInfo.Subtype, v.ClassInfo.DefaultSeverity}
		if ci.typ == "" {
			// FVDL omits ClassInfo's descriptive fields on repeat occurrences
			// of a ClassID already introduced earlier in the document.
			if cached, ok := seen[classID]; ok {
				ci = cached
			}
		} else {
			seen[classID] = ci
		}

		title := ci.typ
		if ci.subtype != "" {
			title += ": " + ci.subtype
		}
		title = firstNonEmpty(title, classID)

		f := ParsedFinding{
			Category: domain.CategorySAST,
			RuleID:   classID,
			Title:    title,
			Severity: fortifySeverity(rules[classID], ci.defaultSeverity, v.InstanceInfo.InstanceSeverity, v.InstanceInfo.Confidence),
			Metadata: map[string]any{
				"kingdom":     ci.kingdom,
				"instance_id": v.InstanceInfo.InstanceID,
				"confidence":  v.InstanceInfo.Confidence,
			},
		}
		if desc, ok := descByClass[classID]; ok {
			f.Description = stripFortifyMarkup(desc.Abstract)
			f.CWE = fortifyCWE(rules[classID], desc)
		}
		if path, line := fortifySourceLocation(v); path != "" {
			f.FilePath = path
			if n, err := strconv.Atoi(line); err == nil && n > 0 {
				f.Line = new(n)
			}
		}
		out = append(out, f)
	}
	return out, nil
}

// readFVDL accepts a bare FVDL XML document, or an .fpr zip archive (what
// Fortify's own tooling produces) and reads its embedded audit.fvdl.
func readFVDL(raw []byte) (fortifyFVDL, error) {
	var doc fortifyFVDL
	if bytes.HasPrefix(raw, []byte("PK\x03\x04")) {
		zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			return doc, fmt.Errorf("decode fortify .fpr: %w", err)
		}
		var fvdlFile *zip.File
		for _, f := range zr.File {
			if strings.EqualFold(f.Name, "audit.fvdl") {
				fvdlFile = f
				break
			}
		}
		if fvdlFile == nil {
			return doc, errors.New("decode fortify .fpr: no audit.fvdl in archive")
		}
		rc, err := fvdlFile.Open()
		if err != nil {
			return doc, fmt.Errorf("open audit.fvdl: %w", err)
		}
		defer rc.Close()
		raw, err = io.ReadAll(rc)
		if err != nil {
			return doc, fmt.Errorf("read audit.fvdl: %w", err)
		}
	}
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return doc, fmt.Errorf("decode fortify FVDL: %w", err)
	}
	if doc.XMLName.Local != "FVDL" {
		return doc, errors.New("decode fortify report: no <FVDL> root — not a Fortify audit.fvdl")
	}
	return doc, nil
}

// fortifySourceLocation returns the path/line of a vulnerability's primary
// trace entry — the sink Fortify reports the issue at.
func fortifySourceLocation(v fortifyVulnerability) (path, line string) {
	for _, e := range v.AnalysisInfo.Unified.Trace.Primary.Entry {
		if e.Node.SourceLocation.Path != "" {
			return e.Node.SourceLocation.Path, e.Node.SourceLocation.Line
		}
	}
	return "", ""
}

// fortifySeverity mirrors Fortify's own priority model: impact (how bad) ×
// likelihood — accuracy × confidence × probability / 25, per Fortify's own
// support documentation — when the engine's rule metadata (EngineData) is
// present; the rule's default severity or the instance's own 0.0–5.0
// InstanceSeverity score otherwise. Never a gradient we invented: every
// branch reads a score Fortify itself computed.
func fortifySeverity(rule fortifyRule, defaultSeverity, instanceSeverity, confidence string) domain.Severity {
	impact, iok := rule.group("Impact")
	accuracy, aok := rule.group("Accuracy")
	probability, pok := rule.group("Probability")
	conf, confErr := strconv.ParseFloat(strings.TrimSpace(confidence), 64)
	if iok && aok && pok && confErr == nil {
		likelihood := accuracy * conf * probability / 25
		switch {
		case impact >= 2.5 && likelihood >= 2.5:
			return domain.SeverityCritical
		case impact >= 2.5:
			return domain.SeverityHigh
		case likelihood >= 2.5:
			return domain.SeverityMedium
		default:
			return domain.SeverityLow
		}
	}
	if defaultSeverity != "" {
		return normalizeSeverity(defaultSeverity)
	}
	if score, err := strconv.ParseFloat(strings.TrimSpace(instanceSeverity), 64); err == nil {
		switch {
		case score >= 4:
			return domain.SeverityCritical
		case score >= 2.5:
			return domain.SeverityHigh
		case score >= 1:
			return domain.SeverityMedium
		case score > 0:
			return domain.SeverityLow
		}
	}
	return domain.SeverityMedium
}

// fortifyCWE prefers the rule's own altcategoryCWE mapping (EngineData) and
// falls back to the CWE id Fortify's canned description cites in its
// references ("CWE ID 79, 80" — the first id is kept, matching how
// Finding.CWE holds a single integer).
func fortifyCWE(rule fortifyRule, desc fortifyDescription) *int {
	if m := fortifyCWEInText.FindStringSubmatch(rule.cwe()); m != nil {
		return cweFrom(m[1])
	}
	for _, ref := range desc.References.Reference {
		if m := fortifyCWEInText.FindStringSubmatch(ref.Title); m != nil {
			return cweFrom(m[1])
		}
	}
	return nil
}

// stripFortifyMarkup strips Fortify's pseudo-XML description markup
// (<Content>, <Paragraph>, <Replace key="..."/> placeholders) down to plain
// prose.
func stripFortifyMarkup(s string) string {
	return strings.TrimSpace(fortifyTagRe.ReplaceAllString(s, ""))
}
