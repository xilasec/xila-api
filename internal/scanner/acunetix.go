package scanner

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Acunetix parses Acunetix web-scanner results in two formats, sniffed from
// the content:
//
//   - the classic Acunetix (WVS) XML export (`wvs_console … /ExportXML`, or
//     Reports → Export → XML; root <ScanGroup>): rule = the scanner module
//     that raised the alert, location = the scan's start URL + the affected
//     path, CWEs/CVEs from the item's lists, severity from the item;
//   - the Acunetix 360 vulnerabilities JSON, which is Invicti's document
//     (same product line) and is mapped exactly like it (see Invicti).
//
// "informational" alerts are skipped. An item Acunetix marked IsFalsePositive
// (classic) or a FalsePositive / AcceptedRisk state (360) is carried as remote
// triage. Several alerts of one module on one path (one per cookie, say) are
// folded into one finding.
type Acunetix struct{}

// NewAcunetix constructs an Acunetix parser.
func NewAcunetix() Acunetix { return Acunetix{} }

// Scanner returns the tool identifier.
func (Acunetix) Scanner() string { return "acunetix" }

// PrimaryCategory is the scan-level category for Acunetix reports.
func (Acunetix) PrimaryCategory() domain.Category { return domain.CategoryDAST }

type acunetixScanGroup struct {
	XMLName xml.Name `xml:"ScanGroup"`
	Scans   []struct {
		StartURL string `xml:"StartURL"`
		Crawler  struct {
			StartURL string `xml:"StartUrl,attr"`
		} `xml:"Crawler"`
		WebServer string         `xml:"WebServer"`
		Items     []acunetixItem `xml:"ReportItems>ReportItem"`
	} `xml:"Scan"`
}

type acunetixItem struct {
	Name           string   `xml:"Name"`
	ModuleName     string   `xml:"ModuleName"`
	Details        string   `xml:"Details"`
	Affects        string   `xml:"Affects"`
	Parameter      string   `xml:"Parameter"`
	IsFalsePos     string   `xml:"IsFalsePositive"`
	Severity       string   `xml:"Severity"`
	Type           string   `xml:"Type"`
	Impact         string   `xml:"Impact"`
	Description    string   `xml:"Description"`
	Recommendation string   `xml:"Recommendation"`
	CWEs           []string `xml:"CWEList>CWE"`
	CVEs           []string `xml:"CVEList>CVE"`
	CVSS           string   `xml:"CVSS>Score"`
	CVSS3          string   `xml:"CVSS3>Score"`
	CVSS3Vector    string   `xml:"CVSS3>Descriptor"`
	References     []struct {
		Database string `xml:"Database"`
		URL      string `xml:"URL"`
	} `xml:"References>Reference"`
}

// Parse implements Parser.
func (Acunetix) Parse(r io.Reader) ([]ParsedFinding, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read acunetix report: %w", err)
	}
	raw = bytes.TrimSpace(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")))
	if !bytes.HasPrefix(raw, []byte("<")) {
		return invictiParse(raw, "acunetix360")
	}

	var rep acunetixScanGroup
	if err := xml.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("decode acunetix xml: %w", err)
	}
	var out []ParsedFinding
	for _, sc := range rep.Scans {
		base := strings.TrimRight(firstNonEmpty(strings.TrimSpace(sc.Crawler.StartURL), strings.TrimSpace(sc.StartURL)), "/")
		for _, it := range sc.Items {
			if f, ok := acunetixFinding(it, base); ok {
				out = append(out, f)
			}
		}
	}
	if out == nil {
		out = []ParsedFinding{}
	}
	return mergeSameLocation(out), nil
}

func acunetixFinding(it acunetixItem, base string) (ParsedFinding, bool) {
	sevText := strings.ToLower(strings.TrimSpace(it.Severity))
	if sevText == "informational" || sevText == "info" {
		return ParsedFinding{}, false
	}
	affects := strings.TrimSpace(it.Affects)
	text := func(s string) string { return strings.TrimSpace(html.UnescapeString(stripTags(s))) }

	desc := text(it.Description)
	if d := text(it.Details); d != "" {
		desc = strings.TrimSpace(desc + "\n\n" + d)
	}
	meta := map[string]any{"affects": affects}
	if p := strings.TrimSpace(it.Parameter); p != "" && p != "<empty>" {
		meta["parameter"] = p
	}
	for k, v := range map[string]string{
		"type":         strings.TrimSpace(it.Type),
		"module":       strings.TrimSpace(it.ModuleName),
		"impact":       text(it.Impact),
		"mitigation":   text(it.Recommendation),
		"cvss3_vector": strings.TrimSpace(it.CVSS3Vector),
	} {
		if v != "" {
			meta[k] = v
		}
	}
	var refs []string
	for _, ref := range it.References {
		if u := strings.TrimSpace(ref.URL); u != "" {
			refs = append(refs, u)
		}
	}
	if len(refs) > 0 {
		meta["references"] = refs
	}
	if strings.EqualFold(strings.TrimSpace(it.IsFalsePos), "true") {
		setImportedStatus(meta, domain.FindingFalsePositive, "Acunetix: IsFalsePositive", zeroTime)
	}

	f := ParsedFinding{
		Category:    domain.CategoryDAST,
		RuleID:      firstNonEmpty(strings.TrimSpace(it.ModuleName), strings.TrimSpace(it.Name)),
		Title:       strings.TrimSpace(it.Name),
		Description: desc,
		Severity:    normalizeSeverity(sevText),
		CVE:         cvesInText(append(cvesFrom(it.CVEs...), it.Details)...),
		FilePath:    base + affects,
		URL:         base,
		Metadata:    meta,
	}
	for _, c := range it.CWEs {
		if f.CWE = cweFrom(c); f.CWE != nil {
			break
		}
	}
	for _, s := range []string{it.CVSS3, it.CVSS} {
		if v, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil && v > 0 {
			f.CVSS = new(v)
			break
		}
	}
	return f, true
}
