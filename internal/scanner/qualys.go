package scanner

import (
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Qualys parses Qualys VM (vulnerability management) host detections in two
// export shapes, sniffed from the content:
//
//   - the XML "Scan Report" / asset data report (Reports → New → Scan Report,
//     format XML; root <ASSET_DATA_REPORT>): per-host <VULN_INFO> detections
//     that reference the QID knowledge base in the report's <GLOSSARY>;
//   - the CSV detection export (VMDR → Vulnerabilities → Download → CSV), one
//     row per host and QID.
//
// The rule is the QID. Qualys severity 1–5 maps to info, low, medium, high,
// critical. "Information gathered" detections (type Ig) are inventory, not
// vulnerabilities, and are skipped, as are detections whose status is Fixed;
// confirmed ("Vuln") and potential ("Practice") detections are kept and told
// apart in metadata. The location is the IP and, for service detections,
// "ip:port/protocol". Every CVE of the QID is lifted.
type Qualys struct{}

// NewQualys constructs a Qualys parser.
func NewQualys() Qualys { return Qualys{} }

// Scanner returns the tool identifier.
func (Qualys) Scanner() string { return "qualys" }

// PrimaryCategory is the scan-level category: Qualys VM is a network scanner.
func (Qualys) PrimaryCategory() domain.Category { return domain.CategoryDAST }

type qualysReport struct {
	XMLName xml.Name `xml:"ASSET_DATA_REPORT"`
	Hosts   []struct {
		IP      string `xml:"IP"`
		DNS     string `xml:"DNS"`
		NetBIOS string `xml:"NETBIOS"`
		OS      string `xml:"OPERATING_SYSTEM"`
		Vulns   []struct {
			QID       string `xml:"QID"`
			Type      string `xml:"TYPE"`
			Port      string `xml:"PORT"`
			Protocol  string `xml:"PROTOCOL"`
			SSL       string `xml:"SSL"`
			Result    string `xml:"RESULT"`
			FirstSeen string `xml:"FIRST_FOUND"`
			LastSeen  string `xml:"LAST_FOUND"`
			Status    string `xml:"VULN_STATUS"`
		} `xml:"VULN_INFO_LIST>VULN_INFO"`
	} `xml:"HOST_LIST>HOST"`
	Glossary []struct {
		QID      string   `xml:"QID"`
		Title    string   `xml:"TITLE"`
		Severity string   `xml:"SEVERITY"`
		Category string   `xml:"CATEGORY"`
		Threat   string   `xml:"THREAT"`
		Impact   string   `xml:"IMPACT"`
		Solution string   `xml:"SOLUTION"`
		CVEs     []string `xml:"CVE_ID_LIST>CVE_ID>ID"`
		CVSS     string   `xml:"CVSS_SCORE>CVSS_BASE"`
		CVSS3    string   `xml:"CVSS3_SCORE>CVSS3_BASE"`
		Vendor   []string `xml:"VENDOR_REFERENCE_LIST>VENDOR_REFERENCE>ID"`
		PCI      string   `xml:"PCI_FLAG"`
	} `xml:"GLOSSARY>VULN_DETAILS_LIST>VULN_DETAILS"`
}

// qualysDetection is one QID on one host, normalized across formats.
type qualysDetection struct {
	qid, title, typ, severity, category   string
	ip, dns, netbios, os                  string
	port, protocol, ssl                   string
	threat, impact, solution, result      string
	cvss, cvss3, firstSeen, lastSeen, pci string
	cves, vendorRefs                      []string
}

// Parse implements Parser.
func (Qualys) Parse(r io.Reader) ([]ParsedFinding, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read qualys report: %w", err)
	}
	raw = bytes.TrimSpace(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")))
	var dets []qualysDetection
	if bytes.HasPrefix(raw, []byte("<")) {
		dets, err = qualysXML(raw)
	} else {
		dets, err = qualysCSV(raw)
	}
	if err != nil {
		return nil, err
	}
	out := make([]ParsedFinding, 0, len(dets))
	for _, d := range dets {
		if f, ok := d.finding(); ok {
			out = append(out, f)
		}
	}
	return mergeSameLocation(out), nil
}

func qualysXML(raw []byte) ([]qualysDetection, error) {
	var rep qualysReport
	if err := xml.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("decode qualys xml: %w", err)
	}
	kb := make(map[string]int, len(rep.Glossary))
	for i, g := range rep.Glossary {
		kb[strings.TrimSpace(g.QID)] = i
	}
	var dets []qualysDetection
	for _, h := range rep.Hosts {
		for _, v := range h.Vulns {
			d := qualysDetection{
				qid: strings.TrimSpace(v.QID), typ: v.Type,
				ip: h.IP, dns: h.DNS, netbios: h.NetBIOS, os: h.OS,
				port: v.Port, protocol: v.Protocol, ssl: v.SSL, result: v.Result,
				firstSeen: v.FirstSeen, lastSeen: v.LastSeen,
			}
			if strings.EqualFold(strings.TrimSpace(v.Status), "fixed") {
				continue
			}
			if i, ok := kb[d.qid]; ok {
				g := rep.Glossary[i]
				d.title, d.severity, d.category = g.Title, g.Severity, g.Category
				d.threat, d.impact, d.solution = g.Threat, g.Impact, g.Solution
				d.cvss, d.cvss3, d.pci = g.CVSS, g.CVSS3, g.PCI
				d.cves, d.vendorRefs = g.CVEs, g.Vendor
			}
			dets = append(dets, d)
		}
	}
	return dets, nil
}

func qualysCSV(raw []byte) ([]qualysDetection, error) {
	cr := csv.NewReader(bytes.NewReader(raw))
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	// Exports may open with a few report-title rows; the header names IP and QID.
	var cols map[string]int
	for cols == nil {
		rec, err := cr.Read()
		if err == io.EOF {
			return nil, errors.New("qualys csv: no header row with IP and QID columns")
		}
		if err != nil {
			return nil, fmt.Errorf("decode qualys csv: %w", err)
		}
		c := map[string]int{}
		for i, h := range rec {
			h = strings.ToLower(strings.TrimSpace(h))
			if _, dup := c[h]; !dup {
				c[h] = i
			}
		}
		_, ip := c["ip"]
		_, qid := c["qid"]
		if ip && qid {
			cols = c
		}
	}
	var dets []qualysDetection
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode qualys csv: %w", err)
		}
		get := func(name string) string {
			if i, ok := cols[name]; ok && i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		if get("qid") == "" || strings.EqualFold(get("vuln status"), "fixed") {
			continue
		}
		dets = append(dets, qualysDetection{
			qid: get("qid"), title: get("title"), typ: get("type"), severity: get("severity"),
			category: get("category"),
			ip:       get("ip"), dns: firstNonEmpty(get("dns"), get("fqdn")), netbios: get("netbios"), os: get("os"),
			port: get("port"), protocol: get("protocol"), ssl: get("ssl"), result: get("results"),
			threat: get("threat"), impact: get("impact"), solution: get("solution"),
			cvss: get("cvss base"), cvss3: firstNonEmpty(get("cvss3 base"), get("cvss3.1 base")),
			firstSeen: get("first detected"), lastSeen: get("last detected"), pci: get("pci vuln"),
			cves:       strings.FieldsFunc(get("cve id"), func(r rune) bool { return r == ',' || r == ' ' }),
			vendorRefs: strings.FieldsFunc(get("vendor reference"), func(r rune) bool { return r == ',' || r == ' ' }),
		})
	}
	return dets, nil
}

// qualysSeverity maps Qualys's 1 (minimal) … 5 (urgent) scale.
func qualysSeverity(s string) domain.Severity {
	switch strings.TrimSpace(s) {
	case "1":
		return domain.SeverityInfo
	case "2":
		return domain.SeverityLow
	case "3":
		return domain.SeverityMedium
	case "4":
		return domain.SeverityHigh
	case "5":
		return domain.SeverityCritical
	}
	return normalizeSeverity(s)
}

// qualysScore reads "9.0 (AV:N/…)" and bare "9.0" CVSS cells.
func qualysScore(s string) (float64, bool) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0, false
	}
	v, err := strconv.ParseFloat(f[0], 64)
	return v, err == nil && v > 0
}

// qualysText turns the knowledge base's light HTML (<P>, <BR>) into text.
func qualysText(s string) string {
	return strings.TrimSpace(html.UnescapeString(stripTags(s)))
}

func (d qualysDetection) finding() (ParsedFinding, bool) {
	typ := strings.ToLower(strings.TrimSpace(d.typ))
	if typ == "ig" || strings.HasPrefix(typ, "info") {
		return ParsedFinding{}, false
	}
	loc := d.ip
	if d.port != "" {
		loc = fmt.Sprintf("%s:%s/%s", d.ip, d.port, strings.ToLower(d.protocol))
	}
	desc := qualysText(d.threat)
	if res := strings.TrimSpace(d.result); res != "" {
		desc = strings.TrimSpace(desc + "\n\nResult:\n" + res)
	}
	meta := map[string]any{"ip": d.ip, "port": d.port, "protocol": d.protocol}
	switch typ {
	case "vuln":
		meta["detection"] = "confirmed"
	case "practice", "potential":
		meta["detection"] = "potential"
	}
	for k, v := range map[string]string{
		"dns":        d.dns,
		"netbios":    d.netbios,
		"os":         d.os,
		"ssl":        d.ssl,
		"category":   d.category,
		"impact":     qualysText(d.impact),
		"mitigation": qualysText(d.solution),
		"first_seen": d.firstSeen,
		"last_seen":  d.lastSeen,
		"pci":        d.pci,
	} {
		if v != "" {
			meta[k] = v
		}
	}
	if len(d.vendorRefs) > 0 {
		meta["references"] = d.vendorRefs
	}
	f := ParsedFinding{
		Category:    domain.CategoryDAST,
		RuleID:      d.qid,
		Title:       firstNonEmpty(strings.TrimSpace(d.title), "QID "+d.qid),
		Description: desc,
		Severity:    qualysSeverity(d.severity),
		CVE:         cvesInText(cvesFrom(d.cves...)...),
		FilePath:    loc,
		URL:         d.ip,
		Metadata:    meta,
	}
	for _, s := range []string{d.cvss3, d.cvss} {
		if v, ok := qualysScore(s); ok {
			f.CVSS = new(v)
			break
		}
	}
	if strings.TrimSpace(d.severity) == "" && f.CVSS != nil {
		f.Severity = severityFromCVSS(*f.CVSS)
	}
	return f, true
}
