package scanner

import (
	"bytes"
	"encoding/csv"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Nessus parses Tenable Nessus / Tenable.io / Tenable.sc vulnerability scan
// results in either of the two shapes they are exported as, sniffed from the
// content:
//
//   - the `.nessus` v2 XML file (Nessus "Export → Nessus", or
//     `GET /scans/{id}/export?format=nessus`): one <ReportItem> per plugin hit
//     on a host/port;
//   - the CSV vulnerability export (Nessus/Tenable.io "Export → CSV", Tenable.sc
//     "Vulnerability Analysis → Export as CSV"). Tenable.io writes one row per
//     CVE of a plugin hit; those rows are folded back into one finding.
//
// The rule is the plugin id; the location is the host and, when the plugin ran
// against a service, "host:port/protocol" (host, IP, port and protocol are also
// kept in metadata). Severity is Nessus's own rating (0 None … 4 Critical);
// severity-0 "None" plugins are informational inventory (OS detection, open
// services, traceroute…) and are skipped. Every CVE the plugin lists is lifted.
type Nessus struct{}

// NewNessus constructs a Nessus parser.
func NewNessus() Nessus { return Nessus{} }

// Scanner returns the tool identifier.
func (Nessus) Scanner() string { return "nessus" }

// PrimaryCategory is the scan-level category: Nessus is a network scanner.
func (Nessus) PrimaryCategory() domain.Category { return domain.CategoryDAST }

type nessusReport struct {
	XMLName xml.Name `xml:"NessusClientData_v2"`
	Reports []struct {
		Hosts []nessusHost `xml:"ReportHost"`
	} `xml:"Report"`
}

type nessusHost struct {
	Name       string `xml:"name,attr"`
	Properties []struct {
		Name  string `xml:"name,attr"`
		Value string `xml:",chardata"`
	} `xml:"HostProperties>tag"`
	Items []nessusItem `xml:"ReportItem"`
}

type nessusItem struct {
	Port             string   `xml:"port,attr"`
	Service          string   `xml:"svc_name,attr"`
	Protocol         string   `xml:"protocol,attr"`
	Severity         string   `xml:"severity,attr"`
	PluginID         string   `xml:"pluginID,attr"`
	PluginName       string   `xml:"pluginName,attr"`
	PluginFamily     string   `xml:"pluginFamily,attr"`
	Synopsis         string   `xml:"synopsis"`
	Description      string   `xml:"description"`
	Solution         string   `xml:"solution"`
	SeeAlso          string   `xml:"see_also"`
	PluginOutput     string   `xml:"plugin_output"`
	RiskFactor       string   `xml:"risk_factor"`
	CVSS3Score       string   `xml:"cvss3_base_score"`
	CVSS3Vector      string   `xml:"cvss3_vector"`
	CVSSScore        string   `xml:"cvss_base_score"`
	CVEs             []string `xml:"cve"`
	CWEs             []string `xml:"cwe"`
	CPE              string   `xml:"cpe"`
	ExploitAvailable string   `xml:"exploit_available"`
}

// nessusHit is one plugin result on one host/port, normalized across formats.
type nessusHit struct {
	pluginID, name, family    string
	host, ip, fqdn            string
	port, protocol, service   string
	severity                  domain.Severity
	synopsis, desc, output    string
	solution, seeAlso         string
	cvss3, cvss               string
	cvss3Vector, cpe, exploit string
	cves, cwes                []string
	state                     string
}

// Parse implements Parser.
func (Nessus) Parse(r io.Reader) ([]ParsedFinding, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read nessus report: %w", err)
	}
	raw = bytes.TrimSpace(bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")))
	var hits []nessusHit
	if bytes.HasPrefix(raw, []byte("<")) {
		hits, err = nessusXML(raw)
	} else {
		hits, err = nessusCSV(raw)
	}
	if err != nil {
		return nil, err
	}
	out := make([]ParsedFinding, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.finding())
	}
	return mergeSameLocation(out), nil
}

func nessusXML(raw []byte) ([]nessusHit, error) {
	var rep nessusReport
	if err := xml.Unmarshal(raw, &rep); err != nil {
		return nil, fmt.Errorf("decode nessus xml: %w", err)
	}
	var hits []nessusHit
	for _, rp := range rep.Reports {
		for _, h := range rp.Hosts {
			props := map[string]string{}
			for _, p := range h.Properties {
				props[p.Name] = strings.TrimSpace(p.Value)
			}
			for _, it := range h.Items {
				sev, ok := nessusSeverity(it.Severity, it.RiskFactor)
				if !ok {
					continue
				}
				hits = append(hits, nessusHit{
					pluginID:    it.PluginID,
					name:        it.PluginName,
					family:      it.PluginFamily,
					host:        firstNonEmpty(h.Name, props["host-fqdn"], props["host-ip"]),
					ip:          props["host-ip"],
					fqdn:        props["host-fqdn"],
					port:        it.Port,
					protocol:    it.Protocol,
					service:     it.Service,
					severity:    sev,
					synopsis:    it.Synopsis,
					desc:        it.Description,
					output:      it.PluginOutput,
					solution:    it.Solution,
					seeAlso:     it.SeeAlso,
					cvss3:       it.CVSS3Score,
					cvss:        it.CVSSScore,
					cvss3Vector: it.CVSS3Vector,
					cpe:         it.CPE,
					exploit:     it.ExploitAvailable,
					cves:        it.CVEs,
					cwes:        it.CWEs,
				})
			}
		}
	}
	return hits, nil
}

// nessusCSV reads the Nessus / Tenable.io / Tenable.sc CSV exports. Their
// column names differ ("Plugin ID" vs "Plugin", "Host" vs "IP Address", a
// numeric vs a named "Severity"), so columns are looked up by every known name.
func nessusCSV(raw []byte) ([]nessusHit, error) {
	cr := csv.NewReader(bytes.NewReader(raw))
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("decode nessus csv: %w", err)
	}
	cols := map[string]int{}
	for i, h := range header {
		h = strings.ToLower(strings.TrimSpace(h))
		if _, dup := cols[h]; !dup && h != "" {
			cols[h] = i
		}
	}
	if _, ok := nessusCol(cols, nil, "plugin id", "plugin"); !ok {
		return nil, errors.New("nessus csv: no Plugin ID column")
	}

	var hits []nessusHit
	idx := map[string]int{} // plugin/host/port/protocol → hits index
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode nessus csv: %w", err)
		}
		get := func(names ...string) string {
			v, _ := nessusCol(cols, rec, names...)
			return v
		}
		plugin := get("plugin id", "plugin")
		if plugin == "" {
			continue // blank trailing rows
		}
		if strings.EqualFold(get("vulnerability state"), "fixed") {
			continue
		}
		sev, ok := nessusSeverity(firstNonEmpty(get("risk"), get("severity")), get("risk factor"))
		if !ok {
			continue
		}
		h := nessusHit{
			pluginID:    plugin,
			name:        get("name", "plugin name"),
			family:      get("plugin family", "family"),
			host:        firstNonEmpty(get("host"), get("dns name", "fqdn"), get("ip address")),
			ip:          get("ip address"),
			fqdn:        get("fqdn", "dns name"),
			port:        get("port"),
			protocol:    strings.ToLower(get("protocol")),
			service:     get("service"),
			severity:    sev,
			synopsis:    get("synopsis"),
			desc:        get("description"),
			output:      strings.TrimPrefix(get("plugin output", "plugin text"), "Plugin Output:"),
			solution:    get("solution"),
			seeAlso:     get("see also"),
			cvss3:       get("cvss3 base score", "cvss v3 base score"),
			cvss:        get("cvss base score", "cvss v2 base score", "cvss"),
			cvss3Vector: get("cvss3 vector", "cvss v3 vector"),
			cpe:         get("cpe"),
			exploit:     get("exploit available", "exploit?"),
			cves:        strings.FieldsFunc(get("cve"), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }),
			state:       get("vulnerability state"),
		}
		key := strings.Join([]string{h.pluginID, h.host, h.port, h.protocol}, "\x00")
		if i, seen := idx[key]; seen {
			hits[i].cves = append(hits[i].cves, h.cves...)
			continue
		}
		idx[key] = len(hits)
		hits = append(hits, h)
	}
	return hits, nil
}

// nessusCol returns the first present column among names (rec nil: presence only).
func nessusCol(cols map[string]int, rec []string, names ...string) (string, bool) {
	for _, n := range names {
		i, ok := cols[n]
		if !ok {
			continue
		}
		if rec == nil {
			return "", true
		}
		if i < len(rec) {
			if v := strings.TrimSpace(rec[i]); v != "" {
				return v, true
			}
		}
	}
	return "", false
}

// nessusSeverity maps Nessus's 0–4 severity (or its name) onto ours; ok is
// false for "None"/0, the informational plugins.
func nessusSeverity(sev, riskFactor string) (domain.Severity, bool) {
	s := strings.TrimSpace(sev)
	if s == "" {
		s = strings.TrimSpace(riskFactor)
	}
	switch strings.ToLower(s) {
	case "0", "none", "info", "informational", "":
		return "", false
	case "1":
		return domain.SeverityLow, true
	case "2":
		return domain.SeverityMedium, true
	case "3":
		return domain.SeverityHigh, true
	case "4":
		return domain.SeverityCritical, true
	}
	return normalizeSeverity(s), true
}

func (h nessusHit) finding() ParsedFinding {
	loc := h.host
	if h.port != "" && h.port != "0" {
		loc = fmt.Sprintf("%s:%s/%s", h.host, h.port, h.protocol)
	}
	desc := strings.TrimSpace(strings.TrimSpace(h.synopsis) + "\n\n" + strings.TrimSpace(h.desc))
	if out := strings.TrimSpace(h.output); out != "" {
		desc += "\n\nPlugin output:\n" + out
	}
	meta := map[string]any{
		"host":     h.host,
		"port":     h.port,
		"protocol": h.protocol,
	}
	for k, v := range map[string]string{
		"ip":                h.ip,
		"fqdn":              h.fqdn,
		"service":           h.service,
		"plugin_family":     h.family,
		"mitigation":        strings.TrimSpace(h.solution),
		"cvss3_vector":      h.cvss3Vector,
		"cpe":               h.cpe,
		"exploit_available": h.exploit,
		"state":             h.state,
	} {
		if v != "" {
			meta[k] = v
		}
	}
	if refs := strings.Fields(h.seeAlso); len(refs) > 0 {
		meta["references"] = refs
	}
	f := ParsedFinding{
		Category:    domain.CategoryDAST,
		RuleID:      h.pluginID,
		Title:       h.name,
		Description: desc,
		Severity:    h.severity,
		CVE:         cvesInText(cvesFrom(h.cves...)...),
		FilePath:    loc,
		URL:         h.host,
		Metadata:    meta,
	}
	for _, c := range h.cwes {
		if f.CWE = cweFrom(c); f.CWE != nil {
			break
		}
	}
	if len(h.cwes) > 1 {
		meta["cwes"] = h.cwes
	}
	for _, s := range []string{h.cvss3, h.cvss} {
		if v, err := strconv.ParseFloat(s, 64); err == nil && v > 0 {
			f.CVSS = new(v)
			break
		}
	}
	return f
}
