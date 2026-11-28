package scanner

import (
	"encoding/xml"
	"fmt"
	"io"
	"maps"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Nmap parses Nmap's XML output (`nmap -sV -oX out.xml …`, optionally with
// `--script vulners` or `--script vuln`). Three kinds of finding come out:
//
//   - every open port, as an info finding (rule "open-port") — network exposure
//     inventory: it is what the attack surface looks like, not a vulnerability,
//     and it auto-closes when the port does;
//   - each CVE the vulners script matched to a service's CPE (rule = the CVE),
//     severity from its CVSS. These are version-banner matches, not verified
//     exploitation — distro backports often patch without bumping the version —
//     so they're tagged "match": "service-version" for triage;
//   - each NSE vulns-library result whose state is VULNERABLE (rule = the
//     script id, e.g. "smb-vuln-ms17-010"): actively probed, so verified. Its
//     severity is the script's CVSS score, else its "Risk factor", else medium.
//
// Closed/filtered ports, down hosts and "NOT VULNERABLE" results are skipped.
type Nmap struct{}

// NewNmap constructs an Nmap parser.
func NewNmap() Nmap { return Nmap{} }

// Scanner returns the tool identifier.
func (Nmap) Scanner() string { return "nmap" }

// PrimaryCategory is the scan-level category for Nmap reports.
func (Nmap) PrimaryCategory() domain.Category { return domain.CategoryDAST }

type nmapRun struct {
	XMLName xml.Name `xml:"nmaprun"`
	Hosts   []struct {
		Status struct {
			State string `xml:"state,attr"`
		} `xml:"status"`
		Addresses []struct {
			Addr     string `xml:"addr,attr"`
			AddrType string `xml:"addrtype,attr"`
		} `xml:"address"`
		Hostnames []struct {
			Name string `xml:"name,attr"`
		} `xml:"hostnames>hostname"`
		Ports []struct {
			Protocol string `xml:"protocol,attr"`
			PortID   string `xml:"portid,attr"`
			State    struct {
				State string `xml:"state,attr"`
			} `xml:"state"`
			Service struct {
				Name      string   `xml:"name,attr"`
				Product   string   `xml:"product,attr"`
				Version   string   `xml:"version,attr"`
				ExtraInfo string   `xml:"extrainfo,attr"`
				CPEs      []string `xml:"cpe"`
			} `xml:"service"`
			Scripts []nmapScript `xml:"script"`
		} `xml:"ports>port"`
		HostScripts []nmapScript `xml:"hostscript>script"`
	} `xml:"host"`
}

type nmapScript struct {
	ID     string      `xml:"id,attr"`
	Output string      `xml:"output,attr"`
	Tables []nmapTable `xml:"table"`
	Elems  []nmapElem  `xml:"elem"`
}

type nmapTable struct {
	Key    string      `xml:"key,attr"`
	Tables []nmapTable `xml:"table"`
	Elems  []nmapElem  `xml:"elem"`
}

type nmapElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

func (t nmapTable) elem(key string) string {
	for _, e := range t.Elems {
		if e.Key == key {
			return strings.TrimSpace(e.Value)
		}
	}
	return ""
}

func (t nmapTable) table(key string) (nmapTable, bool) {
	for _, c := range t.Tables {
		if c.Key == key {
			return c, true
		}
	}
	return nmapTable{}, false
}

// nmapService is the context a script result was produced in.
type nmapService struct {
	target, ip, hostname, port, product, version, name string
}

// Parse implements Parser.
func (Nmap) Parse(r io.Reader) ([]ParsedFinding, error) {
	var run nmapRun
	if err := xml.NewDecoder(r).Decode(&run); err != nil {
		return nil, fmt.Errorf("decode nmap xml: %w", err)
	}

	var out []ParsedFinding
	for _, h := range run.Hosts {
		if h.Status.State != "" && h.Status.State != "up" {
			continue
		}
		ip := ""
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				ip = a.Addr
				break
			}
		}
		hostname := ""
		if len(h.Hostnames) > 0 {
			hostname = h.Hostnames[0].Name
		}
		host := firstNonEmpty(ip, hostname)

		for _, p := range h.Ports {
			if p.State.State != "open" {
				continue
			}
			svc := nmapService{
				target:   fmt.Sprintf("%s:%s/%s", host, p.PortID, p.Protocol),
				ip:       ip,
				hostname: hostname,
				port:     p.PortID + "/" + p.Protocol,
				name:     p.Service.Name,
				product:  p.Service.Product,
				version:  p.Service.Version,
			}
			desc := strings.TrimSpace(strings.Join([]string{p.Service.Name, p.Service.Product, p.Service.Version, p.Service.ExtraInfo}, " "))
			title := "Open port " + svc.port
			if desc != "" {
				title += " (" + strings.Join(strings.Fields(desc), " ") + ")"
			}
			out = append(out, ParsedFinding{
				Category:    domain.CategoryDAST,
				RuleID:      "open-port",
				Title:       title,
				Description: title + " on " + firstNonEmpty(hostname, host),
				Severity:    domain.SeverityInfo,
				FilePath:    svc.target,
				Metadata:    svc.metadata(map[string]any{"cpe": p.Service.CPEs}),
			})
			for _, s := range p.Scripts {
				out = append(out, nmapScriptFindings(s, svc)...)
			}
		}
		hostSvc := nmapService{target: host, ip: ip, hostname: hostname}
		for _, s := range h.HostScripts {
			out = append(out, nmapScriptFindings(s, hostSvc)...)
		}
	}
	return mergeSameLocation(out), nil
}

func (s nmapService) metadata(extra map[string]any) map[string]any {
	m := map[string]any{"ip": s.ip, "hostname": s.hostname}
	if s.port != "" {
		m["port"] = s.port
		m["service"] = s.name
		m["product"] = s.product
		m["version"] = s.version
	}
	maps.Copy(m, extra)
	return m
}

func nmapScriptFindings(s nmapScript, svc nmapService) []ParsedFinding {
	if s.ID == "vulners" {
		return nmapVulners(s, svc)
	}
	var out []ParsedFinding
	for _, t := range s.Tables {
		state := strings.ToUpper(t.elem("state"))
		if !strings.Contains(state, "VULNERABLE") || strings.Contains(state, "NOT VULNERABLE") {
			continue
		}
		title := firstNonEmpty(t.elem("title"), s.ID)
		var ids, refs, description []string
		if ts, ok := t.table("ids"); ok {
			for _, e := range ts.Elems {
				ids = append(ids, e.Value)
			}
		}
		if ts, ok := t.table("refs"); ok {
			for _, e := range ts.Elems {
				refs = append(refs, strings.TrimSpace(e.Value))
			}
		}
		if ts, ok := t.table("description"); ok {
			for _, e := range ts.Elems {
				description = append(description, strings.Join(strings.Fields(e.Value), " "))
			}
		}
		f := ParsedFinding{
			Category:    domain.CategoryDAST,
			RuleID:      s.ID,
			Title:       title,
			Description: strings.Join(description, "\n"),
			CVE:         cvesInText(append(ids, t.Key)...),
			FilePath:    svc.target,
			Package:     svc.product,
			Metadata:    svc.metadata(map[string]any{"state": state, "ids": ids, "match": "probe"}),
		}
		f.Severity = domain.SeverityMedium // a confirmed hit with no rating stays visible
		if risk := nmapRiskFactor(s.Output, title); risk != "" {
			f.Severity = normalizeSeverity(risk)
			f.Metadata["risk_factor"] = risk
		}
		if scores, ok := t.table("scores"); ok {
			for _, e := range scores.Elems {
				if v, err := strconv.ParseFloat(strings.TrimSpace(e.Value), 64); err == nil && v > 0 {
					f.CVSS, f.Severity = new(v), severityFromCVSS(v)
					break
				}
			}
		}
		if len(refs) > 0 {
			f.URL = refs[0]
		}
		out = append(out, f)
	}
	return out
}

// nmapRiskFactor finds the "Risk factor: HIGH" line the vulns library prints
// for the result titled title (the XML tables don't carry it).
func nmapRiskFactor(output, title string) string {
	if i := strings.Index(output, title); i >= 0 {
		output = output[i:]
	}
	_, rest, ok := strings.Cut(output, "Risk factor:")
	if !ok {
		return ""
	}
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// nmapVulners reads the vulners script: a table per CPE, each holding a table
// per known vulnerability {id, type, cvss, is_exploit}. Only CVE entries become
// findings; the exploit/advisory references vulners lists alongside them have
// no CVE to dedup or enrich on and repeat the CVEs' content.
func nmapVulners(s nmapScript, svc nmapService) []ParsedFinding {
	var out []ParsedFinding
	for _, cpe := range s.Tables {
		for _, v := range cpe.Tables {
			id := v.elem("id")
			cves := cvesFrom(id)
			if len(cves) == 0 {
				continue
			}
			product := strings.TrimSpace(svc.product + " " + svc.version)
			f := ParsedFinding{
				Category:       domain.CategoryDAST,
				RuleID:         cves[0],
				Title:          fmt.Sprintf("%s in %s", cves[0], firstNonEmpty(product, cpe.Key)),
				Description:    fmt.Sprintf("%s matched %s on %s by its version (vulners).", cves[0], cpe.Key, svc.target),
				Severity:       domain.SeverityMedium,
				CVE:            cves,
				FilePath:       svc.target,
				Package:        svc.product,
				PackageVersion: svc.version,
				URL:            "https://vulners.com/cve/" + cves[0],
				Metadata: svc.metadata(map[string]any{
					"cpe":        cpe.Key,
					"is_exploit": v.elem("is_exploit") == "true",
					"match":      "service-version",
				}),
			}
			if score, err := strconv.ParseFloat(v.elem("cvss"), 64); err == nil && score > 0 {
				f.CVSS, f.Severity = new(score), severityFromCVSS(score)
			}
			out = append(out, f)
		}
	}
	return out
}
