package scanner

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Nikto parses Nikto web-server scan output in its JSON (`-Format json`) and XML
// (`-Format xml`) forms; the format is sniffed from the content. Every reported
// item is a finding whose rule_id is Nikto's test id ("999100").
//
// Nikto assigns no severity — the same output mixes "uncommon header" notes with
// default credentials — so every item is low: visible, but not ranked as if we
// knew better. Triage rules can raise specific test ids. CVEs named in a message
// are lifted for dedup/enrichment. Several observations of one test on one URL
// (e.g. two uncommon headers on "/") are folded into one finding.
type Nikto struct{}

// NewNikto constructs a Nikto parser.
func NewNikto() Nikto { return Nikto{} }

// Scanner returns the tool identifier.
func (Nikto) Scanner() string { return "nikto" }

// PrimaryCategory is the scan-level category for Nikto reports.
func (Nikto) PrimaryCategory() domain.Category { return domain.CategoryDAST }

type niktoJSONHost struct {
	Host            string `json:"host"`
	IP              string `json:"ip"`
	Port            string `json:"port"`
	Banner          string `json:"banner"`
	Vulnerabilities *[]struct {
		ID         string `json:"id"`
		OSVDB      string `json:"OSVDB"`
		Method     string `json:"method"`
		URL        string `json:"url"`
		Msg        string `json:"msg"`
		References string `json:"references"`
	} `json:"vulnerabilities"`
}

type niktoScanDetails struct {
	TargetIP       string `xml:"targetip,attr"`
	TargetHostname string `xml:"targethostname,attr"`
	TargetPort     string `xml:"targetport,attr"`
	TargetBanner   string `xml:"targetbanner,attr"`
	SiteName       string `xml:"sitename,attr"`
	Items          []struct {
		ID          string `xml:"id,attr"`
		OSVDBID     string `xml:"osvdbid,attr"`
		Method      string `xml:"method,attr"`
		Description string `xml:"description"`
		URI         string `xml:"uri"`
		NameLink    string `xml:"namelink"`
		References  string `xml:"references"`
	} `xml:"item"`
}

// niktoItem is one observation, normalized across the two formats.
type niktoItem struct {
	id, osvdb, method, uri, msg, refs string
	host, ip, port, banner            string
}

// Parse implements Parser.
func (Nikto) Parse(r io.Reader) ([]ParsedFinding, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read nikto report: %w", err)
	}
	raw = bytes.TrimSpace(raw)
	var items []niktoItem
	if bytes.HasPrefix(raw, []byte("<")) {
		items, err = niktoXML(raw)
	} else {
		items, err = niktoJSON(raw)
	}
	if err != nil {
		return nil, err
	}

	out := make([]ParsedFinding, 0, len(items))
	for _, it := range items {
		target := firstNonEmpty(it.host, it.ip)
		if it.port != "" && it.port != "80" && it.port != "443" {
			target += ":" + it.port
		}
		f := ParsedFinding{
			Category:    domain.CategoryDAST,
			RuleID:      it.id,
			Title:       it.msg,
			Description: it.msg,
			Severity:    domain.SeverityLow,
			CVE:         cvesInText(it.msg, it.refs),
			FilePath:    target + it.uri,
			URL:         target,
			Metadata: map[string]any{
				"method": it.method,
				"ip":     it.ip,
				"port":   it.port,
				"banner": it.banner,
			},
		}
		if it.osvdb != "" && it.osvdb != "0" {
			f.Metadata["osvdb"] = it.osvdb
		}
		if it.refs != "" {
			f.Metadata["references"] = it.refs
		}
		out = append(out, f)
	}
	return mergeSameLocation(out), nil
}

// niktoJSON reads one host object, or an array of them (several -h targets).
func niktoJSON(raw []byte) ([]niktoItem, error) {
	var hosts []niktoJSONHost
	if len(raw) > 0 && raw[0] == '[' {
		if err := json.Unmarshal(raw, &hosts); err != nil {
			return nil, fmt.Errorf("decode nikto json: %w", err)
		}
	} else {
		var h niktoJSONHost
		if err := json.Unmarshal(raw, &h); err != nil {
			return nil, fmt.Errorf("decode nikto json: %w", err)
		}
		hosts = []niktoJSONHost{h}
	}
	var items []niktoItem
	for _, h := range hosts {
		if h.Vulnerabilities == nil {
			return nil, errors.New("decode nikto json: no vulnerabilities array — not a Nikto JSON report")
		}
		for _, v := range *h.Vulnerabilities {
			items = append(items, niktoItem{
				id: v.ID, osvdb: v.OSVDB, method: v.Method, uri: v.URL, msg: v.Msg, refs: v.References,
				host: h.Host, ip: h.IP, port: h.Port, banner: h.Banner,
			})
		}
	}
	return items, nil
}

// niktoXML collects every <scandetails> block, whatever it is nested in — the
// root is <niktoscan>, wrapping another <niktoscan> per target in Nikto 2.1.6+.
func niktoXML(raw []byte) ([]niktoItem, error) {
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var items []niktoItem
	sawRoot := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode nikto xml: %w", err)
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "niktoscan":
			sawRoot = true
		case "scandetails":
			var sd niktoScanDetails
			if err := dec.DecodeElement(&sd, &se); err != nil {
				return nil, fmt.Errorf("decode nikto xml: %w", err)
			}
			for _, it := range sd.Items {
				items = append(items, niktoItem{
					id: it.ID, osvdb: it.OSVDBID, method: it.Method,
					uri: strings.TrimSpace(it.URI), msg: strings.TrimSpace(it.Description), refs: strings.TrimSpace(it.References),
					host: sd.TargetHostname, ip: sd.TargetIP, port: sd.TargetPort, banner: sd.TargetBanner,
				})
			}
		}
	}
	if !sawRoot {
		return nil, errors.New("decode nikto xml: no <niktoscan> root — not a Nikto XML report")
	}
	return items, nil
}
