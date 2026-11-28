package scanner

import (
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

// OpenVAS parses Greenbone / OpenVAS (GVM) scan reports in the XML report
// format (Scans → Reports → download with the "XML" report format, or
// `gvm-cli … --xml '<get_reports report_id="…" details="1"/>'`). Each
// <result> is one NVT (vulnerability test) hit on one host/port.
//
// The rule is the NVT OID; the title is the NVT name (the result <name> can be
// a hash in some exports). Severity is GVM's threat class (High/Medium/Low,
// Critical on GVM 22.4+), else its CVSS score. "Log" and "Debug" results and
// severity 0.0 are informational and skipped. CVEs come from the NVT's refs
// (and the legacy <cve> element); the location is "host:port/protocol", or the
// host for "general/…" results. A "False Positive" threat (a GVM override)
// is carried as remote triage.
type OpenVAS struct{}

// NewOpenVAS constructs an OpenVAS parser.
func NewOpenVAS() OpenVAS { return OpenVAS{} }

// Scanner returns the tool identifier.
func (OpenVAS) Scanner() string { return "openvas" }

// PrimaryCategory is the scan-level category: OpenVAS is a network scanner.
func (OpenVAS) PrimaryCategory() domain.Category { return domain.CategoryDAST }

type openvasResult struct {
	Name string `xml:"name"`
	Host struct {
		IP       string `xml:",chardata"`
		Hostname string `xml:"hostname"`
	} `xml:"host"`
	Port string `xml:"port"`
	NVT  struct {
		OID      string `xml:"oid,attr"`
		Name     string `xml:"name"`
		Family   string `xml:"family"`
		CVSSBase string `xml:"cvss_base"`
		Tags     string `xml:"tags"`
		CVE      string `xml:"cve"`
		Solution struct {
			Type string `xml:"type,attr"`
			Text string `xml:",chardata"`
		} `xml:"solution"`
		Refs []struct {
			ID   string `xml:"id,attr"`
			Type string `xml:"type,attr"`
		} `xml:"refs>ref"`
	} `xml:"nvt"`
	Threat      string `xml:"threat"`
	Severity    string `xml:"severity"`
	QoD         string `xml:"qod>value"`
	Description string `xml:"description"`
}

var openvasCWEURL = regexp.MustCompile(`^(?:https?://)?(?:www\.)?cwe\.mitre\.org/data/definitions/(\d+)`)

// Parse implements Parser.
func (OpenVAS) Parse(r io.Reader) ([]ParsedFinding, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read openvas report: %w", err)
	}
	dec := xml.NewDecoder(bytes.NewReader(raw))
	var (
		stack   []string
		results []openvasResult
		sawRoot bool
	)
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode openvas xml: %w", err)
		}
		switch el := tok.(type) {
		case xml.StartElement:
			if len(stack) == 0 && el.Name.Local != "report" && el.Name.Local != "get_reports_response" {
				return nil, fmt.Errorf("decode openvas xml: unexpected root <%s>", el.Name.Local)
			}
			sawRoot = true
			if el.Name.Local == "result" && len(stack) > 0 && stack[len(stack)-1] == "results" {
				var res openvasResult
				if err := dec.DecodeElement(&res, &el); err != nil {
					return nil, fmt.Errorf("decode openvas result: %w", err)
				}
				results = append(results, res)
				continue
			}
			stack = append(stack, el.Name.Local)
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	if !sawRoot || len(stack) != 0 {
		return nil, errors.New("decode openvas xml: not a complete GVM report")
	}

	out := make([]ParsedFinding, 0, len(results))
	for _, res := range results {
		if f, ok := openvasFinding(res); ok {
			out = append(out, f)
		}
	}
	return mergeSameLocation(out), nil
}

func openvasFinding(res openvasResult) (ParsedFinding, bool) {
	score, scoreErr := strconv.ParseFloat(strings.TrimSpace(res.Severity), 64)
	threat := strings.TrimSpace(res.Threat)
	falsePositive := strings.EqualFold(threat, "False Positive")
	var sev domain.Severity
	switch strings.ToLower(threat) {
	case "log", "debug":
		return ParsedFinding{}, false
	case "", "false positive", "alarm":
		if scoreErr != nil || score <= 0 {
			return ParsedFinding{}, false
		}
		sev = severityFromCVSS(score)
	default:
		sev = normalizeSeverity(threat)
	}

	tags := openvasTags(res.NVT.Tags)
	host := strings.TrimSpace(res.Host.IP)
	hostname := strings.TrimSpace(res.Host.Hostname)
	port, proto, _ := strings.Cut(strings.TrimSpace(res.Port), "/")
	loc := firstNonEmpty(host, hostname)
	if _, err := strconv.Atoi(port); err == nil {
		loc = fmt.Sprintf("%s:%s/%s", loc, port, proto)
	}

	var (
		cves = cvesInText(res.NVT.CVE)
		refs []string
		cwe  *int
	)
	for _, ref := range res.NVT.Refs {
		switch strings.ToLower(ref.Type) {
		case "cve":
			cves = append(cves, cvesFrom(ref.ID)...)
		case "cwe":
			if cwe == nil {
				cwe = cweFrom(ref.ID)
			}
		case "url":
			refs = append(refs, ref.ID)
			if m := openvasCWEURL.FindStringSubmatch(ref.ID); m != nil && cwe == nil {
				cwe = cweFrom(m[1])
			}
		}
	}

	title := firstNonEmpty(strings.TrimSpace(res.NVT.Name), strings.TrimSpace(res.Name))
	desc := strings.TrimSpace(tags["summary"])
	for _, part := range []string{tags["insight"], res.Description} {
		if p := strings.TrimSpace(part); p != "" {
			desc = strings.TrimSpace(desc + "\n\n" + p)
		}
	}
	meta := map[string]any{
		"host":     host,
		"hostname": hostname,
		"port":     port,
		"protocol": proto,
	}
	for k, v := range map[string]string{
		"family":        res.NVT.Family,
		"qod":           res.QoD,
		"mitigation":    firstNonEmpty(strings.TrimSpace(res.NVT.Solution.Text), tags["solution"]),
		"solution_type": firstNonEmpty(res.NVT.Solution.Type, tags["solution_type"]),
		"impact":        tags["impact"],
		"affected":      tags["affected"],
		"threat":        threat,
	} {
		if v = strings.TrimSpace(v); v != "" {
			meta[k] = v
		}
	}
	if len(refs) > 0 {
		meta["references"] = refs
	}
	if falsePositive {
		setImportedStatus(meta, domain.FindingFalsePositive, "OpenVAS override: False Positive", zeroTime)
	}
	f := ParsedFinding{
		Category:    domain.CategoryDAST,
		RuleID:      res.NVT.OID,
		Title:       title,
		Description: desc,
		Severity:    sev,
		CWE:         cwe,
		CVE:         cvesInText(cves...),
		FilePath:    loc,
		URL:         firstNonEmpty(host, hostname),
		Metadata:    meta,
	}
	if scoreErr == nil && score > 0 {
		f.CVSS = floatPtr(score)
	}
	return f, true
}

// openvasTags splits the NVT's "summary=…|insight=…|solution=…" tag string.
func openvasTags(s string) map[string]string {
	tags := map[string]string{}
	for _, part := range strings.Split(s, "|") {
		if k, v, ok := strings.Cut(part, "="); ok {
			tags[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return tags
}
