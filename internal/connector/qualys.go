package connector

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	xrv "github.com/mattermost/xml-roundtrip-validator"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
)

// Qualys VMDR Host Detection List, per its API reference
// (https://docs.qualys.com/en/vm/qweb-all-api/mergedProjects/qapi-assets/host_lists/host_detection.htm)
// and the Host List Detection API sample output
// (https://github.com/QualysAPI/Qualys-API-Doc-Center, "Host List Detection
// API samples/Sample 1"):
//
//   - GET/POST {base_url}/api/2.0/fo/asset/host/vm/detection/?action=list,
//     HTTP Basic auth plus the required `X-Requested-With` header, XML
//     response; truncated results carry a `<WARNING><URL>` with the next
//     page's full URL (the API's own cursor, like Tenable's chunk list).
//   - QID is the detection's identity (`rule_id`); its CVEs come from one
//     `GET .../fo/knowledge_base/vuln/?action=list&ids=<qids>` lookup over
//     every distinct QID the pull saw, cached for that pull (a QID repeats
//     across many hosts). A failed or empty lookup leaves CVEs unset rather
//     than failing the pull: it only enriches identity, and the finding is
//     still actionable by QID and host.
//
// Status FIXED detections aren't fetched (so the next pull auto-closes them,
// like a fixed Tenable vulnerability); IS_DISABLED detections are skipped the
// same way. IS_IGNORED carries over as a remote triage verdict, matching
// Tenable's accepted-risk and Wiz's rejected-finding precedent.
const qualysRequestedWith = "Xila connector (github.com/xilasec/xila-api)"

type qualys struct {
	base, filter, username, password string
	hc                               *http.Client
}

type qualysCredentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func parseQualysCredentials(token string) (qualysCredentials, error) {
	var c qualysCredentials
	if err := json.Unmarshal([]byte(token), &c); err != nil || c.Username == "" || c.Password == "" {
		return qualysCredentials{}, invalid(`token must be JSON {"username": "...", "password": "..."}`)
	}
	return c, nil
}

func (q *qualys) basicAuth() string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(q.username+":"+q.password))
}

// get issues a GET with Basic auth, retrying on 429 like httpJSON, and
// returns the raw, size-bounded response body (XML, not JSON — httpJSON
// decodes JSON, so this is its own small twin).
func (q *qualys) get(ctx context.Context, rawURL string) ([]byte, error) {
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			return nil, remoteErr("build request: %v", err)
		}
		req.Header.Set("Authorization", q.basicAuth())
		req.Header.Set("X-Requested-With", qualysRequestedWith)
		resp, err := q.hc.Do(req)
		if err != nil {
			return nil, RemoteError{msg: "GET " + req.URL.Path + ": request failed", detail: err.Error()}
		}
		if resp.StatusCode == http.StatusTooManyRequests && attempt < maxRateLimitRetries {
			wait, ok := retryAfter(resp.Header)
			resp.Body.Close()
			if !ok {
				wait = time.Duration(1<<uint(attempt)) * time.Second
			}
			if wait > maxRateLimitWait {
				wait = maxRateLimitWait
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
		if err != nil {
			return nil, remoteErr("read response: %v", err)
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			snippet := string(body)
			if len(snippet) > 500 {
				snippet = snippet[:500]
			}
			return nil, RemoteError{msg: fmt.Sprintf("GET %s: status %d", req.URL.Path, resp.StatusCode), detail: snippet}
		}
		return body, nil
	}
}

func decodeQualysXML(body []byte, dst any) error {
	if err := xrv.Validate(bytes.NewReader(body)); err != nil {
		return remoteErr("malformed xml: %v", err)
	}
	if err := xml.NewDecoder(bytes.NewReader(body)).Decode(dst); err != nil {
		return remoteErr("decode xml: %v", err)
	}
	return nil
}

type qualysDetection struct {
	QID        int    `xml:"QID"`
	Type       string `xml:"TYPE"`
	Severity   int    `xml:"SEVERITY"`
	Port       int    `xml:"PORT"`
	Protocol   string `xml:"PROTOCOL"`
	Results    string `xml:"RESULTS"`
	Status     string `xml:"STATUS"`
	IsIgnored  int    `xml:"IS_IGNORED"`
	IsDisabled int    `xml:"IS_DISABLED"`
}

type qualysHost struct {
	ID         string            `xml:"ID"`
	IP         string            `xml:"IP"`
	DNS        string            `xml:"DNS"`
	NetBIOS    string            `xml:"NETBIOS"`
	OS         string            `xml:"OS"`
	Detections []qualysDetection `xml:"DETECTION_LIST>DETECTION"`
}

type qualysDetectionOutput struct {
	XMLName  xml.Name `xml:"HOST_LIST_VM_DETECTION_OUTPUT"`
	Response struct {
		HostList []qualysHost `xml:"HOST_LIST>HOST"`
		Warning  *struct {
			URL string `xml:"URL"`
		} `xml:"WARNING"`
	} `xml:"RESPONSE"`
}

func (q *qualys) Check(ctx context.Context) (string, error) {
	body, err := q.get(ctx, q.base+"/api/2.0/fo/asset/host/vm/detection/?action=list&truncation_limit=1")
	if err != nil {
		return "", err
	}
	var out qualysDetectionOutput
	if err := decodeQualysXML(body, &out); err != nil {
		return "", err
	}
	return "Qualys VMDR", nil
}

type qualysVuln struct {
	QID     int      `xml:"QID"`
	Title   string   `xml:"TITLE"`
	CveList []string `xml:"CVE_LIST>CVE>ID"`
}

type qualysKBOutput struct {
	XMLName  xml.Name `xml:"KNOWLEDGE_BASE_VULN_LIST_OUTPUT"`
	Response struct {
		VulnList []qualysVuln `xml:"VULN_LIST>VULN"`
	} `xml:"RESPONSE"`
}

type qualysKBEntry struct {
	title string
	cves  []string
}

// knowledgeBase looks up title and CVEs for every QID seen in this pull. A
// failed lookup returns an empty map rather than an error: the finding is
// still created, by QID, without a title or CVE.
func (q *qualys) knowledgeBase(ctx context.Context, qids []int) map[int]qualysKBEntry {
	if len(qids) == 0 {
		return nil
	}
	ids := make([]string, len(qids))
	for i, id := range qids {
		ids[i] = strconv.Itoa(id)
	}
	body, err := q.get(ctx, q.base+"/api/2.0/fo/knowledge_base/vuln/?action=list&details=Basic&ids="+strings.Join(ids, ","))
	if err != nil {
		return nil
	}
	var out qualysKBOutput
	if decodeQualysXML(body, &out) != nil {
		return nil
	}
	m := make(map[int]qualysKBEntry, len(out.Response.VulnList))
	for _, v := range out.Response.VulnList {
		cves := []string{}
		for _, c := range v.CveList {
			cves = addCVE(cves, c)
		}
		m[v.QID] = qualysKBEntry{title: v.Title, cves: cves}
	}
	return m
}

func (q *qualys) Fetch(ctx context.Context) ([]finding.Finding, error) {
	hosts := []qualysHost{}
	next := q.base + "/api/2.0/fo/asset/host/vm/detection/?action=list&show_asset_id=1"
	for page := 0; next != ""; page++ {
		if page >= maxPages {
			return nil, remoteErr("qualys: more than %d pages of host detections", maxPages)
		}
		body, err := q.get(ctx, next)
		if err != nil {
			return nil, err
		}
		var out qualysDetectionOutput
		if err := decodeQualysXML(body, &out); err != nil {
			return nil, err
		}
		hosts = append(hosts, out.Response.HostList...)
		next = ""
		if out.Response.Warning != nil {
			next = out.Response.Warning.URL
		}
	}

	seen := map[int]bool{}
	var qids []int
	for _, h := range hosts {
		for _, d := range h.Detections {
			if d.Status == "Fixed" || d.IsDisabled == 1 || seen[d.QID] {
				continue
			}
			seen[d.QID] = true
			qids = append(qids, d.QID)
		}
	}
	kb := q.knowledgeBase(ctx, qids)

	out := []finding.Finding{}
	for _, h := range hosts {
		host := qualysFirstNonEmpty(h.DNS, h.NetBIOS, h.IP)
		for _, d := range h.Detections {
			if d.Status == "Fixed" || d.IsDisabled == 1 {
				continue
			}
			out = append(out, q.toFinding(h, host, d, kb[d.QID]))
		}
	}
	return uniqueByFingerprint(out), nil
}

// Category is DAST: Qualys VMDR is network/host vulnerability scanning, like
// the Tenable and Nessus connectors.
func (q *qualys) Category([]finding.Finding) domain.Category { return domain.CategoryDAST }

// qualysSeverity maps Qualys' 1 (Minimal) .. 5 (Urgent) scale onto Xila's
// five-point severity.
func qualysSeverity(level int) domain.Severity {
	switch {
	case level >= 5:
		return domain.SeverityCritical
	case level == 4:
		return domain.SeverityHigh
	case level == 3:
		return domain.SeverityMedium
	case level == 2:
		return domain.SeverityLow
	}
	return domain.SeverityInfo
}

func qualysFirstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

func (q *qualys) toFinding(h qualysHost, host string, d qualysDetection, kb qualysKBEntry) finding.Finding {
	loc := host
	if d.Port > 0 {
		loc = fmt.Sprintf("%s:%d/%s", host, d.Port, strings.ToLower(d.Protocol))
	}
	title := kb.title
	if title == "" {
		title = "QID " + strconv.Itoa(d.QID)
	}
	desc := withSection(d.Results, "Detection type", d.Type)
	meta := map[string]any{"source": "qualys", "host_id": h.ID, "status": d.Status}
	if h.IP != "" {
		meta["ip"] = h.IP
	}
	if d.Port > 0 {
		meta["port"] = d.Port
		meta["protocol"] = d.Protocol
	}
	if d.IsIgnored == 1 {
		meta["remote_triage"] = string(domain.FindingFalsePositive)
		meta["remote_triage_reason"] = "Qualys: detection ignored"
	}
	return finding.Finding{
		Fingerprint: fingerprint(KindQualys, h.ID+"|"+strconv.Itoa(d.QID)+"|"+strconv.Itoa(d.Port)),
		Category:    domain.CategoryDAST,
		RuleID:      strconv.Itoa(d.QID),
		Title:       title,
		Description: desc,
		Severity:    qualysSeverity(d.Severity),
		CVE:         kb.cves,
		FilePath:    loc,
		Metadata:    meta,
	}
}
