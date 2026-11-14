package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Invicti parses Invicti Enterprise / Netsparker vulnerability exports in their
// JSON form (Scan → Report → "Vulnerabilities (JSON)", or the API's
// `GET /api/1.0/scans/report/{id}?Type=Vulnerabilities&Format=Json`).
// Acunetix 360 is the same product line and writes the same document; the
// Acunetix parser reuses this mapping.
//
// One finding per vulnerability: the rule is Invicti's vulnerability Type
// ("CookieNotMarkedAsHttpOnly"), the location the URL it was confirmed on,
// the CWE the first of the classification's list. Severity is Invicti's own
// (Critical/High/Medium/Low; BestPractice is low); "Information" items are
// informational and skipped, as are vulnerabilities whose State says they are
// fixed and no longer present. A State of FalsePositive / AcceptedRisk /
// Ignored is a decision made in Invicti and is carried as remote triage.
type Invicti struct{}

// NewInvicti constructs an Invicti parser.
func NewInvicti() Invicti { return Invicti{} }

// Scanner returns the tool identifier.
func (Invicti) Scanner() string { return "invicti" }

// PrimaryCategory is the scan-level category for Invicti reports.
func (Invicti) PrimaryCategory() domain.Category { return domain.CategoryDAST }

// invictiReport is the vulnerabilities JSON shared by Invicti/Netsparker and
// Acunetix 360.
type invictiReport struct {
	Target *struct {
		URL    string `json:"Url"`
		ScanID string `json:"ScanId"`
	} `json:"Target"`
	Vulnerabilities *[]invictiVuln `json:"Vulnerabilities"`
}

type invictiVuln struct {
	URL            string `json:"Url"`
	Type           string `json:"Type"`
	Name           string `json:"Name"`
	Severity       string `json:"Severity"`
	State          string `json:"State"`
	Certainty      int    `json:"Certainty"`
	Confirmed      bool   `json:"Confirmed"`
	LookupID       string `json:"LookupId"`
	Description    string `json:"Description"`
	Impact         string `json:"Impact"`
	RemedialProc   string `json:"RemedialProcedure"`
	RemedialAction string `json:"RemedialActions"`
	ExternalRefs   string `json:"ExternalReferences"`
	ProofOfConcept string `json:"ProofOfConcept"`
	Classification *struct {
		CWE   string       `json:"Cwe"`
		OWASP string       `json:"Owasp"`
		WASC  string       `json:"Wasc"`
		CVSS  *invictiCVSS `json:"Cvss"`
		CVSS3 *invictiCVSS `json:"Cvss31"`
	} `json:"Classification"`
	KnownVulnerabilities []struct {
		Title    string `json:"Title"`
		Severity string `json:"Severity"`
	} `json:"KnownVulnerabilities"`
	ExtraInformation []struct {
		Name  string `json:"Name"`
		Value string `json:"Value"`
	} `json:"ExtraInformation"`
	HTTPRequest *struct {
		Method string `json:"Method"`
	} `json:"HttpRequest"`
}

type invictiCVSS struct {
	BaseScore *struct {
		Value string `json:"Value"`
	} `json:"BaseScore"`
	Vector string `json:"Vector"`
}

var invictiHref = regexp.MustCompile(`href=['"]([^'"]+)['"]`)

// Parse implements Parser.
func (Invicti) Parse(r io.Reader) ([]ParsedFinding, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read invicti report: %w", err)
	}
	return invictiParse(raw, "invicti")
}

// invictiParse maps an Invicti/Acunetix 360 vulnerabilities document; tool
// names the product in errors and triage reasons.
func invictiParse(raw []byte, tool string) ([]ParsedFinding, error) {
	var rep invictiReport
	if err := json.Unmarshal(bytes.TrimSpace(raw), &rep); err != nil {
		return nil, fmt.Errorf("decode %s json: %w", tool, err)
	}
	if rep.Vulnerabilities == nil {
		return nil, fmt.Errorf("decode %s json: %w", tool, errors.New(`no "Vulnerabilities" list`))
	}
	target := ""
	if rep.Target != nil {
		target = rep.Target.URL
	}
	out := make([]ParsedFinding, 0, len(*rep.Vulnerabilities))
	for _, v := range *rep.Vulnerabilities {
		if f, ok := invictiFinding(v, target, tool); ok {
			out = append(out, f)
		}
	}
	return mergeSameLocation(out), nil
}

// invictiText turns the report's HTML fragments into plain text.
func invictiText(s string) string {
	return strings.TrimSpace(html.UnescapeString(stripTags(s)))
}

func invictiSeverity(s string) (domain.Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "information", "informational", "info":
		return "", false
	case "bestpractice", "best practice":
		return domain.SeverityLow, true
	}
	return normalizeSeverity(s), true
}

// invictiState reads the comma-separated State ("Present, FalsePositive").
// gone is true when the vulnerability is reported fixed and not present.
func invictiState(state string) (status domain.FindingStatus, reason string, gone bool) {
	present := false
	fixed := false
	for _, s := range strings.Split(state, ",") {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "present", "revived", "new", "scanning":
			present = true
		case "fixed", "fixedunconfirmed", "fixed (unconfirmed)", "fixedcantretest", "fixedconfirmed":
			fixed = true
		case "falsepositive":
			status, reason = domain.FindingFalsePositive, "FalsePositive"
		case "acceptedrisk":
			status, reason = domain.FindingRiskAccepted, "AcceptedRisk"
		case "ignored":
			status, reason = domain.FindingWontFix, "Ignored"
		}
	}
	return status, reason, fixed && !present
}

func invictiFinding(v invictiVuln, target, tool string) (ParsedFinding, bool) {
	sev, ok := invictiSeverity(v.Severity)
	if !ok {
		return ParsedFinding{}, false
	}
	status, reason, gone := invictiState(v.State)
	if gone {
		return ParsedFinding{}, false
	}

	desc := invictiText(v.Description)
	if poc := invictiText(v.ProofOfConcept); poc != "" {
		desc += "\n\nProof of concept:\n" + poc
	}
	meta := map[string]any{
		"certainty": v.Certainty,
		"confirmed": v.Confirmed,
	}
	if v.HTTPRequest != nil && v.HTTPRequest.Method != "" {
		meta["method"] = v.HTTPRequest.Method
	}
	for k, val := range map[string]string{
		"impact":     invictiText(v.Impact),
		"mitigation": invictiText(firstNonEmpty(v.RemedialProc, v.RemedialAction)),
		"state":      strings.TrimSpace(v.State),
		"lookup_id":  v.LookupID,
	} {
		if val != "" {
			meta[k] = val
		}
	}
	var refs []string
	for _, m := range invictiHref.FindAllStringSubmatch(v.ExternalRefs, -1) {
		refs = append(refs, html.UnescapeString(m[1]))
	}
	if len(refs) > 0 {
		meta["references"] = refs
	}
	if len(v.ExtraInformation) > 0 {
		extra := make(map[string]string, len(v.ExtraInformation))
		for _, e := range v.ExtraInformation {
			extra[e.Name] = e.Value
		}
		meta["extra_information"] = extra
	}
	cveTexts := []string{v.Name, v.Description}
	if len(v.KnownVulnerabilities) > 0 {
		known := make([]string, 0, len(v.KnownVulnerabilities))
		for _, k := range v.KnownVulnerabilities {
			known = append(known, k.Title)
			cveTexts = append(cveTexts, k.Title)
		}
		meta["known_vulnerabilities"] = known
	}

	f := ParsedFinding{
		Category:    domain.CategoryDAST,
		RuleID:      v.Type,
		Title:       firstNonEmpty(v.Name, v.Type),
		Description: desc,
		Severity:    sev,
		CVE:         cvesInText(cveTexts...),
		FilePath:    v.URL,
		URL:         firstNonEmpty(target, v.URL),
		Metadata:    meta,
	}
	if c := v.Classification; c != nil {
		var cwes []string
		for _, s := range strings.Split(c.CWE, ",") {
			if s = strings.TrimSpace(s); s != "" {
				cwes = append(cwes, s)
			}
		}
		if len(cwes) > 0 {
			f.CWE = cweFrom(cwes[0])
		}
		if len(cwes) > 1 {
			meta["cwes"] = cwes
		}
		if c.OWASP != "" {
			meta["owasp"] = c.OWASP
		}
		if c.WASC != "" {
			meta["wasc"] = c.WASC
		}
		for _, cv := range []*invictiCVSS{c.CVSS3, c.CVSS} {
			if cv == nil || cv.BaseScore == nil {
				continue
			}
			if s, err := strconv.ParseFloat(cv.BaseScore.Value, 64); err == nil && s > 0 {
				f.CVSS = floatPtr(s)
				meta["cvss_vector"] = cv.Vector
				break
			}
		}
	}
	if status != "" {
		setImportedStatus(meta, status, tool+" state: "+reason, zeroTime)
	}
	return f, true
}
