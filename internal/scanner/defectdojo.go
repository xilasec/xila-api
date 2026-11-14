package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// DefectDojoGeneric parses DefectDojo's "Generic Findings Import" JSON
// (`{"findings":[…]}`), the lingua franca many in-house tools and migration
// scripts already emit for DefectDojo. Its triage flags (false_p,
// risk_accepted, out_of_scope, verified) are carried as an imported verdict —
// see setImportedStatus — and mitigated/inactive findings are skipped: they are
// history, not something to fix.
//
// Tip: upload with ?scanner=<original-tool>&format=defectdojo-generic to keep
// the original tool's identity on the findings.
type DefectDojoGeneric struct{}

// NewDefectDojoGeneric constructs a DefectDojoGeneric parser.
func NewDefectDojoGeneric() DefectDojoGeneric { return DefectDojoGeneric{} }

// Scanner returns the tool identifier.
func (DefectDojoGeneric) Scanner() string { return "defectdojo-generic" }

// PrimaryCategory is the scan-level default; each finding is categorized by
// what it points at (a component, an endpoint, or source code).
func (DefectDojoGeneric) PrimaryCategory() domain.Category { return domain.CategorySAST }

type ddGenericReport struct {
	Name     string              `json:"name"`
	Type     string              `json:"type"`
	Findings *[]ddGenericFinding `json:"findings"`
}

type ddGenericFinding struct {
	Title             string            `json:"title"`
	Severity          string            `json:"severity"`
	Description       string            `json:"description"`
	Mitigation        string            `json:"mitigation"`
	Impact            string            `json:"impact"`
	References        string            `json:"references"`
	Date              string            `json:"date"`
	CVE               string            `json:"cve"`
	VulnerabilityIDs  flexStrings       `json:"vulnerability_ids"`
	CWE               flexInt           `json:"cwe"`
	CWEs              flexStrings       `json:"cwes"`
	CVSSv3            string            `json:"cvssv3"`
	CVSSv3Score       flexFloat         `json:"cvssv3_score"`
	CVSSv4Score       flexFloat         `json:"cvssv4_score"`
	EPSSScore         flexFloat         `json:"epss_score"`
	KnownExploited    bool              `json:"known_exploited"`
	FilePath          string            `json:"file_path"`
	Line              flexInt           `json:"line"`
	ComponentName     string            `json:"component_name"`
	ComponentVersion  string            `json:"component_version"`
	FixVersion        string            `json:"fix_version"`
	UniqueIDFromTool  string            `json:"unique_id_from_tool"`
	VulnIDFromTool    string            `json:"vuln_id_from_tool"`
	Endpoints         []json.RawMessage `json:"endpoints"`
	Tags              flexStrings       `json:"tags"`
	Param             string            `json:"param"`
	Payload           string            `json:"payload"`
	DynamicFinding    *bool             `json:"dynamic_finding"`
	Active            *bool             `json:"active"`
	Verified          bool              `json:"verified"`
	FalseP            bool              `json:"false_p"`
	RiskAccepted      bool              `json:"risk_accepted"`
	OutOfScope        bool              `json:"out_of_scope"`
	IsMitigated       bool              `json:"is_mitigated"`
	PlannedRemDate    string            `json:"planned_remediation_date"`
	SeverityJustified string            `json:"severity_justification"`
}

// Parse converts a DefectDojo generic JSON report into findings.
func (DefectDojoGeneric) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report ddGenericReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode defectdojo generic report: %w", err)
	}
	if report.Findings == nil {
		return nil, errors.New(`decode defectdojo generic report: no "findings" array`)
	}

	out := make([]ParsedFinding, 0, len(*report.Findings))
	for i, f := range *report.Findings {
		if f.Title == "" || f.Severity == "" {
			return nil, fmt.Errorf("defectdojo generic report: finding %d lacks the required title/severity", i)
		}
		status, keep := ddGenericStatus(f)
		if !keep {
			continue // mitigated or closed in DefectDojo: history, not work
		}

		ids := append([]string{f.CVE}, f.VulnerabilityIDs...)
		endpoint := ""
		if len(f.Endpoints) > 0 {
			endpoint = ddEndpointURL(f.Endpoints[0])
		}

		pf := ParsedFinding{
			Category:       ddGenericCategory(f, endpoint),
			RuleID:         firstNonEmpty(f.VulnIDFromTool, firstNonEmpty(ids...), f.Title),
			Title:          f.Title,
			Description:    f.Description,
			Severity:       normalizeSeverity(f.Severity),
			CWE:            f.CWE.ptr(),
			CVE:            cvesFrom(ids...),
			FilePath:       firstNonEmpty(f.FilePath, endpoint),
			Line:           f.Line.ptr(),
			Package:        f.ComponentName,
			PackageVersion: f.ComponentVersion,
			FixedVersion:   f.FixVersion,
			URL:            endpoint,
			CVSS:           ddGenericCVSS(f),
			Metadata:       map[string]any{},
		}
		if pf.CWE == nil {
			pf.CWE = cweFirst(f.CWEs...)
		}
		meta := pf.Metadata
		for k, v := range map[string]string{
			"mitigation": f.Mitigation, "impact": f.Impact, "references": f.References,
			"date": f.Date, "unique_id_from_tool": f.UniqueIDFromTool, "vuln_id_from_tool": f.VulnIDFromTool,
			"cvssv3_vector": f.CVSSv3, "param": f.Param, "payload": f.Payload,
			"planned_remediation_date": f.PlannedRemDate, "severity_justification": f.SeverityJustified,
			"source_tool": firstNonEmpty(report.Type, report.Name),
		} {
			if v != "" {
				meta[k] = v
			}
		}
		if len(f.Tags) > 0 {
			meta["tags"] = []string(f.Tags)
		}
		if ids := nonEmpty(ids); len(ids) > 0 {
			meta["vulnerability_ids"] = ids
		}
		if f.EPSSScore.ptr() != nil {
			meta["epss_score"] = *f.EPSSScore.ptr()
		}
		if f.KnownExploited {
			meta["known_exploited"] = true
		}
		setImportedStatus(meta, status, "imported from DefectDojo", zeroTime)
		out = append(out, pf)
	}
	return mergeSameLocation(out), nil
}

// ddGenericStatus maps DefectDojo's boolean triage flags onto a verdict, and
// reports whether the finding should be imported at all. A mitigated finding,
// or one DefectDojo marks inactive without saying why, is closed there.
func ddGenericStatus(f ddGenericFinding) (domain.FindingStatus, bool) {
	switch {
	case f.FalseP:
		return domain.FindingFalsePositive, true
	case f.RiskAccepted:
		return domain.FindingRiskAccepted, true
	case f.OutOfScope:
		return domain.FindingWontFix, true
	case f.IsMitigated, f.Active != nil && !*f.Active:
		return "", false
	case f.Verified:
		return domain.FindingConfirmed, true
	}
	return domain.FindingOpen, true
}

// ddGenericCategory infers the finding class from what it points at.
func ddGenericCategory(f ddGenericFinding, endpoint string) domain.Category {
	switch {
	case f.ComponentName != "":
		return domain.CategorySCA
	case f.DynamicFinding != nil && *f.DynamicFinding, endpoint != "" && f.FilePath == "":
		return domain.CategoryDAST
	}
	return domain.CategorySAST
}

// ddGenericCVSS prefers the explicit v3 score, then one derived from the v3
// vector, then the v4 score.
func ddGenericCVSS(f ddGenericFinding) *float64 {
	if p := f.CVSSv3Score.ptr(); p != nil && *p > 0 {
		return p
	}
	if s, ok := cvss3BaseScore(f.CVSSv3); ok {
		return floatPtr(s)
	}
	if p := f.CVSSv4Score.ptr(); p != nil && *p > 0 {
		return p
	}
	return nil
}

// ddEndpointURL renders a generic-import endpoint, which is either a URL/host
// string or a DefectDojo Endpoint object.
func ddEndpointURL(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var e struct {
		Protocol string  `json:"protocol"`
		Host     string  `json:"host"`
		Port     flexInt `json:"port"`
		Path     string  `json:"path"`
		Query    string  `json:"query"`
	}
	if err := json.Unmarshal(raw, &e); err != nil || e.Host == "" {
		return ""
	}
	u := url.URL{Scheme: e.Protocol, Host: e.Host, Path: e.Path, RawQuery: e.Query}
	if p := e.Port.ptr(); p != nil {
		u.Host += ":" + strconv.Itoa(*p)
	}
	if u.Path != "" && !strings.HasPrefix(u.Path, "/") {
		u.Path = "/" + u.Path
	}
	if u.Scheme == "" {
		return strings.TrimPrefix(u.String(), "//")
	}
	return u.String()
}

func nonEmpty(vals []string) []string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
