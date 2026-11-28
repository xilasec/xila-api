package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// SonarQube parses the JSON pages of SonarQube's Web API: the issue search
// (`GET /api/issues/search?types=VULNERABILITY&componentKeys=<project>`) and
// the security-hotspot search (`GET /api/hotspots/search?projectKey=<project>`).
// The shape is sniffed from the top-level "issues" or "hotspots" array.
//
// Only the security part of a report is imported: VULNERABILITY issues and
// security hotspots. Code smells and bugs are code quality, not security, and
// would bury the real findings. Issues already closed or resolved as fixed
// (and hotspots reviewed as fixed) are not reported; a SonarQube verdict —
// false positive, won't fix, a hotspot reviewed as safe — is carried as
// remote triage. Component keys are resolved to file paths through the
// response's "components" list, falling back to stripping the "project:" prefix.
//
// Issues raised by the Dependency-Check plugin
// (OWASP:UsingComponentWithKnownVulnerability) are attached to the project, not
// a file; their message ("Filename: x.jar | Reference: CVE-… | CVSS Score: …")
// is parsed for the package, CVE, CVSS and CWE.
type SonarQube struct{}

// NewSonarQube constructs a SonarQube parser.
func NewSonarQube() SonarQube { return SonarQube{} }

// Scanner returns the tool identifier.
func (SonarQube) Scanner() string { return "sonarqube" }

// PrimaryCategory is the scan-level category for SonarQube reports.
func (SonarQube) PrimaryCategory() domain.Category { return domain.CategorySAST }

type sonarQubeTextRange struct {
	StartLine int `json:"startLine"`
}

type sonarQubeReport struct {
	Issues     *[]sonarQubeIssue   `json:"issues"`
	Hotspots   *[]sonarQubeHotspot `json:"hotspots"`
	Components []struct {
		Key  string `json:"key"`
		Path string `json:"path"`
	} `json:"components"`
}

type sonarQubeIssue struct {
	Key         string             `json:"key"`
	Rule        string             `json:"rule"`
	Severity    string             `json:"severity"`
	Component   string             `json:"component"`
	Project     string             `json:"project"`
	Line        int                `json:"line"`
	TextRange   sonarQubeTextRange `json:"textRange"`
	Status      string             `json:"status"`
	IssueStatus string             `json:"issueStatus"`
	Resolution  string             `json:"resolution"`
	Message     string             `json:"message"`
	Effort      string             `json:"effort"`
	Tags        []string           `json:"tags"`
	Type        string             `json:"type"`
	Impacts     []struct {
		SoftwareQuality string `json:"softwareQuality"`
		Severity        string `json:"severity"`
	} `json:"impacts"`
}

type sonarQubeHotspot struct {
	Key                      string             `json:"key"`
	Component                string             `json:"component"`
	Project                  string             `json:"project"`
	SecurityCategory         string             `json:"securityCategory"`
	VulnerabilityProbability string             `json:"vulnerabilityProbability"`
	Status                   string             `json:"status"`
	Resolution               string             `json:"resolution"`
	Line                     int                `json:"line"`
	TextRange                sonarQubeTextRange `json:"textRange"`
	Message                  string             `json:"message"`
	RuleKey                  string             `json:"ruleKey"`
}

// Parse implements Parser.
func (SonarQube) Parse(r io.Reader) ([]ParsedFinding, error) {
	var rep sonarQubeReport
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode sonarqube report: %w", err)
	}
	if rep.Issues == nil && rep.Hotspots == nil {
		return nil, errors.New(`decode sonarqube report: no "issues" or "hotspots" array (expected /api/issues/search or /api/hotspots/search JSON)`)
	}
	paths := make(map[string]string, len(rep.Components))
	for _, c := range rep.Components {
		if c.Path != "" {
			paths[c.Key] = c.Path
		}
	}
	path := func(component, project string) string {
		if p, ok := paths[component]; ok {
			return p
		}
		if component == project {
			return ""
		}
		return strings.TrimPrefix(component, project+":")
	}

	out := []ParsedFinding{}
	if rep.Issues != nil {
		for _, is := range *rep.Issues {
			if !sonarQubeSecurityIssue(is) {
				continue
			}
			if f, ok := sonarQubeIssueFinding(is, path(is.Component, is.Project)); ok {
				out = append(out, f)
			}
		}
	}
	if rep.Hotspots != nil {
		for _, h := range *rep.Hotspots {
			if f, ok := sonarQubeHotspotFinding(h, path(h.Component, h.Project)); ok {
				out = append(out, f)
			}
		}
	}
	return mergeSameLocation(out), nil
}

// sonarQubeSecurityIssue keeps VULNERABILITY issues; on SonarQube 10.2+ an
// issue without a legacy type counts when it has a SECURITY impact.
func sonarQubeSecurityIssue(is sonarQubeIssue) bool {
	if is.Type != "" {
		return is.Type == "VULNERABILITY"
	}
	for _, im := range is.Impacts {
		if im.SoftwareQuality == "SECURITY" {
			return true
		}
	}
	return false
}

func sonarQubeIssueFinding(is sonarQubeIssue, file string) (ParsedFinding, bool) {
	meta := map[string]any{"key": is.Key, "status": is.Status, "project": is.Project}
	switch {
	case is.Status == "CLOSED", is.Resolution == "FIXED", is.Resolution == "REMOVED":
		return ParsedFinding{}, false
	case is.Resolution == "FALSE-POSITIVE", is.IssueStatus == "FALSE_POSITIVE":
		setImportedStatus(meta, domain.FindingFalsePositive, "SonarQube: resolved as false positive", zeroTime)
	case is.Resolution == "WONTFIX", is.IssueStatus == "ACCEPTED":
		setImportedStatus(meta, domain.FindingWontFix, "SonarQube: resolved as won't fix", zeroTime)
	case is.Status == "CONFIRMED", is.IssueStatus == "CONFIRMED":
		setImportedStatus(meta, domain.FindingConfirmed, "SonarQube: confirmed", zeroTime)
	}
	if is.Resolution != "" {
		meta["resolution"] = is.Resolution
	}
	if len(is.Tags) > 0 {
		meta["tags"] = is.Tags
	}
	if is.Effort != "" {
		meta["effort"] = is.Effort
	}

	sev := sonarQubeSeverity(is.Severity)
	if is.Severity == "" {
		for _, im := range is.Impacts {
			if im.SoftwareQuality == "SECURITY" {
				sev = normalizeSeverity(im.Severity)
			}
		}
	}
	f := ParsedFinding{
		Category:    domain.CategorySAST,
		RuleID:      is.Rule,
		Title:       is.Message,
		Description: is.Message,
		Severity:    sev,
		CVE:         cvesInText(is.Message),
		FilePath:    file,
		Line:        sonarQubeLine(is.Line, is.TextRange),
		Metadata:    meta,
	}

	// Dependency-Check plugin: "Filename: x | Reference: CVE-… | CVSS Score: 6.4 | Category: CWE-120 | …".
	fields := sonarQubeMessageFields(is.Message)
	if pkg := fields["Filename"]; pkg != "" {
		f.Category = domain.CategorySCA
		f.Package = pkg
		f.CWE = cweFirst(fields["Category"])
		ref := firstNonEmpty(fields["Reference"], fields["References"])
		if ref != "" {
			meta["references"] = ref
			if len(f.CVE) > 0 {
				ref = strings.Join(f.CVE, ", ")
			}
			f.Title = fmt.Sprintf("%s in %s", ref, pkg)
		}
		score := firstNonEmpty(fields["CVSS Score"], fields["Highest CVSS Score"])
		if v, err := strconv.ParseFloat(score, 64); err == nil {
			f.CVSS = new(v)
		}
	}
	return f, true
}

func sonarQubeHotspotFinding(h sonarQubeHotspot, file string) (ParsedFinding, bool) {
	meta := map[string]any{
		"key":                       h.Key,
		"status":                    h.Status,
		"project":                   h.Project,
		"hotspot":                   true,
		"security_category":         h.SecurityCategory,
		"vulnerability_probability": h.VulnerabilityProbability,
	}
	if h.Status == "REVIEWED" {
		meta["resolution"] = h.Resolution
		switch h.Resolution {
		case "FIXED":
			return ParsedFinding{}, false
		case "SAFE":
			setImportedStatus(meta, domain.FindingFalsePositive, "SonarQube: hotspot reviewed as safe", zeroTime)
		case "ACKNOWLEDGED":
			setImportedStatus(meta, domain.FindingConfirmed, "SonarQube: hotspot acknowledged", zeroTime)
		}
	}
	return ParsedFinding{
		Category:    domain.CategorySAST,
		RuleID:      h.RuleKey,
		Title:       h.Message,
		Description: h.Message,
		Severity:    normalizeSeverity(h.VulnerabilityProbability),
		CVE:         cvesInText(h.Message),
		FilePath:    file,
		Line:        sonarQubeLine(h.Line, h.TextRange),
		Metadata:    meta,
	}, true
}

// sonarQubeSeverity maps SonarQube's legacy issue severities.
func sonarQubeSeverity(s string) domain.Severity {
	switch strings.ToUpper(s) {
	case "BLOCKER":
		return domain.SeverityCritical
	case "CRITICAL":
		return domain.SeverityHigh
	case "MAJOR":
		return domain.SeverityMedium
	case "MINOR":
		return domain.SeverityLow
	case "INFO":
		return domain.SeverityInfo
	}
	return normalizeSeverity(s)
}

func sonarQubeLine(line int, tr sonarQubeTextRange) *int {
	if line > 0 {
		return new(line)
	}
	if tr.StartLine > 0 {
		return new(tr.StartLine)
	}
	return nil
}

// sonarQubeMessageFields splits a "Key: value | Key: value" message.
func sonarQubeMessageFields(msg string) map[string]string {
	out := map[string]string{}
	for part := range strings.SplitSeq(msg, " | ") {
		if k, v, ok := strings.Cut(part, ": "); ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}
