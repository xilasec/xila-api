package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Trivy parses `trivy ... --format json` output. A single report can contain
// multiple result classes (vulnerabilities, misconfigurations, secrets), which
// are mapped onto the appropriate finding category.
type Trivy struct{}

// NewTrivy constructs a Trivy parser.
func NewTrivy() Trivy { return Trivy{} }

// Scanner returns the tool identifier.
func (Trivy) Scanner() string { return "trivy" }

// PrimaryCategory is the default scan-level category for Trivy reports.
func (Trivy) PrimaryCategory() domain.Category { return domain.CategorySCA }

// trivyReport mirrors the subset of the Trivy JSON schema we consume.
type trivyReport struct {
	ArtifactName string `json:"ArtifactName"`
	ArtifactType string `json:"ArtifactType"`
	Metadata     struct {
		OS struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
		} `json:"OS"`
	} `json:"Metadata"`
	Results []struct {
		Target            string               `json:"Target"`
		Class             string               `json:"Class"`
		Type              string               `json:"Type"`
		Vulnerabilities   []trivyVulnerability `json:"Vulnerabilities"`
		Misconfigurations []trivyMisconfig     `json:"Misconfigurations"`
		Secrets           []trivySecret        `json:"Secrets"`
	} `json:"Results"`
}

type trivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Title            string   `json:"Title"`
	Description      string   `json:"Description"`
	Severity         string   `json:"Severity"`
	PrimaryURL       string   `json:"PrimaryURL"`
	CweIDs           []string `json:"CweIDs"`
	PkgIdentifier    struct {
		PURL string `json:"PURL"`
	} `json:"PkgIdentifier"`
	Layer struct {
		DiffID string `json:"DiffID"`
	} `json:"Layer"`
	CVSS map[string]struct {
		V3Score float64 `json:"V3Score"`
		V2Score float64 `json:"V2Score"`
	} `json:"CVSS"`
}

type trivyMisconfig struct {
	ID          string `json:"ID"`
	AVDID       string `json:"AVDID"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
	Severity    string `json:"Severity"`
	Resolution  string `json:"Resolution"`
	PrimaryURL  string `json:"PrimaryURL"`
}

type trivySecret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Title     string `json:"Title"`
	Severity  string `json:"Severity"`
	StartLine int    `json:"StartLine"`
	Match     string `json:"Match"`
}

// Parse implements Parser.
func (Trivy) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report trivyReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode trivy report: %w", err)
	}

	// An image scan names the image and its OS: remediation groups the
	// image's distro packages ("os-pkgs") as one base-image rebuild.
	image, osName := "", ""
	if report.ArtifactType == "container_image" {
		image = report.ArtifactName
		osName = strings.TrimSpace(report.Metadata.OS.Family + " " + report.Metadata.OS.Name)
	}
	var out []ParsedFinding
	for _, res := range report.Results {
		for _, v := range res.Vulnerabilities {
			md := map[string]any{"pkg_type": res.Type}
			if image != "" {
				md["image"] = image
				md["pkg_class"] = res.Class
				if osName != "" {
					md["os"] = osName
				}
				if v.Layer.DiffID != "" {
					md["layer_diff_id"] = v.Layer.DiffID
				}
			}
			out = append(out, ParsedFinding{
				Category:       domain.CategorySCA,
				RuleID:         v.VulnerabilityID,
				Title:          firstNonEmpty(v.Title, v.VulnerabilityID),
				Description:    v.Description,
				Severity:       mapTrivySeverity(v.Severity),
				CWE:            firstCWE(v.CweIDs),
				CVE:            cveList(v.VulnerabilityID),
				FilePath:       res.Target,
				Package:        v.PkgName,
				PackageVersion: v.InstalledVersion,
				FixedVersion:   v.FixedVersion,
				Purl:           v.PkgIdentifier.PURL,
				CVSS:           trivyCVSS(v),
				URL:            v.PrimaryURL,
				Metadata:       md,
			})
		}
		for _, m := range res.Misconfigurations {
			out = append(out, ParsedFinding{
				Category:    domain.CategoryIaC,
				RuleID:      firstNonEmpty(m.AVDID, m.ID),
				Title:       firstNonEmpty(m.Title, m.ID),
				Description: strings.TrimSpace(m.Description + "\n" + m.Resolution),
				Severity:    mapTrivySeverity(m.Severity),
				FilePath:    res.Target,
				URL:         m.PrimaryURL,
			})
		}
		for _, s := range res.Secrets {
			line := s.StartLine
			out = append(out, ParsedFinding{
				Category: domain.CategorySecret,
				RuleID:   s.RuleID,
				Title:    firstNonEmpty(s.Title, s.RuleID),
				Severity: mapTrivySeverity(s.Severity),
				FilePath: res.Target,
				Line:     &line,
				Metadata: map[string]any{
					"secret_category": s.Category,
				},
			})
		}
	}
	return out, nil
}

// trivyCVSS picks a base score, preferring NVD v3, then any v3, then any v2.
func trivyCVSS(v trivyVulnerability) *float64 {
	if c, ok := v.CVSS["nvd"]; ok {
		if c.V3Score > 0 {
			return &c.V3Score
		}
		if c.V2Score > 0 {
			return &c.V2Score
		}
	}
	for _, c := range v.CVSS {
		if c.V3Score > 0 {
			return &c.V3Score
		}
	}
	return nil
}

// mapTrivySeverity maps Trivy's scale onto our normalized severities.
func mapTrivySeverity(s string) domain.Severity {
	switch strings.ToUpper(s) {
	case "LOW":
		return domain.SeverityLow
	case "MEDIUM":
		return domain.SeverityMedium
	case "HIGH":
		return domain.SeverityHigh
	case "CRITICAL":
		return domain.SeverityCritical
	default: // UNKNOWN, "", etc.
		return domain.SeverityInfo
	}
}

// firstCWE extracts the first "CWE-123" id as an integer, if present.
func firstCWE(ids []string) *int {
	for _, id := range ids {
		if n, ok := strings.CutPrefix(strings.ToUpper(id), "CWE-"); ok {
			if v, err := strconv.Atoi(n); err == nil {
				return intPtr(v)
			}
		}
	}
	return nil
}

// cveList returns the vuln id as a CVE reference when it looks like one.
func cveList(vulnID string) []string {
	if strings.HasPrefix(strings.ToUpper(vulnID), "CVE-") {
		return []string{vulnID}
	}
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
