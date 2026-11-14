package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Prowler parses Prowler's native JSON (`prowler <provider> -M json`), the
// cloud security posture (CSPM) scanner for AWS/GCP/Azure/Kubernetes. Only
// failing checks become findings; the CheckID becomes rule_id so results map to
// compliance controls (e.g. CIS) via scanner="prowler" rule mappings.
type Prowler struct{}

// NewProwler constructs a Prowler parser.
func NewProwler() Prowler { return Prowler{} }

// Scanner returns the tool identifier.
func (Prowler) Scanner() string { return "prowler" }

// PrimaryCategory is the scan-level category for Prowler reports.
func (Prowler) PrimaryCategory() domain.Category { return domain.CategoryCloud }

type prowlerFinding struct {
	Provider       string `json:"Provider"`
	CheckID        string `json:"CheckID"`
	CheckTitle     string `json:"CheckTitle"`
	ServiceName    string `json:"ServiceName"`
	Severity       string `json:"Severity"`
	ResourceType   string `json:"ResourceType"`
	ResourceID     string `json:"ResourceId"`
	ResourceArn    string `json:"ResourceArn"`
	Status         string `json:"Status"`
	StatusExtended string `json:"StatusExtended"`
	Region         string `json:"Region"`
	AccountID      string `json:"AccountId"`
	Description    string `json:"Description"`
	Risk           string `json:"Risk"`
	RelatedURL     string `json:"RelatedUrl"`
	Remediation    struct {
		Recommendation struct {
			Text string `json:"Text"`
			URL  string `json:"Url"`
		} `json:"Recommendation"`
	} `json:"Remediation"`
	Compliance map[string][]string `json:"Compliance"`
	// Categories is the check's own classification ("internet-exposed",
	// "encryption", …); asset exposure inference keys on it.
	Categories []string `json:"Categories"`
}

// Parse implements Parser.
func (Prowler) Parse(r io.Reader) ([]ParsedFinding, error) {
	var findings []prowlerFinding
	if err := json.NewDecoder(r).Decode(&findings); err != nil {
		return nil, fmt.Errorf("decode prowler report: %w", err)
	}

	var out []ParsedFinding
	for _, f := range findings {
		if !strings.EqualFold(f.Status, "FAIL") {
			continue // PASS / MANUAL / INFO are not findings
		}
		out = append(out, ParsedFinding{
			Category:    domain.CategoryCloud,
			RuleID:      f.CheckID,
			Title:       firstNonEmpty(f.CheckTitle, f.CheckID),
			Description: strings.TrimSpace(firstNonEmpty(f.StatusExtended, f.Description) + "\n" + f.Risk),
			Severity:    mapProwlerSeverity(f.Severity),
			FilePath:    f.ResourceID, // the affected resource (ARN / id) is the "location"
			URL:         firstNonEmpty(f.Remediation.Recommendation.URL, f.RelatedURL),
			Metadata: map[string]any{
				"provider":      f.Provider,
				"service":       f.ServiceName,
				"region":        f.Region,
				"account":       f.AccountID,
				"resource_type": f.ResourceType,
				"remediation":   f.Remediation.Recommendation.Text,
				"compliance":    f.Compliance,
				"categories":    f.Categories,
				"resource_arn":  f.ResourceArn,
			},
		})
	}
	return out, nil
}

func mapProwlerSeverity(s string) domain.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return domain.SeverityCritical
	case "high":
		return domain.SeverityHigh
	case "medium":
		return domain.SeverityMedium
	case "low":
		return domain.SeverityLow
	default: // informational, ""
		return domain.SeverityInfo
	}
}
