package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Kubescape parses Kubescape's JSON report (`kubescape scan --format json`), a
// Kubernetes security posture (KSPM) scanner. Each failed control on a resource
// becomes a finding; the controlID (e.g. C-0016) becomes rule_id for compliance
// mapping.
type Kubescape struct{}

// NewKubescape constructs a Kubescape parser.
func NewKubescape() Kubescape { return Kubescape{} }

// Scanner returns the tool identifier.
func (Kubescape) Scanner() string { return "kubescape" }

// PrimaryCategory is the scan-level category for Kubescape reports.
func (Kubescape) PrimaryCategory() domain.Category { return domain.CategoryKubernetes }

type kubescapeReport struct {
	Results []struct {
		ResourceID string `json:"resourceID"`
		Controls   []struct {
			ControlID string `json:"controlID"`
			Name      string `json:"name"`
			Status    struct {
				Status string `json:"status"`
			} `json:"status"`
		} `json:"controls"`
	} `json:"results"`
	Resources []struct {
		ResourceID string `json:"resourceID"`
		Object     struct {
			Kind     string `json:"kind"`
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
		} `json:"object"`
	} `json:"resources"`
	SummaryDetails struct {
		Controls map[string]struct {
			Name     string `json:"name"`
			Severity string `json:"severity"`
		} `json:"controls"`
	} `json:"summaryDetails"`
}

// Parse implements Parser.
func (Kubescape) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report kubescapeReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode kubescape report: %w", err)
	}

	// resourceID -> "Kind namespace/name" for a readable location.
	locations := make(map[string]string, len(report.Resources))
	for _, res := range report.Resources {
		name := res.Object.Metadata.Name
		if ns := res.Object.Metadata.Namespace; ns != "" {
			name = ns + "/" + name
		}
		locations[res.ResourceID] = strings.TrimSpace(res.Object.Kind + " " + name)
	}

	var out []ParsedFinding
	for _, res := range report.Results {
		loc := firstNonEmpty(locations[res.ResourceID], res.ResourceID)
		for _, ctrl := range res.Controls {
			if !strings.EqualFold(ctrl.Status.Status, "failed") {
				continue
			}
			meta := report.SummaryDetails.Controls[ctrl.ControlID]
			out = append(out, ParsedFinding{
				Category: domain.CategoryKubernetes,
				RuleID:   ctrl.ControlID,
				Title:    firstNonEmpty(ctrl.Name, meta.Name, ctrl.ControlID),
				Severity: mapKubescapeSeverity(meta.Severity),
				FilePath: loc,
				Metadata: map[string]any{"resource_id": res.ResourceID},
			})
		}
	}
	return out, nil
}

func mapKubescapeSeverity(s string) domain.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return domain.SeverityCritical
	case "high":
		return domain.SeverityHigh
	case "medium":
		return domain.SeverityMedium
	case "low":
		return domain.SeverityLow
	default:
		return domain.SeverityMedium // Kubescape often omits severity; assume medium
	}
}
