package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Polaris parses Fairwinds Polaris audit JSON (`polaris audit --format json`,
// against a cluster or manifests). Results nest three levels deep — controller,
// pod spec, each container — and every failed check at any level is a finding
// whose rule_id is the check id (e.g. "runAsRootAllowed"). Successful checks
// are passes and checks Polaris was told to ignore never appear as failures.
type Polaris struct{}

// NewPolaris constructs a Polaris parser.
func NewPolaris() Polaris { return Polaris{} }

// Scanner returns the tool identifier.
func (Polaris) Scanner() string { return "polaris" }

// PrimaryCategory is the scan-level category for Polaris reports.
func (Polaris) PrimaryCategory() domain.Category { return domain.CategoryKubernetes }

type polarisResult struct {
	ID       string `json:"ID"`
	Message  string `json:"Message"`
	Success  bool   `json:"Success"`
	Severity string `json:"Severity"` // "danger" | "warning" | "ignore"
	Category string `json:"Category"` // Security | Reliability | Efficiency
}

type polarisReport struct {
	PolarisOutputVersion string `json:"PolarisOutputVersion"`
	SourceName           string `json:"SourceName"`
	Results              *[]struct {
		Name      string                   `json:"Name"`
		Namespace string                   `json:"Namespace"`
		Kind      string                   `json:"Kind"`
		Results   map[string]polarisResult `json:"Results"`
		PodResult *struct {
			Results          map[string]polarisResult `json:"Results"`
			ContainerResults []struct {
				Name    string                   `json:"Name"`
				Results map[string]polarisResult `json:"Results"`
			} `json:"ContainerResults"`
		} `json:"PodResult"`
	} `json:"Results"`
}

// Parse implements Parser.
func (Polaris) Parse(r io.Reader) ([]ParsedFinding, error) {
	var rep polarisReport
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode polaris report: %w", err)
	}
	if rep.Results == nil {
		return nil, errors.New("decode polaris report: no Results — not a Polaris audit report")
	}

	var out []ParsedFinding
	for _, res := range *rep.Results {
		resource := res.Kind + " " + res.Name
		if res.Namespace != "" {
			resource = res.Kind + " " + res.Namespace + "/" + res.Name
		}
		out = polarisAppend(out, rep.SourceName, resource, "", res.Results)
		if res.PodResult == nil {
			continue
		}
		out = polarisAppend(out, rep.SourceName, resource, "", res.PodResult.Results)
		for _, c := range res.PodResult.ContainerResults {
			out = polarisAppend(out, rep.SourceName, resource, c.Name, c.Results)
		}
	}
	return out, nil
}

func polarisAppend(out []ParsedFinding, source, resource, container string, results map[string]polarisResult) []ParsedFinding {
	for _, id := range slices.Sorted(maps.Keys(results)) {
		c := results[id]
		if c.Success || strings.EqualFold(c.Severity, "ignore") {
			continue
		}
		location := resource
		if container != "" {
			location += " container " + container
		}
		f := ParsedFinding{
			Category:    domain.CategoryKubernetes,
			RuleID:      firstNonEmpty(c.ID, id),
			Title:       c.Message,
			Description: c.Message + "\n" + location,
			Severity:    dangerSeverity(c.Severity),
			FilePath:    location,
			Metadata: map[string]any{
				"check_category": c.Category,
				"source":         source,
			},
		}
		if container != "" {
			f.Metadata["container"] = container
		}
		out = append(out, f)
	}
	return out
}
