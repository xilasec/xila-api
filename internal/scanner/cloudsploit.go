package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// CloudSploit parses Aqua CloudSploit's native JSON scan results: a plain
// array of plugin checks, one per evaluated resource. Only FAIL entries are
// findings — OK means the check passed, and WARN/UNKNOWN mean CloudSploit
// couldn't decide either way, which "map only what failed" treats the same as
// a pass.
//
// CloudSploit's output carries no severity for a check (the plugin's own risk
// level isn't part of the report), so every finding is medium — the same
// "don't invent a gradient we don't have" choice as kube-bench's FAIL.
type CloudSploit struct{}

// NewCloudSploit constructs a CloudSploit parser.
func NewCloudSploit() CloudSploit { return CloudSploit{} }

// Scanner returns the tool identifier.
func (CloudSploit) Scanner() string { return "cloudsploit" }

// PrimaryCategory is the scan-level category for CloudSploit reports.
func (CloudSploit) PrimaryCategory() domain.Category { return domain.CategoryCloud }

type cloudSploitResult struct {
	Plugin      string          `json:"plugin"`
	Category    string          `json:"category"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Resource    string          `json:"resource"`
	Region      json.RawMessage `json:"region"`
	Status      string          `json:"status"`
	Message     string          `json:"message"`
}

// Parse implements Parser.
func (CloudSploit) Parse(r io.Reader) ([]ParsedFinding, error) {
	var results []cloudSploitResult
	if err := json.NewDecoder(r).Decode(&results); err != nil {
		return nil, fmt.Errorf("decode cloudsploit report: %w", err)
	}

	out := []ParsedFinding{}
	for _, res := range results {
		if !strings.EqualFold(res.Status, "FAIL") {
			continue
		}
		f := ParsedFinding{
			Category:    domain.CategoryCloud,
			RuleID:      res.Plugin,
			Title:       firstNonEmpty(res.Title, res.Plugin),
			Description: strings.TrimSpace(res.Description + "\n" + res.Message),
			Severity:    domain.SeverityMedium,
			FilePath:    res.Resource, // the affected resource (ARN / id) is the "location"
			Metadata: map[string]any{
				"cloud_category": res.Category,
				"message":        res.Message,
			},
		}
		if region := cloudSploitRegion(res.Region); region != "" {
			f.Metadata["region"] = region
		}
		out = append(out, f)
	}
	return out, nil
}

// cloudSploitRegion reads CloudSploit's "region" field, which is a plain
// string for most checks but a list for global-service checks that span
// several regions.
func cloudSploitRegion(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return strings.Join(list, ", ")
	}
	return ""
}
