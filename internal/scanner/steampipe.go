package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Steampipe parses the JSON a Steampipe or Powerpipe compliance-mod benchmark
// run exports (`steampipe check <benchmark> --export=out.json` / `powerpipe
// benchmark run <benchmark> --output json` — both tools share this schema,
// Powerpipe having grown out of Steampipe's `check` command): a tree of
// result groups (benchmarks and sub-benchmarks), each holding child groups
// and/or controls, each control holding one result row per resource its SQL
// query evaluated.
//
// Only rows with status "alarm" (the check failed) or "error" (the query
// itself failed for that resource) are findings — "ok" and "info" passed,
// "skip" was never evaluated. A control that failed to execute at all (no
// per-resource rows, run_status "error") still gets one finding, or a broken
// query would silently drop a whole check from the backlog.
type Steampipe struct{}

// NewSteampipe constructs a Steampipe parser.
func NewSteampipe() Steampipe { return Steampipe{} }

// Scanner returns the tool identifier.
func (Steampipe) Scanner() string { return "steampipe" }

// PrimaryCategory is the scan-level category for Steampipe/Powerpipe reports.
func (Steampipe) PrimaryCategory() domain.Category { return domain.CategoryCloud }

// steampipeRunStatusError is the control run_status Steampipe/Powerpipe's own
// export template encodes for "the control failed to execute" (ready=1,
// started=2, complete=4, error=8).
const steampipeRunStatusError = 8

type steampipeGroup struct {
	GroupID  string             `json:"group_id"`
	Title    string             `json:"title"`
	Groups   []steampipeGroup   `json:"groups"`
	Controls []steampipeControl `json:"controls"`
}

type steampipeControl struct {
	Summary     steampipeSummary  `json:"summary"`
	Results     []steampipeResult `json:"results"`
	ControlID   string            `json:"control_id"`
	Description string            `json:"description"`
	Severity    string            `json:"severity"`
	Tags        map[string]string `json:"tags"`
	Title       string            `json:"title"`
	RunStatus   int               `json:"run_status"`
	RunError    string            `json:"run_error"`
}

// steampipeSummary is a control's status counts. Exports made with a custom
// or summary template carry only these, without the per-resource rows.
type steampipeSummary struct {
	Alarm int `json:"alarm"`
	Error int `json:"error"`
}

type steampipeResult struct {
	Reason     string               `json:"reason"`
	Resource   string               `json:"resource"`
	Status     string               `json:"status"`
	Dimensions []steampipeDimension `json:"dimensions"`
}

type steampipeDimension struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// Parse implements Parser.
func (Steampipe) Parse(r io.Reader) ([]ParsedFinding, error) {
	var root steampipeGroup
	if err := json.NewDecoder(r).Decode(&root); err != nil {
		return nil, fmt.Errorf("decode steampipe report: %w", err)
	}
	if root.GroupID == "" && len(root.Groups) == 0 && len(root.Controls) == 0 {
		return nil, errors.New("decode steampipe report: no group_id, groups or controls — not a steampipe/powerpipe benchmark export")
	}

	out := []ParsedFinding{}
	collectSteampipe(root, nil, &out)
	return out, nil
}

func collectSteampipe(g steampipeGroup, path []string, out *[]ParsedFinding) {
	groupPath := path
	if g.Title != "" {
		groupPath = append(append([]string{}, path...), g.Title)
	}
	for _, child := range g.Groups {
		collectSteampipe(child, groupPath, out)
	}
	for _, c := range g.Controls {
		*out = append(*out, steampipeControlFindings(c, groupPath)...)
	}
}

func steampipeControlFindings(c steampipeControl, groupPath []string) []ParsedFinding {
	sev := normalizeSeverity(c.Severity)
	title := firstNonEmpty(c.Title, c.ControlID)
	benchmark := strings.Join(groupPath, " / ")

	var out []ParsedFinding
	for _, res := range c.Results {
		if res.Status != "alarm" && res.Status != "error" {
			continue
		}
		meta := map[string]any{"status": res.Status}
		if benchmark != "" {
			meta["benchmark"] = benchmark
		}
		if len(c.Tags) > 0 {
			meta["tags"] = c.Tags
		}
		for _, d := range res.Dimensions {
			meta[d.Key] = d.Value
		}
		out = append(out, ParsedFinding{
			Category:    domain.CategoryCloud,
			RuleID:      c.ControlID,
			Title:       title,
			Description: firstNonEmpty(res.Reason, c.Description),
			Severity:    sev,
			FilePath:    res.Resource, // the affected resource is the "location"
			Metadata:    meta,
		})
	}
	// The control itself failed to execute: there's no per-resource row to
	// blame, but a broken query is still worth surfacing.
	if len(c.Results) == 0 && c.RunStatus == steampipeRunStatusError {
		meta := map[string]any{"status": "error", "run_error": c.RunError}
		if benchmark != "" {
			meta["benchmark"] = benchmark
		}
		out = append(out, ParsedFinding{
			Category:    domain.CategoryCloud,
			RuleID:      c.ControlID,
			Title:       title,
			Description: firstNonEmpty(c.RunError, c.Description),
			Severity:    sev,
			Metadata:    meta,
		})
		return out
	}
	// A summary-only export (no result rows) still says how many resources
	// failed: one finding for the control, so the alarms aren't silently lost.
	if len(c.Results) == 0 && c.Summary.Alarm > 0 {
		meta := map[string]any{"status": "alarm", "alarm_count": c.Summary.Alarm}
		if benchmark != "" {
			meta["benchmark"] = benchmark
		}
		if len(c.Tags) > 0 {
			meta["tags"] = c.Tags
		}
		out = append(out, ParsedFinding{
			Category: domain.CategoryCloud,
			RuleID:   c.ControlID,
			Title:    title,
			Description: firstNonEmpty(c.Description,
				fmt.Sprintf("%d resource(s) in alarm; the export carries no per-resource rows.", c.Summary.Alarm)),
			Severity: sev,
			Metadata: meta,
		})
	}
	return out
}
