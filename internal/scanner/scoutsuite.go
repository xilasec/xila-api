package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// ScoutSuite parses NCC Group ScoutSuite's results file — the
// `scoutsuite-results/scoutsuite_results_<account>.js` the HTML report loads
// (a `scoutsuite_results =` assignment wrapping JSON), or the same object as
// plain JSON (`--result-format json`).
//
// Each rule under services.<svc>.findings lists the resources it flagged by
// their path in the results tree; every flagged resource becomes one finding
// whose rule_id is the rule key (e.g. "iam-root-account-no-mfa"), so failures
// map to compliance controls like the other CSPM tools. Rules that flagged
// nothing are passes and are skipped.
type ScoutSuite struct{}

// NewScoutSuite constructs a ScoutSuite parser.
func NewScoutSuite() ScoutSuite { return ScoutSuite{} }

// Scanner returns the tool identifier.
func (ScoutSuite) Scanner() string { return "scoutsuite" }

// PrimaryCategory is the scan-level category for ScoutSuite reports.
func (ScoutSuite) PrimaryCategory() domain.Category { return domain.CategoryCloud }

type scoutSuiteReport struct {
	ProviderCode string                     `json:"provider_code"`
	AccountID    string                     `json:"account_id"`
	Services     map[string]json.RawMessage `json:"services"`
}

type scoutSuiteFinding struct {
	Description   string   `json:"description"`
	Rationale     *string  `json:"rationale"`
	Remediation   *string  `json:"remediation"`
	Level         string   `json:"level"`
	Service       string   `json:"service"`
	DashboardName string   `json:"dashboard_name"`
	IDSuffix      *string  `json:"id_suffix"`
	Items         []string `json:"items"`
	FlaggedItems  int      `json:"flagged_items"`
	References    []string `json:"references"`
	Compliance    []struct {
		Name      string `json:"name"`
		Version   string `json:"version"`
		Reference string `json:"reference"`
	} `json:"compliance"`
}

// Parse implements Parser.
func (ScoutSuite) Parse(r io.Reader) ([]ParsedFinding, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read scoutsuite report: %w", err)
	}
	// Strip the JavaScript assignment the .js results file wraps the JSON in.
	start := bytes.IndexByte(raw, '{')
	if start < 0 {
		return nil, errors.New("decode scoutsuite report: no JSON object found")
	}
	if prefix := bytes.TrimSpace(raw[:start]); len(prefix) > 0 && !bytes.Contains(prefix, []byte("scoutsuite_results")) {
		return nil, errors.New("decode scoutsuite report: unexpected content before the results object")
	}
	var rep scoutSuiteReport
	if err := json.Unmarshal(raw[start:], &rep); err != nil {
		return nil, fmt.Errorf("decode scoutsuite report: %w", err)
	}
	if rep.Services == nil {
		return nil, errors.New("decode scoutsuite report: no services — not a ScoutSuite results file")
	}

	var out []ParsedFinding
	for _, svcName := range slices.Sorted(maps.Keys(rep.Services)) {
		var svc struct {
			Findings map[string]scoutSuiteFinding `json:"findings"`
		}
		if err := json.Unmarshal(rep.Services[svcName], &svc); err != nil {
			return nil, fmt.Errorf("decode scoutsuite service %s: %w", svcName, err)
		}
		var tree any // the service's resource tree, decoded only if something was flagged
		for _, ruleID := range slices.Sorted(maps.Keys(svc.Findings)) {
			rule := svc.Findings[ruleID]
			if rule.FlaggedItems == 0 || len(rule.Items) == 0 {
				continue // checked and passed
			}
			if tree == nil {
				if err := json.Unmarshal(rep.Services[svcName], &tree); err != nil {
					return nil, fmt.Errorf("decode scoutsuite service %s: %w", svcName, err)
				}
			}
			for _, item := range rule.Items {
				out = append(out, scoutSuiteItem(rep, svcName, ruleID, rule, item, tree))
			}
		}
	}
	return out, nil
}

func scoutSuiteItem(rep scoutSuiteReport, svcName, ruleID string, rule scoutSuiteFinding, item string, tree any) ParsedFinding {
	// The item is the flagged attribute's path ("…buckets.<id>.logging_enabled");
	// the resource is that path without the rule's attribute suffix.
	resourcePath := item
	if s := strOrEmpty(rule.IDSuffix); s != "" {
		resourcePath = strings.TrimSuffix(resourcePath, "."+s)
	}
	name := scoutSuiteResourceName(tree, strings.TrimPrefix(resourcePath, svcName+"."))

	compliance := make([]string, 0, len(rule.Compliance))
	for _, c := range rule.Compliance {
		compliance = append(compliance, strings.TrimSpace(fmt.Sprintf("%s %s %s", c.Name, c.Version, c.Reference)))
	}
	f := ParsedFinding{
		Category:    domain.CategoryCloud,
		RuleID:      ruleID,
		Title:       firstNonEmpty(rule.Description, ruleID),
		Description: strings.TrimSpace(strOrEmpty(rule.Rationale) + "\n" + firstNonEmpty(name, resourcePath)),
		Severity:    dangerSeverity(rule.Level),
		FilePath:    resourcePath, // the flagged resource is the "location"
		Metadata: map[string]any{
			"provider":    rep.ProviderCode,
			"account":     rep.AccountID,
			"service":     firstNonEmpty(rule.Service, svcName),
			"dashboard":   rule.DashboardName,
			"resource":    name,
			"remediation": strOrEmpty(rule.Remediation),
			"compliance":  compliance,
		},
	}
	if len(rule.References) > 0 {
		f.URL = rule.References[0]
	}
	return f
}

// dangerSeverity maps the two-level "danger"/"warning" scale ScoutSuite and
// Polaris share. Neither tool ranks finer, so neither do we.
func dangerSeverity(level string) domain.Severity {
	if strings.EqualFold(level, "danger") {
		return domain.SeverityHigh
	}
	return normalizeSeverity(level)
}

// scoutSuiteResourceName walks a dotted resource path through the service tree
// and returns the "name" of the deepest named object on it — the bucket, the
// security group whose rule was flagged, … — or "" when nothing on the path is
// named. Keys may themselves contain dots (bucket names, ARNs), so a component
// that doesn't match is joined with the next one and retried.
func scoutSuiteResourceName(tree any, path string) string {
	parts := strings.Split(path, ".")
	node, name := tree, ""
	for i := 0; ; {
		obj, ok := node.(map[string]any)
		if !ok {
			return name
		}
		if n, ok := obj["name"].(string); ok && n != "" {
			name = n
		}
		if i >= len(parts) {
			return name
		}
		matched := false
		for j := i + 1; j <= len(parts); j++ {
			if child, ok := obj[strings.Join(parts[i:j], ".")]; ok {
				node, i, matched = child, j, true
				break
			}
		}
		if !matched {
			return name
		}
	}
}
