package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// KubeBench parses Aqua kube-bench's JSON (`kube-bench --json`) — the CIS
// Kubernetes Benchmark runner. Current releases wrap the controls in
// {"Controls": [...], "Totals": {...}}; older ones print the bare array. Both
// are accepted.
//
// The CIS check number ("1.1.1") is the rule_id, so a CIS Kubernetes framework
// can map it. kube-bench assigns no severity, and we don't invent one:
// FAIL — an automated check that failed — is medium; WARN — a check kube-bench
// could not decide and a human must verify (mostly "Manual" controls) — is low.
// PASS and INFO are not findings.
type KubeBench struct{}

// NewKubeBench constructs a kube-bench parser.
func NewKubeBench() KubeBench { return KubeBench{} }

// Scanner returns the tool identifier.
func (KubeBench) Scanner() string { return "kube-bench" }

// PrimaryCategory is the scan-level category for kube-bench reports.
func (KubeBench) PrimaryCategory() domain.Category { return domain.CategoryKubernetes }

type kubeBenchControls struct {
	ID              string `json:"id"`
	Version         string `json:"version"`
	DetectedVersion string `json:"detected_version"`
	Text            string `json:"text"`
	NodeType        string `json:"node_type"`
	Tests           []struct {
		Section string `json:"section"`
		Desc    string `json:"desc"`
		Results []struct {
			TestNumber     string `json:"test_number"`
			TestDesc       string `json:"test_desc"`
			Audit          string `json:"audit"`
			Remediation    string `json:"remediation"`
			Status         string `json:"status"`
			ActualValue    string `json:"actual_value"`
			ExpectedResult string `json:"expected_result"`
			Scored         bool   `json:"scored"`
			Reason         string `json:"reason"`
		} `json:"results"`
	} `json:"tests"`
}

// Parse implements Parser.
func (KubeBench) Parse(r io.Reader) ([]ParsedFinding, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read kube-bench report: %w", err)
	}
	var controls []kubeBenchControls
	if trimmed := bytes.TrimSpace(raw); len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &controls); err != nil {
			return nil, fmt.Errorf("decode kube-bench report: %w", err)
		}
	} else {
		var wrapped struct {
			Controls *[]kubeBenchControls `json:"Controls"`
		}
		if err := json.Unmarshal(trimmed, &wrapped); err != nil {
			return nil, fmt.Errorf("decode kube-bench report: %w", err)
		}
		if wrapped.Controls == nil {
			return nil, errors.New("decode kube-bench report: no Controls — not a kube-bench JSON report")
		}
		controls = *wrapped.Controls
	}

	var out []ParsedFinding
	for _, c := range controls {
		for _, t := range c.Tests {
			for _, res := range t.Results {
				var severity domain.Severity
				switch strings.ToUpper(res.Status) {
				case "FAIL":
					severity = domain.SeverityMedium
				case "WARN":
					severity = domain.SeverityLow
				default:
					continue
				}
				f := ParsedFinding{
					Category:    domain.CategoryKubernetes,
					RuleID:      res.TestNumber,
					Title:       res.TestDesc,
					Description: strings.TrimSpace(res.Remediation),
					Severity:    severity,
					FilePath:    c.NodeType, // master / etcd / controlplane / node / policies
					Metadata: map[string]any{
						"status":            res.Status,
						"scored":            res.Scored,
						"benchmark_version": firstNonEmpty(c.DetectedVersion, c.Version),
						"control":           c.ID + " " + c.Text,
						"section":           t.Section + " " + t.Desc,
						"audit":             res.Audit,
					},
				}
				if res.ActualValue != "" {
					f.Metadata["actual_value"] = res.ActualValue
				}
				if res.ExpectedResult != "" {
					f.Metadata["expected_result"] = res.ExpectedResult
				}
				if res.Reason != "" {
					f.Metadata["reason"] = res.Reason
				}
				out = append(out, f)
			}
		}
	}
	return out, nil
}
