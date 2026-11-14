package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Kubeaudit parses kubeaudit's JSON output (`kubeaudit all -f manifest.yaml -o json`),
// a Kubernetes manifest auditor. Output is newline-delimited JSON log entries;
// error/warning entries become findings.
type Kubeaudit struct{}

// NewKubeaudit constructs a Kubeaudit parser.
func NewKubeaudit() Kubeaudit { return Kubeaudit{} }

// Scanner returns the tool identifier.
func (Kubeaudit) Scanner() string { return "kubeaudit" }

// PrimaryCategory is the scan-level category for kubeaudit reports.
func (Kubeaudit) PrimaryCategory() domain.Category { return domain.CategoryKubernetes }

type kubeauditEntry struct {
	Level             string `json:"level"`
	Msg               string `json:"msg"`
	AuditResultName   string `json:"AuditResultName"`
	ResourceKind      string `json:"ResourceKind"`
	ResourceName      string `json:"ResourceName"`
	ResourceNamespace string `json:"ResourceNamespace"`
	Container         string `json:"Container"`
}

// Parse implements Parser. It reads a stream of JSON objects (JSONL).
func (Kubeaudit) Parse(r io.Reader) ([]ParsedFinding, error) {
	dec := json.NewDecoder(r)
	var out []ParsedFinding
	for {
		var e kubeauditEntry
		if err := dec.Decode(&e); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("decode kubeaudit entry: %w", err)
		}
		// info-level entries are advisories, not findings.
		if e.AuditResultName == "" || strings.EqualFold(e.Level, "info") {
			continue
		}

		name := e.ResourceName
		if e.ResourceNamespace != "" {
			name = e.ResourceNamespace + "/" + name
		}
		out = append(out, ParsedFinding{
			Category:    domain.CategoryKubernetes,
			RuleID:      e.AuditResultName,
			Title:       e.AuditResultName,
			Description: e.Msg,
			Severity:    mapKubeauditLevel(e.Level),
			FilePath:    strings.TrimSpace(e.ResourceKind + " " + name),
			Metadata:    map[string]any{"container": e.Container},
		})
	}
	return out, nil
}

func mapKubeauditLevel(level string) domain.Severity {
	switch strings.ToLower(level) {
	case "error":
		return domain.SeverityHigh
	case "warning", "warn":
		return domain.SeverityMedium
	default:
		return domain.SeverityLow
	}
}
