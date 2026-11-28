package scanner

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/xilasec/xila-api/internal/domain"
)

// Nuclei parses `nuclei -jsonl` output (one JSON object per line). Nuclei is
// template-driven DAST: each hit is a template that *matched* against a live
// host, so findings are evidence, not inference.
type Nuclei struct{}

// NewNuclei constructs a Nuclei parser.
func NewNuclei() Nuclei { return Nuclei{} }

// Scanner returns the tool identifier.
func (Nuclei) Scanner() string { return "nuclei" }

// PrimaryCategory is the scan-level category for Nuclei reports.
func (Nuclei) PrimaryCategory() domain.Category { return domain.CategoryDAST }

type nucleiFinding struct {
	TemplateID string `json:"template-id"`
	Type       string `json:"type"`
	Host       string `json:"host"`
	MatchedAt  string `json:"matched-at"`
	Info       struct {
		Name           string   `json:"name"`
		Severity       string   `json:"severity"`
		Description    string   `json:"description"`
		Reference      []string `json:"reference"`
		Tags           []string `json:"tags"`
		Classification struct {
			CveID     []string `json:"cve-id"`
			CweID     []string `json:"cwe-id"`
			CVSSScore float64  `json:"cvss-score"`
		} `json:"classification"`
	} `json:"info"`
}

// Parse converts a Nuclei JSONL stream into findings.
func (Nuclei) Parse(r io.Reader) ([]ParsedFinding, error) {
	var out []ParsedFinding
	err := decodeJSONLines(r, func(raw json.RawMessage) error {
		var n nucleiFinding
		if err := json.Unmarshal(raw, &n); err != nil {
			return fmt.Errorf("decode nuclei finding: %w", err)
		}
		if n.TemplateID == "" {
			return nil
		}

		f := ParsedFinding{
			Category:    domain.CategoryDAST,
			RuleID:      n.TemplateID,
			Title:       firstNonEmptyStr(n.Info.Name, n.TemplateID),
			Description: n.Info.Description,
			Severity:    normalizeSeverity(n.Info.Severity),
			CVE:         cvesFrom(n.Info.Classification.CveID...),
			FilePath:    firstNonEmptyStr(n.MatchedAt, n.Host),
			Metadata: map[string]any{
				"host": n.Host,
				"type": n.Type,
				"tags": n.Info.Tags,
			},
		}
		if len(n.Info.Classification.CweID) > 0 {
			f.CWE = cweFrom(n.Info.Classification.CweID[0])
		}
		if n.Info.Classification.CVSSScore > 0 {
			f.CVSS = new(n.Info.Classification.CVSSScore)
		}
		if len(n.Info.Reference) > 0 {
			f.URL = n.Info.Reference[0]
		}
		out = append(out, f)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
