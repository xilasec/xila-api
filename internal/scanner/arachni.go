package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/xilasec/xila-api/internal/domain"
)

// Arachni parses the JSON report Arachni Web Scanner's `arachni_reporter`
// generates from a saved .afr scan (`arachni_reporter --reporter 'json'
// scan.afr`). Arachni reports only confirmed issues — there is no "passed
// check" entry — so every issue in the report is a finding.
type Arachni struct{}

// NewArachni constructs an Arachni parser.
func NewArachni() Arachni { return Arachni{} }

// Scanner returns the tool identifier.
func (Arachni) Scanner() string { return "arachni" }

// PrimaryCategory is the scan-level category for Arachni reports.
func (Arachni) PrimaryCategory() domain.Category { return domain.CategoryDAST }

type arachniReport struct {
	Issues []arachniIssue `json:"issues"`
}

type arachniIssue struct {
	Name           string            `json:"name"`
	Description    string            `json:"description"`
	References     map[string]string `json:"references"`
	CWE            int               `json:"cwe"`
	Severity       string            `json:"severity"`
	RemedyGuidance string            `json:"remedy_guidance"`
	Check          struct {
		Name      string `json:"name"`
		Shortname string `json:"shortname"`
	} `json:"check"`
	Vector struct {
		Type              string `json:"type"`
		URL               string `json:"url"`
		Action            string `json:"action"`
		Method            string `json:"method"`
		AffectedInputName string `json:"affected_input_name"`
	} `json:"vector"`
	Proof string `json:"proof"`
}

// Parse implements Parser.
func (Arachni) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report arachniReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode arachni report: %w", err)
	}
	if report.Issues == nil {
		return nil, errors.New(`decode arachni report: no "issues" array — not an arachni JSON report`)
	}

	out := make([]ParsedFinding, 0, len(report.Issues))
	for _, iss := range report.Issues {
		url := firstNonEmpty(iss.Vector.Action, iss.Vector.URL)
		meta := map[string]any{"check": iss.Check.Shortname, "vector_type": iss.Vector.Type}
		if iss.Vector.AffectedInputName != "" {
			meta["affected_input_name"] = iss.Vector.AffectedInputName
		}
		if iss.Vector.Method != "" {
			meta["method"] = iss.Vector.Method
		}
		if iss.Proof != "" {
			meta["proof"] = iss.Proof
		}
		if len(iss.References) > 0 {
			meta["references"] = iss.References
		}
		f := ParsedFinding{
			Category:    domain.CategoryDAST,
			RuleID:      iss.Check.Shortname,
			Title:       iss.Name,
			Description: iss.Description,
			Severity:    normalizeSeverity(iss.Severity),
			FilePath:    url, // DAST: the URL the finding was proven on is the "location"
			URL:         url,
			Metadata:    meta,
		}
		if iss.CWE > 0 {
			cwe := iss.CWE
			f.CWE = &cwe
		}
		out = append(out, f)
	}
	return mergeSameLocation(out), nil
}
