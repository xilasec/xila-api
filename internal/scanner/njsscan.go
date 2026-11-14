package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// NJSScan parses the JSON output of njsscan, the Node.js SAST tool
// (`njsscan --json -o out.json <dir>`). Results are grouped by rule under
// "nodejs" (code rules) and "templates" (template rules); every file match is
// a finding at its first matched line, rule_id being the rule key
// ("express_xss"). Severity is the rule's ERROR/WARNING/INFO rating.
type NJSScan struct{}

// NewNJSScan constructs an njsscan parser.
func NewNJSScan() NJSScan { return NJSScan{} }

// Scanner returns the tool identifier.
func (NJSScan) Scanner() string { return "njsscan" }

// PrimaryCategory is the scan-level category for njsscan reports.
func (NJSScan) PrimaryCategory() domain.Category { return domain.CategorySAST }

type njsscanReport struct {
	Version   *string                `json:"njsscan_version"`
	NodeJS    map[string]njsscanRule `json:"nodejs"`
	Templates map[string]njsscanRule `json:"templates"`
}

type njsscanRule struct {
	Files []struct {
		FilePath      string `json:"file_path"`
		MatchLines    []int  `json:"match_lines"`
		MatchPosition []int  `json:"match_position"`
		MatchString   string `json:"match_string"`
	} `json:"files"`
	Metadata struct {
		CWE         string `json:"cwe"`
		Description string `json:"description"`
		OWASPWeb    string `json:"owasp-web"`
		OWASPMobile string `json:"owasp-mobile"`
		MASVS       string `json:"masvs"`
		Reference   string `json:"reference"`
		Severity    string `json:"severity"`
	} `json:"metadata"`
}

// Parse converts an njsscan JSON report into findings.
func (NJSScan) Parse(r io.Reader) ([]ParsedFinding, error) {
	var rep njsscanReport
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode njsscan report: %w", err)
	}
	if rep.Version == nil && rep.NodeJS == nil && rep.Templates == nil {
		return nil, errors.New("decode njsscan report: not an njsscan report")
	}
	out := []ParsedFinding{}
	for _, group := range []map[string]njsscanRule{rep.NodeJS, rep.Templates} {
		ids := make([]string, 0, len(group))
		for id := range group {
			ids = append(ids, id)
		}
		sort.Strings(ids) // map order is random; keep output deterministic
		for _, id := range ids {
			rule := group[id]
			md := rule.Metadata
			cwe, _, _ := strings.Cut(md.CWE, ":") // "CWE-79: Improper Neutralization…"
			for _, m := range rule.Files {
				f := ParsedFinding{
					Category:    domain.CategorySAST,
					RuleID:      id,
					Title:       id + ": " + md.Description,
					Description: md.Description,
					Severity:    normalizeSeverity(md.Severity),
					CWE:         cweFrom(cwe),
					FilePath:    m.FilePath,
					Metadata: map[string]any{
						"cwe_name":     md.CWE,
						"match_string": m.MatchString,
					},
				}
				if len(m.MatchLines) > 0 && m.MatchLines[0] > 0 {
					f.Line = intPtr(m.MatchLines[0])
					f.Metadata["end_line"] = m.MatchLines[len(m.MatchLines)-1]
				}
				for k, v := range map[string]string{
					"owasp_web":    md.OWASPWeb,
					"owasp_mobile": md.OWASPMobile,
					"masvs":        md.MASVS,
					"references":   md.Reference,
				} {
					if v != "" {
						f.Metadata[k] = v
					}
				}
				out = append(out, f)
			}
		}
	}
	return mergeSameLocation(out), nil
}
