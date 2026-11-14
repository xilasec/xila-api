package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Zap parses OWASP ZAP's JSON report (`zap-baseline.py -J out.json`, or the
// desktop "Export JSON" report) — the standard OSS DAST tool.
type Zap struct{}

// NewZap constructs a Zap parser.
func NewZap() Zap { return Zap{} }

// Scanner returns the tool identifier.
func (Zap) Scanner() string { return "zap" }

// PrimaryCategory is the scan-level category for ZAP reports.
func (Zap) PrimaryCategory() domain.Category { return domain.CategoryDAST }

type zapReport struct {
	Site []struct {
		Name   string `json:"@name"`
		Alerts []struct {
			PluginID  string `json:"pluginid"`
			AlertRef  string `json:"alertRef"`
			Name      string `json:"name"`
			RiskDesc  string `json:"riskdesc"` // "High (Medium)" — risk, then confidence
			Desc      string `json:"desc"`
			Solution  string `json:"solution"`
			Reference string `json:"reference"`
			CWEID     string `json:"cweid"`
			Instances []struct {
				URI    string `json:"uri"`
				Method string `json:"method"`
				Param  string `json:"param"`
			} `json:"instances"`
		} `json:"alerts"`
	} `json:"site"`
}

// Parse converts a ZAP report into findings.
func (Zap) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report zapReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode zap report: %w", err)
	}

	var out []ParsedFinding
	for _, site := range report.Site {
		for _, a := range site.Alerts {
			risk, confidence := zapRisk(a.RiskDesc)

			f := ParsedFinding{
				Category:    domain.CategoryDAST,
				RuleID:      firstNonEmptyStr(a.AlertRef, a.PluginID),
				Title:       a.Name,
				Description: stripTags(a.Desc),
				Severity:    normalizeSeverity(risk),
				CWE:         cweFrom(a.CWEID),
				URL:         site.Name,
				Metadata: map[string]any{
					"confidence": confidence,
					"solution":   stripTags(a.Solution),
					"instances":  len(a.Instances),
				},
			}
			// The URL a finding was proven on is the closest thing DAST has to a
			// file path — it's what you'd paste into a browser to reproduce.
			if len(a.Instances) > 0 {
				f.FilePath = a.Instances[0].URI
				f.Metadata["method"] = a.Instances[0].Method
				f.Metadata["param"] = a.Instances[0].Param
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// zapRisk splits ZAP's "High (Medium)" into risk and confidence.
func zapRisk(riskDesc string) (risk, confidence string) {
	risk, rest, found := strings.Cut(riskDesc, "(")
	risk = strings.TrimSpace(risk)
	if found {
		confidence = strings.TrimSuffix(strings.TrimSpace(rest), ")")
	}
	return risk, confidence
}

// stripTags removes the HTML ZAP wraps its prose in, so descriptions read as text.
func stripTags(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch {
		case r == '<':
			depth++
		case r == '>' && depth > 0:
			depth--
		case depth == 0:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}
