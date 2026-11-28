package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Sarif parses SARIF 2.1.0 — the format emitted by Semgrep, CodeQL, gitleaks,
// checkov, grype, trivy (--format sarif) and many others. Because SARIF is
// tool-agnostic, this one parser covers a large slice of the ecosystem.
//
// It is resolved by the ?format=sarif query parameter; the finding's scanner
// identity still comes from ?scanner= (e.g. semgrep), so dedup and auto-close
// remain per-tool.
type Sarif struct{}

// NewSarif constructs a SARIF parser.
func NewSarif() Sarif { return Sarif{} }

// Scanner returns the format identifier used to select this parser.
func (Sarif) Scanner() string { return "sarif" }

// PrimaryCategory is the scan-level default; individual findings refine it.
func (Sarif) PrimaryCategory() domain.Category { return domain.CategorySAST }

type sarifDoc struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Name  string      `json:"name"`
				Rules []sarifRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []sarifResult `json:"results"`
	} `json:"runs"`
}

type sarifProps struct {
	SecuritySeverity string   `json:"security-severity"`
	Tags             []string `json:"tags"`
}

type sarifRule struct {
	ID               string `json:"id"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	FullDescription struct {
		Text string `json:"text"`
	} `json:"fullDescription"`
	HelpURI              string `json:"helpUri"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Properties sarifProps `json:"properties"`
}

type sarifResult struct {
	RuleID    string `json:"ruleId"`
	RuleIndex *int   `json:"ruleIndex"`
	Level     string `json:"level"`
	Message   struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
	Properties sarifProps `json:"properties"`
}

// Parse implements Parser.
func (Sarif) Parse(r io.Reader) ([]ParsedFinding, error) {
	var doc sarifDoc
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode sarif: %w", err)
	}

	var out []ParsedFinding
	for _, run := range doc.Runs {
		rules := run.Tool.Driver.Rules
		byID := make(map[string]sarifRule, len(rules))
		for _, rule := range rules {
			byID[rule.ID] = rule
		}

		for _, res := range run.Results {
			rule := ruleFor(res, rules, byID)
			file, line := sarifLocation(res)
			out = append(out, ParsedFinding{
				Category:    sarifCategory(rule, res),
				RuleID:      firstNonEmpty(res.RuleID, rule.ID),
				Title:       firstNonEmpty(rule.ShortDescription.Text, res.Message.Text, res.RuleID, rule.ID),
				Description: firstNonEmpty(res.Message.Text, rule.FullDescription.Text),
				Severity:    sarifSeverity(res, rule),
				CWE:         sarifCWE(res, rule),
				FilePath:    file,
				Line:        line,
				URL:         rule.HelpURI,
				Metadata:    map[string]any{"tool": run.Tool.Driver.Name},
			})
		}
	}
	return out, nil
}

// ruleFor resolves the rule a result refers to, by index or id.
func ruleFor(res sarifResult, rules []sarifRule, byID map[string]sarifRule) sarifRule {
	if res.RuleIndex != nil && *res.RuleIndex >= 0 && *res.RuleIndex < len(rules) {
		return rules[*res.RuleIndex]
	}
	return byID[res.RuleID]
}

func sarifLocation(res sarifResult) (string, *int) {
	if len(res.Locations) == 0 {
		return "", nil
	}
	loc := res.Locations[0].PhysicalLocation
	var line *int
	if loc.Region.StartLine > 0 {
		line = new(loc.Region.StartLine)
	}
	return loc.ArtifactLocation.URI, line
}

// sarifSeverity prefers the numeric security-severity (0–10, GitHub convention),
// falling back to the SARIF level.
func sarifSeverity(res sarifResult, rule sarifRule) domain.Severity {
	if ss := firstNonEmpty(res.Properties.SecuritySeverity, rule.Properties.SecuritySeverity); ss != "" {
		if f, err := strconv.ParseFloat(ss, 64); err == nil {
			switch {
			case f >= 9:
				return domain.SeverityCritical
			case f >= 7:
				return domain.SeverityHigh
			case f >= 4:
				return domain.SeverityMedium
			case f > 0:
				return domain.SeverityLow
			default:
				return domain.SeverityInfo
			}
		}
	}
	switch firstNonEmpty(res.Level, rule.DefaultConfiguration.Level) {
	case "error":
		return domain.SeverityHigh
	case "warning":
		return domain.SeverityMedium
	case "note":
		return domain.SeverityLow
	default:
		return domain.SeverityInfo
	}
}

var cweRe = regexp.MustCompile(`(?i)cwe[-:/ ]?(\d+)`)

func sarifCWE(res sarifResult, rule sarifRule) *int {
	tags := append(append([]string{}, rule.Properties.Tags...), res.Properties.Tags...)
	for _, t := range tags {
		if m := cweRe.FindStringSubmatch(t); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil {
				return new(n)
			}
		}
	}
	return nil
}

// sarifCategory infers the finding class from rule/result tags.
func sarifCategory(rule sarifRule, res sarifResult) domain.Category {
	tags := strings.ToLower(strings.Join(append(append([]string{}, rule.Properties.Tags...), res.Properties.Tags...), " "))
	switch {
	case strings.Contains(tags, "secret"):
		return domain.CategorySecret
	case containsAny(tags, "terraform", "iac", "kubernetes", "dockerfile", "cloudformation", "misconfig"):
		return domain.CategoryIaC
	case containsAny(tags, "container", "image"):
		return domain.CategoryContainer
	case strings.Contains(tags, "license"):
		return domain.CategoryLicense
	case containsAny(tags, "dependency", "sca", "supply-chain", "vulnerability"):
		return domain.CategorySCA
	default:
		return domain.CategorySAST
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
