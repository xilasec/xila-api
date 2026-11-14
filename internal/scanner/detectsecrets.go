package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// DetectSecrets parses a detect-secrets baseline (`detect-secrets scan >
// .secrets.baseline`, optionally audited with `detect-secrets audit`). Like
// Gitleaks it has no severity: a secret is high either way, and critical when
// detect-secrets verified it live. Several plugins often flag the same line
// (a GitHub token is also a high-entropy string and a "secret keyword"), so a
// line yields one finding, named by its most specific detector. An audited
// baseline's verdicts are carried as imported triage: is_secret=false → false
// positive, is_secret=true → confirmed.
type DetectSecrets struct{}

// NewDetectSecrets constructs a DetectSecrets parser.
func NewDetectSecrets() DetectSecrets { return DetectSecrets{} }

// Scanner returns the tool identifier.
func (DetectSecrets) Scanner() string { return "detect-secrets" }

// PrimaryCategory is the scan-level category for detect-secrets baselines.
func (DetectSecrets) PrimaryCategory() domain.Category { return domain.CategorySecret }

type detectSecretsEntry struct {
	Type         string `json:"type"`
	Filename     string `json:"filename"`
	HashedSecret string `json:"hashed_secret"`
	IsVerified   bool   `json:"is_verified"`
	LineNumber   int    `json:"line_number"`
	IsSecret     *bool  `json:"is_secret"`
}

// genericSecretDetectors are the catch-all plugins; any other detector that
// fires on the same line names the secret more precisely.
var genericSecretDetectors = []string{"Base64 High Entropy String", "Hex High Entropy String", "Secret Keyword"}

// Parse converts a detect-secrets baseline into findings.
func (DetectSecrets) Parse(r io.Reader) ([]ParsedFinding, error) {
	var baseline struct {
		Version string                          `json:"version"`
		Results map[string][]detectSecretsEntry `json:"results"`
	}
	if err := json.NewDecoder(r).Decode(&baseline); err != nil {
		return nil, fmt.Errorf("decode detect-secrets baseline: %w", err)
	}
	if baseline.Results == nil {
		return nil, errors.New(`decode detect-secrets baseline: no "results" object`)
	}

	files := make([]string, 0, len(baseline.Results))
	for f := range baseline.Results {
		files = append(files, f)
	}
	slices.Sort(files) // deterministic output order

	out := []ParsedFinding{}
	for _, file := range files {
		byLine := map[int][]detectSecretsEntry{}
		var lines []int
		for _, e := range baseline.Results[file] {
			if _, ok := byLine[e.LineNumber]; !ok {
				lines = append(lines, e.LineNumber)
			}
			byLine[e.LineNumber] = append(byLine[e.LineNumber], e)
		}
		slices.Sort(lines)
		for _, line := range lines {
			out = append(out, detectSecretsFinding(file, line, byLine[line]))
		}
	}
	return mergeSameLocation(out), nil
}

func detectSecretsFinding(file string, line int, entries []detectSecretsEntry) ParsedFinding {
	primary := entries[0]
	types := make([]string, 0, len(entries))
	verified := false
	var audited *bool
	for _, e := range entries {
		types = append(types, e.Type)
		if slices.Contains(genericSecretDetectors, primary.Type) && !slices.Contains(genericSecretDetectors, e.Type) {
			primary = e
		}
		verified = verified || e.IsVerified
		if e.IsSecret != nil {
			// One audited "real" outweighs a "false positive" on another plugin.
			if audited == nil || *e.IsSecret {
				audited = e.IsSecret
			}
		}
	}
	f := ParsedFinding{
		Category:    domain.CategorySecret,
		RuleID:      secretRuleID(primary.Type),
		Title:       fmt.Sprintf("%s in %s", primary.Type, file),
		Description: fmt.Sprintf("detect-secrets found a %s on line %d (detectors: %s). Rotate the credential and remove it from the repository history.", primary.Type, line, strings.Join(types, ", ")),
		Severity:    domain.SeverityHigh,
		FilePath:    firstNonEmpty(file, primary.Filename),
		Metadata: map[string]any{
			"detectors":     types,
			"hashed_secret": primary.HashedSecret,
			"verified":      verified,
		},
	}
	if line > 0 {
		f.Line = intPtr(line)
	}
	if verified {
		f.Severity = domain.SeverityCritical
	}
	if audited != nil {
		if *audited {
			setImportedStatus(f.Metadata, domain.FindingConfirmed, "audited as a real secret (detect-secrets audit)", zeroTime)
		} else {
			setImportedStatus(f.Metadata, domain.FindingFalsePositive, "audited as not a secret (detect-secrets audit)", zeroTime)
		}
	}
	return f
}

// secretRuleID slugs a detector name ("AWS Access Key" → "aws-access-key").
func secretRuleID(name string) string {
	return strings.Join(strings.Fields(strings.ToLower(name)), "-")
}
