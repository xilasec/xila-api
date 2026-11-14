package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// RetireJS parses `retire --outputformat json`: vulnerable JavaScript libraries
// found vendored in a tree (jquery.min.js copied into static/), which lockfile
// scanners miss. Retire.js 2+ wraps results as {"data":[…]}; 1.x emitted the
// array bare. Each advisory is keyed by its CVE (else GHSA, else the upstream
// issue), and two advisories naming the same CVE for the same file collapse
// into one finding.
type RetireJS struct{}

// NewRetireJS constructs a RetireJS parser.
func NewRetireJS() RetireJS { return RetireJS{} }

// Scanner returns the tool identifier.
func (RetireJS) Scanner() string { return "retirejs" }

// PrimaryCategory is the scan-level category for Retire.js reports.
func (RetireJS) PrimaryCategory() domain.Category { return domain.CategorySCA }

type retireFile struct {
	File    string `json:"file"`
	Results []struct {
		Component       string `json:"component"`
		Version         string `json:"version"`
		Detection       string `json:"detection"`
		Vulnerabilities []struct {
			Info        []string `json:"info"`
			Below       string   `json:"below"`
			AtOrAbove   string   `json:"atOrAbove"`
			Severity    string   `json:"severity"`
			CWE         []string `json:"cwe"`
			Identifiers struct {
				Summary  string      `json:"summary"`
				CVE      []string    `json:"CVE"`
				GithubID string      `json:"githubID"`
				Issue    flexStrings `json:"issue"`
				Bug      flexStrings `json:"bug"`
			} `json:"identifiers"`
		} `json:"vulnerabilities"`
	} `json:"results"`
}

// Parse converts a Retire.js JSON report into findings.
func (RetireJS) Parse(r io.Reader) ([]ParsedFinding, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read retire.js report: %w", err)
	}
	var files []retireFile
	if data = bytes.TrimSpace(data); len(data) > 0 && data[0] == '[' {
		err = json.Unmarshal(data, &files)
	} else {
		var doc struct {
			Data *[]retireFile `json:"data"`
		}
		if err = json.Unmarshal(data, &doc); err == nil {
			if doc.Data == nil {
				return nil, fmt.Errorf(`decode retire.js report: no "data" array`)
			}
			files = *doc.Data
		}
	}
	if err != nil {
		return nil, fmt.Errorf("decode retire.js report: %w", err)
	}

	out := []ParsedFinding{}
	index := map[string]int{}
	for _, file := range files {
		for _, res := range file.Results {
			for _, v := range res.Vulnerabilities {
				id := v.Identifiers
				ruleID := firstNonEmpty(firstOf(id.CVE), id.GithubID)
				if ruleID == "" {
					ref := firstNonEmpty(firstOf(id.Issue), firstOf(id.Bug))
					if ref == "" {
						ref = "below-" + v.Below
					}
					ruleID = "retire:" + res.Component + ":" + ref
				}
				key := file.File + "\x00" + res.Component + "\x00" + res.Version + "\x00" + ruleID
				if i, ok := index[key]; ok {
					merged := &out[i]
					merged.CVE = mergeStrings(merged.CVE, cvesFrom(id.CVE...))
					if id.Summary != "" && !strings.Contains(merged.Description, id.Summary) {
						merged.Description += "\n" + id.Summary
					}
					if s := normalizeSeverity(v.Severity); s.Weight() > merged.Severity.Weight() {
						merged.Severity = s
					}
					continue
				}
				f := ParsedFinding{
					Category:       domain.CategorySCA,
					RuleID:         ruleID,
					Title:          fmt.Sprintf("%s %s: %s", res.Component, res.Version, firstNonEmpty(id.Summary, ruleID)),
					Description:    id.Summary,
					Severity:       normalizeSeverity(v.Severity),
					CWE:            cweFirst(v.CWE...),
					CVE:            cvesFrom(id.CVE...),
					FilePath:       file.File,
					Package:        res.Component,
					PackageVersion: res.Version,
					FixedVersion:   v.Below,
					Purl:           ecosystemPurl("npm", res.Component, res.Version),
					URL:            firstOf(v.Info),
					Metadata: map[string]any{
						"detection": res.Detection,
						"info":      v.Info,
						"below":     v.Below,
					},
				}
				if v.AtOrAbove != "" {
					f.Metadata["at_or_above"] = v.AtOrAbove
				}
				if id.GithubID != "" {
					f.Metadata["ghsa"] = id.GithubID
				}
				index[key] = len(out)
				out = append(out, f)
			}
		}
	}
	return mergeSameLocation(out), nil
}

func firstOf(vals []string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func mergeStrings(a, b []string) []string {
	for _, v := range b {
		if !slices.Contains(a, v) {
			a = append(a, v)
		}
	}
	return a
}
