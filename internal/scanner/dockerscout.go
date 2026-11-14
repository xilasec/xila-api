package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// DockerScout parses `docker scout cves --format sarif <image>`. The generic
// SARIF path accepts this file too, but it drops everything Scout puts outside
// the SARIF core — the package PURL, fixed version and CVSS score (rule
// properties / logical locations) and the CVE itself (Scout's rule id) — so the
// findings can't dedup against other scanners or be enriched. This parser reads
// Scout's extensions.
type DockerScout struct{}

// NewDockerScout constructs a Docker Scout parser.
func NewDockerScout() DockerScout { return DockerScout{} }

// Scanner returns the tool identifier.
func (DockerScout) Scanner() string { return "docker-scout" }

// PrimaryCategory is the scan-level category for Docker Scout reports.
func (DockerScout) PrimaryCategory() domain.Category { return domain.CategoryContainer }

type scoutRule struct {
	ID               string `json:"id"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	Help struct {
		Text string `json:"text"`
	} `json:"help"`
	HelpURI    string `json:"helpUri"`
	Properties struct {
		AffectedVersion string   `json:"affected_version"`
		FixedVersion    string   `json:"fixed_version"`
		CVSSV3          float64  `json:"cvssV3"`
		CVSSV3Severity  string   `json:"cvssV3_severity"`
		CVSSV3Vector    string   `json:"cvssV3_vector"`
		Purls           []string `json:"purls"`
	} `json:"properties"`
}

type scoutSarif struct {
	Runs *[]struct {
		Tool struct {
			Driver struct {
				Name    string      `json:"name"`
				Version string      `json:"version"`
				Rules   []scoutRule `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			RuleIndex *int   `json:"ruleIndex"`
			Message   struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
				} `json:"physicalLocation"`
				LogicalLocations []struct {
					Name               string `json:"name"`
					FullyQualifiedName string `json:"fullyQualifiedName"`
				} `json:"logicalLocations"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

// Parse implements Parser.
func (DockerScout) Parse(r io.Reader) ([]ParsedFinding, error) {
	var doc scoutSarif
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode docker scout sarif: %w", err)
	}
	if doc.Runs == nil {
		return nil, errors.New("decode docker scout sarif: no runs — not a SARIF report")
	}

	var out []ParsedFinding
	for _, run := range *doc.Runs {
		rules := run.Tool.Driver.Rules
		byID := make(map[string]scoutRule, len(rules))
		for _, rule := range rules {
			byID[rule.ID] = rule
		}
		for _, res := range run.Results {
			rule, ok := byID[res.RuleID]
			if res.RuleIndex != nil && *res.RuleIndex >= 0 && *res.RuleIndex < len(rules) {
				rule, ok = rules[*res.RuleIndex], true
			}
			if !ok {
				rule.ID = res.RuleID
			}

			purl, path := "", ""
			for _, loc := range res.Locations {
				path = firstNonEmpty(path, loc.PhysicalLocation.ArtifactLocation.URI)
				for _, ll := range loc.LogicalLocations {
					if strings.HasPrefix(ll.FullyQualifiedName, "pkg:") {
						purl = firstNonEmpty(purl, ll.FullyQualifiedName)
					} else {
						path = firstNonEmpty(path, ll.FullyQualifiedName)
					}
				}
			}
			if purl == "" {
				purl = scoutMessageField(res.Message.Text, "Package")
				if !strings.HasPrefix(purl, "pkg:") {
					purl = ""
				}
			}
			if purl == "" && len(rule.Properties.Purls) == 1 {
				purl = rule.Properties.Purls[0]
			}
			name, version := purlParts(purl)

			p := rule.Properties
			severity := normalizeSeverity(p.CVSSV3Severity)
			if strings.EqualFold(p.CVSSV3Severity, "unspecified") || p.CVSSV3Severity == "" {
				severity = domain.SeverityMedium // unranked stays visible
				if p.CVSSV3 > 0 {
					severity = severityFromCVSS(p.CVSSV3)
				}
			}
			f := ParsedFinding{
				Category:       domain.CategoryContainer,
				RuleID:         rule.ID,
				Title:          fmt.Sprintf("%s in %s", rule.ID, firstNonEmpty(name, purl, path)),
				Description:    strings.TrimSpace(firstNonEmpty(rule.Help.Text, rule.ShortDescription.Text)),
				Severity:       severity,
				CVE:            cvesFrom(rule.ID),
				Package:        name,
				PackageVersion: version,
				FixedVersion:   scoutFixed(p.FixedVersion),
				Purl:           purl,
				FilePath:       path,
				URL:            rule.HelpURI,
				Metadata: map[string]any{
					"affected_range": p.AffectedVersion,
					"summary":        rule.ShortDescription.Text,
				},
			}
			if p.CVSSV3 > 0 {
				f.CVSS = floatPtr(p.CVSSV3)
				f.Metadata["cvss_vector"] = p.CVSSV3Vector
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// scoutMessageField reads "  Key   : value" from Scout's result message.
func scoutMessageField(msg, key string) string {
	for line := range strings.SplitSeq(msg, "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(k) == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// scoutFixed drops Scout's "not fixed" placeholder.
func scoutFixed(v string) string {
	if strings.EqualFold(v, "not fixed") {
		return ""
	}
	return v
}

// purlParts splits a package URL into the package name (with its
// namespace for npm scopes / Go modules, as other scanners report it) and
// version: pkg:npm/%40scope/name@1.2.3 → "@scope/name", "1.2.3".
func purlParts(purl string) (name, version string) {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return "", ""
	}
	rest, _, _ = strings.Cut(rest, "#")
	rest, _, _ = strings.Cut(rest, "?")
	typ, path, ok := strings.Cut(rest, "/")
	if !ok {
		return "", ""
	}
	if at := strings.LastIndex(path, "@"); at > 0 {
		path, version = path[:at], path[at+1:]
	}
	if unescaped, err := url.PathUnescape(path); err == nil {
		path = unescaped
	}
	if v, err := url.PathUnescape(version); err == nil {
		version = v
	}
	switch typ {
	case "npm", "golang", "composer":
		return path, version
	}
	return path[strings.LastIndex(path, "/")+1:], version
}
