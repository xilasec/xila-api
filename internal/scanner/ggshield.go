package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// GGShield parses GitGuardian ggshield's JSON (`ggshield secret scan … --json`):
// a commit-range/pre-receive scan nests incidents under "scans" (one per
// commit), a path/docker scan lists them at the top level — both are read. A
// secret present across many commits is one incident (keyed by its ignore_sha)
// per file, reported once with the commits it appears in. Severity follows
// GitGuardian's validity check: a secret confirmed valid is critical, anything
// else (invalid, no checker, check failed) is high — it still has to be rotated.
type GGShield struct{}

// NewGGShield constructs a GGShield parser.
func NewGGShield() GGShield { return GGShield{} }

// Scanner returns the tool identifier.
func (GGShield) Scanner() string { return "ggshield" }

// PrimaryCategory is the scan-level category for ggshield reports.
func (GGShield) PrimaryCategory() domain.Category { return domain.CategorySecret }

type ggEntity struct {
	Filename  string `json:"filename"`
	Mode      string `json:"mode"`
	Incidents []struct {
		Policy      string `json:"policy"`
		Type        string `json:"type"`
		Validity    string `json:"validity"`
		IgnoreSHA   string `json:"ignore_sha"`
		IncidentURL string `json:"incident_url"`
		KnownSecret bool   `json:"known_secret"`
		Occurrences []struct {
			Match     string `json:"match"`
			Type      string `json:"type"`
			LineStart *int   `json:"line_start"`
		} `json:"occurrences"`
	} `json:"incidents"`
}

type ggScan struct {
	ID                   string     `json:"id"`
	Type                 string     `json:"type"`
	EntitiesWithIncident []ggEntity `json:"entities_with_incidents"`
	ExtraInfo            struct {
		Author string `json:"author"`
		Email  string `json:"email"`
		Date   string `json:"date"`
	} `json:"extra_info"`
}

type ggReport struct {
	ggScan
	Scans          []ggScan `json:"scans"`
	TotalIncidents *int     `json:"total_incidents"`
}

// Parse converts a ggshield JSON report into findings.
func (GGShield) Parse(r io.Reader) ([]ParsedFinding, error) {
	var report ggReport
	if err := json.NewDecoder(r).Decode(&report); err != nil {
		return nil, fmt.Errorf("decode ggshield report: %w", err)
	}
	if report.TotalIncidents == nil {
		return nil, errors.New(`decode ggshield report: no "total_incidents" (expected ggshield --json output)`)
	}

	out := []ParsedFinding{}
	index := map[string]int{}
	for _, sc := range append([]ggScan{report.ggScan}, report.Scans...) {
		commit := ""
		if sc.Type == "commit" {
			commit = sc.ID
		}
		for _, ent := range sc.EntitiesWithIncident {
			for _, inc := range ent.Incidents {
				key := inc.IgnoreSHA + "\x00" + ent.Filename
				var line *int
				var occTypes []string
				for _, o := range inc.Occurrences {
					if line == nil && o.LineStart != nil && *o.LineStart > 0 {
						line = o.LineStart
					}
					occTypes = append(occTypes, o.Type)
				}
				if i, ok := index[key]; ok {
					f := &out[i]
					if f.Line == nil {
						f.Line = line
					}
					if commit != "" {
						f.Metadata["commits"] = append(f.Metadata["commits"].([]string), commit)
					}
					continue
				}
				f := ParsedFinding{
					Category:    domain.CategorySecret,
					RuleID:      secretRuleID(inc.Type),
					Title:       fmt.Sprintf("%s in %s", inc.Type, ent.Filename),
					Description: fmt.Sprintf("GitGuardian detected a %s (%s). Rotate the credential and remove it from the repository history.", inc.Type, inc.Policy),
					Severity:    domain.SeverityHigh,
					FilePath:    ent.Filename,
					Line:        line,
					URL:         inc.IncidentURL,
					Metadata: map[string]any{
						"validity":     inc.Validity,
						"ignore_sha":   inc.IgnoreSHA,
						"policy":       inc.Policy,
						"match_types":  occTypes,
						"commits":      []string{},
						"known_secret": inc.KnownSecret,
					},
				}
				if commit != "" {
					f.Metadata["commits"] = []string{commit}
					f.Metadata["author"] = sc.ExtraInfo.Author
				}
				if strings.EqualFold(inc.Validity, "valid") {
					f.Severity = domain.SeverityCritical
				}
				index[key] = len(out)
				out = append(out, f)
			}
		}
	}
	return mergeSameLocation(out), nil
}
