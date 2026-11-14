package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/xilasec/xila-api/internal/domain"
)

// Snyk parses `snyk test --json` (Snyk Open Source). With --all-projects the
// CLI emits a JSON array with one result object per manifest; a single project
// is a bare object. Both are accepted. Snyk lists an issue once per dependency
// path ("from"), so the same advisory on the same package is emitted once per
// manifest, with the paths kept in metadata. License-policy issues are mapped to
// the license category.
type Snyk struct{}

// NewSnyk constructs a Snyk parser.
func NewSnyk() Snyk { return Snyk{} }

// Scanner returns the tool identifier.
func (Snyk) Scanner() string { return "snyk" }

// PrimaryCategory is the scan-level category for Snyk Open Source reports.
func (Snyk) PrimaryCategory() domain.Category { return domain.CategorySCA }

type snykProject struct {
	Vulnerabilities   *[]snykVuln `json:"vulnerabilities"`
	PackageManager    string      `json:"packageManager"`
	ProjectName       string      `json:"projectName"`
	DisplayTargetFile string      `json:"displayTargetFile"`
	TargetFile        string      `json:"targetFile"`
	Path              string      `json:"path"`
	Error             string      `json:"error"`
}

type snykVuln struct {
	ID             string   `json:"id"`
	Type           string   `json:"type"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       string   `json:"severity"`
	CVSSScore      float64  `json:"cvssScore"`
	CVSSv3         string   `json:"CVSSv3"`
	PackageName    string   `json:"packageName"`
	Version        string   `json:"version"`
	PackageManager string   `json:"packageManager"`
	FixedIn        []string `json:"fixedIn"`
	From           []string `json:"from"`
	IsUpgradable   bool     `json:"isUpgradable"`
	IsPatchable    bool     `json:"isPatchable"`
	Exploit        string   `json:"exploit"`
	License        string   `json:"license"`
	Identifiers    struct {
		CVE  []string `json:"CVE"`
		CWE  []string `json:"CWE"`
		GHSA []string `json:"GHSA"`
	} `json:"identifiers"`
}

// Parse converts a Snyk Open Source JSON report into findings.
func (Snyk) Parse(r io.Reader) ([]ParsedFinding, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read snyk report: %w", err)
	}
	var projects []snykProject
	if data = bytes.TrimSpace(data); len(data) > 0 && data[0] == '[' {
		err = json.Unmarshal(data, &projects)
	} else {
		var p snykProject
		err = json.Unmarshal(data, &p)
		projects = []snykProject{p}
	}
	if err != nil {
		return nil, fmt.Errorf("decode snyk report: %w", err)
	}

	var out []ParsedFinding
	for _, p := range projects {
		if p.Vulnerabilities == nil {
			if p.Error != "" {
				return nil, fmt.Errorf("snyk report: %s", p.Error)
			}
			return nil, errors.New(`decode snyk report: no "vulnerabilities" array (expected snyk test --json output)`)
		}
		target := firstNonEmpty(p.DisplayTargetFile, p.TargetFile)
		byKey := map[string]int{}
		for _, v := range *p.Vulnerabilities {
			if v.ID == "" {
				return nil, errors.New("snyk report: issue without an id (not snyk test --json output?)")
			}
			path := joinPath(v.From)
			key := v.ID + "\x00" + v.PackageName + "\x00" + v.Version
			if i, ok := byKey[key]; ok {
				paths := out[i].Metadata["paths"].([]string)
				out[i].Metadata["paths"] = append(paths, path)
				continue
			}
			ecosystem := firstNonEmpty(v.PackageManager, p.PackageManager)
			f := ParsedFinding{
				Category:       domain.CategorySCA,
				RuleID:         v.ID,
				Title:          fmt.Sprintf("%s in %s", v.Title, v.PackageName),
				Description:    v.Description,
				Severity:       normalizeSeverity(v.Severity),
				CWE:            cweFirst(v.Identifiers.CWE...),
				CVE:            cvesFrom(v.Identifiers.CVE...),
				FilePath:       target,
				Package:        v.PackageName,
				PackageVersion: v.Version,
				Purl:           ecosystemPurl(ecosystem, v.PackageName, v.Version),
				URL:            snykURL(v.ID),
				Metadata: map[string]any{
					"paths":       []string{path},
					"upgradable":  v.IsUpgradable,
					"patchable":   v.IsPatchable,
					"ecosystem":   ecosystem,
					"project":     p.ProjectName,
					"cvss_vector": v.CVSSv3,
				},
			}
			if v.Type == "license" {
				f.Category = domain.CategoryLicense
				f.URL = ""
				f.Metadata["license"] = v.License
			}
			f.FixedVersion = nearestFix(v.Version, v.FixedIn)
			if v.CVSSScore > 0 {
				f.CVSS = floatPtr(v.CVSSScore)
			}
			if v.Exploit != "" && v.Exploit != "Not Defined" {
				f.Metadata["exploit_maturity"] = v.Exploit
			}
			if len(v.Identifiers.GHSA) > 0 {
				f.Metadata["ghsa"] = v.Identifiers.GHSA
			}
			byKey[key] = len(out)
			out = append(out, f)
		}
	}
	if out == nil {
		out = []ParsedFinding{}
	}
	return mergeSameLocation(out), nil
}

func snykURL(id string) string {
	if id == "" {
		return ""
	}
	return "https://security.snyk.io/vuln/" + id
}

// joinPath renders a dependency path the way Snyk prints it.
func joinPath(from []string) string {
	var b bytes.Buffer
	for i, p := range from {
		if i > 0 {
			b.WriteString(" > ")
		}
		b.WriteString(p)
	}
	return b.String()
}
