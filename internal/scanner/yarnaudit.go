package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// YarnAudit parses `yarn audit` output in all three shapes Yarn has emitted:
//
//   - Yarn 1 (`yarn audit --json`): newline-delimited JSON events; each
//     "auditAdvisory" event carries one npm advisory. An "error" event (the
//     registry was unreachable) makes the report unusable and is rejected.
//   - Yarn Berry 2/3 (`yarn npm audit --json`): one npm-audit-v6 style object
//     with an "advisories" map.
//   - Yarn Berry 4 (`yarn npm audit --json`): newline-delimited
//     {"value": <package>, "children": {...}} objects, including deprecation
//     notices.
//
// One finding per advisory × installed version, with the dependency paths kept
// in metadata. rule_id is the GHSA id when known, else "NPM-<advisory id>"; CVEs
// are lifted for dedup and enrichment, and the fixed version is the lowest
// patched release above the installed one.
type YarnAudit struct{}

// NewYarnAudit constructs a yarn audit parser.
func NewYarnAudit() YarnAudit { return YarnAudit{} }

// Scanner returns the tool identifier.
func (YarnAudit) Scanner() string { return "yarn-audit" }

// PrimaryCategory is the scan-level category for yarn audit reports.
func (YarnAudit) PrimaryCategory() domain.Category { return domain.CategorySCA }

// yarnAuditObject is any top-level object of the three formats.
type yarnAuditObject struct {
	Type       string                       `json:"type"`
	Data       json.RawMessage              `json:"data"`
	Advisories map[string]yarnAuditAdvisory `json:"advisories"`
	Value      string                       `json:"value"`
	Children   *yarnAuditBerryChild         `json:"children"`
}

type yarnAuditAdvisory struct {
	ID                 int             `json:"id"`
	Title              string          `json:"title"`
	ModuleName         string          `json:"module_name"`
	Severity           string          `json:"severity"`
	CVEs               []string        `json:"cves"`
	CWE                json.RawMessage `json:"cwe"`
	GitHubAdvisoryID   string          `json:"github_advisory_id"`
	VulnerableVersions string          `json:"vulnerable_versions"`
	PatchedVersions    string          `json:"patched_versions"`
	Overview           string          `json:"overview"`
	Recommendation     string          `json:"recommendation"`
	References         string          `json:"references"`
	URL                string          `json:"url"`
	CVSS               struct {
		Score        float64 `json:"score"`
		VectorString string  `json:"vectorString"`
	} `json:"cvss"`
	Findings []struct {
		Version string   `json:"version"`
		Paths   []string `json:"paths"`
	} `json:"findings"`
}

type yarnAuditBerryChild struct {
	ID                 json.RawMessage `json:"ID"`
	Issue              string          `json:"Issue"`
	URL                string          `json:"URL"`
	Severity           string          `json:"Severity"`
	VulnerableVersions string          `json:"Vulnerable Versions"`
	TreeVersions       []string        `json:"Tree Versions"`
	Dependents         []string        `json:"Dependents"`
}

var (
	yarnAuditGHSARe      = regexp.MustCompile(`GHSA(-[23456789cfghjmpqrvwx]{4}){3}`)
	yarnAuditPatchedRe   = regexp.MustCompile(`>=\s*v?(\d[^\s|<>=]*)`)
	yarnAuditUpperOnlyRe = regexp.MustCompile(`^<\s*v?(\d\S*)$`)
)

// Parse converts a yarn audit report into findings.
func (YarnAudit) Parse(r io.Reader) ([]ParsedFinding, error) {
	out := []ParsedFinding{}
	index := map[string]int{} // rule|package|version → position in out
	add := func(f ParsedFinding, paths []string) {
		k := f.RuleID + "|" + f.Package + "|" + f.PackageVersion
		if i, ok := index[k]; ok {
			// Yarn 1 repeats an advisory once per resolution path.
			prev, _ := out[i].Metadata["paths"].([]string)
			out[i].Metadata["paths"] = yarnAuditUnion(prev, paths)
			return
		}
		f.Metadata["paths"] = yarnAuditUnion(nil, paths)
		index[k] = len(out)
		out = append(out, f)
	}

	recognized := false
	err := decodeJSONLines(r, func(raw json.RawMessage) error {
		var obj yarnAuditObject
		if err := json.Unmarshal(raw, &obj); err != nil {
			return err
		}
		switch {
		case obj.Advisories != nil:
			recognized = true
			for _, a := range obj.Advisories {
				yarnAuditEmit(a, add)
			}
		case obj.Children != nil && obj.Value != "":
			recognized = true
			yarnAuditEmitBerry(obj.Value, *obj.Children, add)
		case obj.Type != "":
			recognized = true
			switch obj.Type {
			case "error":
				var msg string
				_ = json.Unmarshal(obj.Data, &msg)
				return fmt.Errorf("yarn audit failed: %s", msg)
			case "auditAdvisory":
				var data struct {
					Advisory *yarnAuditAdvisory `json:"advisory"`
				}
				if err := json.Unmarshal(obj.Data, &data); err != nil {
					return err
				}
				if data.Advisory == nil {
					return errors.New("auditAdvisory event without advisory")
				}
				yarnAuditEmit(*data.Advisory, add)
			}
		default:
			return errors.New("unrecognized object")
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("decode yarn audit report: %w", err)
	}
	if !recognized {
		return nil, errors.New("decode yarn audit report: empty input")
	}
	return out, nil
}

// yarnAuditEmit maps one npm advisory (Yarn 1 / Berry 2-3) to a finding per
// installed version.
func yarnAuditEmit(a yarnAuditAdvisory, add func(ParsedFinding, []string)) {
	ghsa := a.GitHubAdvisoryID
	if ghsa == "" {
		ghsa = yarnAuditGHSARe.FindString(a.URL)
	}
	rule := ghsa
	if rule == "" {
		rule = "NPM-" + strconv.Itoa(a.ID)
	}
	var patched []string
	for _, m := range yarnAuditPatchedRe.FindAllStringSubmatch(a.PatchedVersions, -1) {
		patched = append(patched, m[1])
	}
	cwes := yarnAuditCWEs(a.CWE)
	sev := normalizeSeverity(a.Severity)
	if a.Severity == "" && a.CVSS.Score > 0 {
		sev = severityFromCVSS(a.CVSS.Score)
	}
	for _, fnd := range a.Findings {
		f := ParsedFinding{
			Category:       domain.CategorySCA,
			RuleID:         rule,
			Title:          a.ModuleName + ": " + a.Title,
			Description:    a.Overview,
			Severity:       sev,
			CVE:            cvesFrom(a.CVEs...),
			Package:        a.ModuleName,
			PackageVersion: fnd.Version,
			FixedVersion:   nearestFix(fnd.Version, patched),
			Purl:           ecosystemPurl("npm", a.ModuleName, fnd.Version),
			URL:            a.URL,
			Metadata: map[string]any{
				"advisory_id":         a.ID,
				"vulnerable_versions": a.VulnerableVersions,
				"patched_versions":    a.PatchedVersions,
			},
		}
		if len(cwes) > 0 {
			f.CWE = cweFrom(cwes[0])
			f.Metadata["cwes"] = cwes
		}
		if a.CVSS.Score > 0 {
			f.CVSS = floatPtr(a.CVSS.Score)
		}
		if a.CVSS.VectorString != "" {
			f.Metadata["cvss_vector"] = a.CVSS.VectorString
		}
		if ghsa != "" {
			f.Metadata["ghsa"] = ghsa
		}
		if a.Recommendation != "" {
			f.Metadata["mitigation"] = a.Recommendation
		}
		if refs := strings.TrimSpace(a.References); refs != "" {
			f.Metadata["references"] = refs
		} else if a.URL != "" {
			f.Metadata["references"] = a.URL
		}
		add(f, fnd.Paths)
	}
}

// yarnAuditEmitBerry maps one Yarn Berry 4 entry to a finding per installed
// version. Berry 4 gives no patched range; a pure upper bound ("< 4.38.0")
// still names the first fixed release.
func yarnAuditEmitBerry(pkg string, c yarnAuditBerryChild, add func(ParsedFinding, []string)) {
	var id string
	if err := json.Unmarshal(c.ID, &id); err != nil {
		id = strings.TrimSpace(string(c.ID)) // numeric npm advisory id
	}
	ghsa := yarnAuditGHSARe.FindString(c.URL)
	rule := ghsa
	if rule == "" {
		if _, err := strconv.Atoi(id); err == nil {
			rule = "NPM-" + id
		} else {
			rule = id // "pkg (deprecation)"
		}
	}
	fixed := ""
	if m := yarnAuditUpperOnlyRe.FindStringSubmatch(strings.TrimSpace(c.VulnerableVersions)); m != nil {
		fixed = m[1]
	}
	for _, v := range c.TreeVersions {
		f := ParsedFinding{
			Category:       domain.CategorySCA,
			RuleID:         rule,
			Title:          pkg + ": " + c.Issue,
			Description:    c.Issue,
			Severity:       normalizeSeverity(c.Severity),
			CVE:            cvesInText(c.Issue),
			Package:        pkg,
			PackageVersion: v,
			FixedVersion:   fixed,
			Purl:           ecosystemPurl("npm", pkg, v),
			URL:            c.URL,
			Metadata: map[string]any{
				"advisory_id":         id,
				"vulnerable_versions": c.VulnerableVersions,
				"dependents":          c.Dependents,
			},
		}
		if ghsa != "" {
			f.Metadata["ghsa"] = ghsa
		}
		if c.URL != "" {
			f.Metadata["references"] = c.URL
		}
		add(f, nil)
	}
}

// yarnAuditCWEs accepts the advisory's cwe as either a string ("CWE-79", Yarn
// 1) or a list (Berry).
func yarnAuditCWEs(raw json.RawMessage) []string {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		if one == "" {
			return nil
		}
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(raw, &many)
	return many
}

func yarnAuditUnion(a, b []string) []string {
	out := append([]string{}, a...)
	for _, s := range b {
		dup := false
		for _, x := range out {
			if x == s {
				dup = true
				break
			}
		}
		if !dup {
			out = append(out, s)
		}
	}
	return out
}
