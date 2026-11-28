package scanner

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Anchore parses Anchore Enterprise image vulnerability reports:
// `anchorectl image vulnerabilities <image> -o json` (a JSON array) and the
// API / legacy `anchore-cli --json image vuln <image> all` shape (an object with
// a "vulnerabilities" array). This is distinct from Grype's JSON: Anchore's
// records are flat ({vuln, package, packageVersion, fix, nvdData, …}).
//
// The vulnerability id is the rule id; "None" placeholders are treated as empty.
type Anchore struct{}

// NewAnchore constructs an Anchore parser.
func NewAnchore() Anchore { return Anchore{} }

// Scanner returns the tool identifier.
func (Anchore) Scanner() string { return "anchore" }

// PrimaryCategory is the scan-level category for Anchore reports.
func (Anchore) PrimaryCategory() domain.Category { return domain.CategoryContainer }

type anchoreVuln struct {
	Vuln           string `json:"vuln"`
	Severity       string `json:"severity"`
	Package        string `json:"package"`
	PackageName    string `json:"packageName"`
	PackageVersion string `json:"packageVersion"`
	PackageType    string `json:"packageType"`
	PackagePath    string `json:"packagePath"`
	PackageCPE     string `json:"packageCpe"`
	Fix            string `json:"fix"`
	URL            string `json:"url"`
	Feed           string `json:"feed"`
	FeedGroup      string `json:"feedGroup"`
	NVDData        []struct {
		ID     string `json:"id"`
		CVSSV3 struct {
			BaseScore float64 `json:"base_score"`
		} `json:"cvss_v3"`
		CVSSV2 struct {
			BaseScore float64 `json:"base_score"`
		} `json:"cvss_v2"`
	} `json:"nvdData"`
}

// Parse implements Parser.
func (Anchore) Parse(r io.Reader) ([]ParsedFinding, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read anchore report: %w", err)
	}
	var vulns []anchoreVuln
	var image string
	if trimmed := bytes.TrimSpace(raw); len(trimmed) > 0 && trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &vulns); err != nil {
			return nil, fmt.Errorf("decode anchore report: %w", err)
		}
	} else {
		var rep struct {
			ImageDigest     string         `json:"imageDigest"`
			Vulnerabilities *[]anchoreVuln `json:"vulnerabilities"`
		}
		if err := json.Unmarshal(trimmed, &rep); err != nil {
			return nil, fmt.Errorf("decode anchore report: %w", err)
		}
		if rep.Vulnerabilities == nil {
			return nil, errors.New("decode anchore report: no vulnerabilities array — not an Anchore vulnerability report")
		}
		vulns, image = *rep.Vulnerabilities, rep.ImageDigest
	}

	out := make([]ParsedFinding, 0, len(vulns))
	for _, v := range vulns {
		if v.Vuln == "" {
			return nil, errors.New("decode anchore report: record without a vuln id — not an Anchore vulnerability report")
		}
		name := firstNonEmpty(anchoreValue(v.PackageName), anchoreValue(v.Package))
		ids := []string{v.Vuln}
		for _, n := range v.NVDData {
			ids = append(ids, n.ID)
		}
		f := ParsedFinding{
			Category:       domain.CategoryContainer,
			RuleID:         v.Vuln,
			Title:          fmt.Sprintf("%s in %s", v.Vuln, name),
			Severity:       normalizeSeverity(v.Severity), // Negligible → low, Unknown → info
			CVE:            cvesInText(ids...),            // deduplicated: nvdData repeats the primary id
			Package:        name,
			PackageVersion: anchoreValue(v.PackageVersion),
			FixedVersion:   anchoreValue(v.Fix),
			FilePath:       anchoreValue(v.PackagePath),
			URL:            anchoreValue(v.URL),
			Metadata: map[string]any{
				"package_type": v.PackageType,
				"feed_group":   v.FeedGroup,
			},
		}
		if image != "" {
			f.Metadata["image_digest"] = image
		}
		if cpe := anchoreValue(v.PackageCPE); cpe != "" {
			f.Metadata["cpe"] = cpe
		}
		for _, n := range v.NVDData { // -1 marks an absent score
			s := n.CVSSV3.BaseScore
			if s <= 0 {
				s = n.CVSSV2.BaseScore
			}
			if s > 0 {
				f.CVSS = new(s)
				break
			}
		}
		out = append(out, f)
	}
	return out, nil
}

// anchoreValue drops the "None" Anchore writes for absent values.
func anchoreValue(s string) string {
	if strings.EqualFold(s, "none") || s == "N/A" {
		return ""
	}
	return s
}
