package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// JFrogXray parses JFrog Xray (v3+) "Unified" vulnerability reports in JSON:
// the export of a Vulnerabilities report (Xray UI → Reports → Export JSON, or
// `GET /xray/api/v1/reports/vulnerabilities/{id}`), shaped as
// `{"total_rows": N, "rows": [...]}`. Each row is one Xray issue on one
// vulnerable component inside an impacted artifact. The vulnerable component
// (e.g. `npm://jquery:3.4.1`) is the package the fix versions apply to, so it
// becomes Package/PackageVersion; the impacted artifact (the image or build
// that ships it) is kept in metadata.
type JFrogXray struct{}

// NewJFrogXray constructs a JFrog Xray Unified parser.
func NewJFrogXray() JFrogXray { return JFrogXray{} }

// Scanner returns the tool identifier.
func (JFrogXray) Scanner() string { return "jfrog-xray" }

// PrimaryCategory is the scan-level category for Xray vulnerability reports.
func (JFrogXray) PrimaryCategory() domain.Category { return domain.CategorySCA }

type jfrogXrayReport struct {
	Rows      *[]jfrogXrayRow `json:"rows"`
	TotalRows int             `json:"total_rows"`
}

type jfrogXrayRow struct {
	IssueID     string `json:"issue_id"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	CVEs        []struct {
		CVE          string  `json:"cve"`
		CVSSv3Score  float64 `json:"cvss_v3_score"`
		CVSSv3Vector string  `json:"cvss_v3_vector"`
		CVSSv2Vector string  `json:"cvss_v2_vector"`
		CVSSv2Score  float64 `json:"cvss_v2_score"`
	} `json:"cves"`
	CVSS3MaxScore            float64       `json:"cvss3_max_score"`
	CVSS2MaxScore            float64       `json:"cvss2_max_score"`
	VulnerableComponent      string        `json:"vulnerable_component"`
	ImpactedArtifact         string        `json:"impacted_artifact"`
	ImpactPath               []string      `json:"impact_path"`
	Path                     string        `json:"path"`
	FixedVersions            []string      `json:"fixed_versions"`
	PackageType              string        `json:"package_type"`
	Provider                 string        `json:"provider"`
	Published                string        `json:"published"`
	ArtifactScanTime         string        `json:"artifact_scan_time"`
	References               jfrogXrayRefs `json:"references"`
	ApplicabilityResult      string        `json:"applicability_result"`
	ComponentPhysicalPath    string        `json:"component_physical_path"`
	ExternalAdvisorySource   string        `json:"external_advisory_source"`
	ExternalAdvisorySeverity string        `json:"external_advisory_severity"`
}

// jfrogXrayRefs accepts a JSON string or an array of strings (Xray's
// "references" has been both).
type jfrogXrayRefs []string

func (f *jfrogXrayRefs) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		if one != "" {
			*f = []string{one}
		}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return nil //nolint:nilerr // an unexpected shape loses the references, not the finding
	}
	*f = many
	return nil
}

// Parse converts an Xray Unified vulnerabilities report into findings.
func (JFrogXray) Parse(r io.Reader) ([]ParsedFinding, error) {
	var rep jfrogXrayReport
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return nil, fmt.Errorf("decode jfrog xray report: %w", err)
	}
	if rep.Rows == nil {
		return nil, errors.New(`decode jfrog xray report: no "rows" array (expected an Xray Unified vulnerabilities report)`)
	}
	out := make([]ParsedFinding, 0, len(*rep.Rows))
	for _, row := range *rep.Rows {
		if row.IssueID == "" && len(row.CVEs) == 0 {
			return nil, errors.New("jfrog xray report: row without an issue id or CVE (not an Xray Unified report?)")
		}
		out = append(out, jfrogXrayFinding(row))
	}
	return mergeSameLocation(out), nil
}

func jfrogXrayFinding(row jfrogXrayRow) ParsedFinding {
	scheme, name, version := jfrogXrayComponent(row.VulnerableComponent)
	ecosystem := firstNonEmpty(row.PackageType, scheme)

	var ids []string
	var vector string
	var best float64
	for _, c := range row.CVEs {
		ids = append(ids, c.CVE)
		if c.CVSSv3Score > best {
			best, vector = c.CVSSv3Score, c.CVSSv3Vector
		}
	}
	if vector == "" && len(row.CVEs) > 0 {
		vector = firstNonEmpty(row.CVEs[0].CVSSv3Vector, row.CVEs[0].CVSSv2Vector)
	}
	cves := cvesFrom(ids...)

	fixes := make([]string, 0, len(row.FixedVersions))
	for _, v := range row.FixedVersions {
		if v = jfrogXrayFixVersion(v); v != "" {
			fixes = append(fixes, v)
		}
	}

	ident := row.IssueID
	if len(cves) > 0 {
		ident = cves[0]
	}
	title := ident
	if name != "" {
		title = fmt.Sprintf("%s in %s", ident, name)
	}

	meta := map[string]any{
		"impacted_artifact": row.ImpactedArtifact,
		"component":         row.VulnerableComponent,
	}
	if len(row.ImpactPath) > 0 {
		meta["impact_path"] = row.ImpactPath
	}
	if row.Path != "" {
		meta["path"] = row.Path
	}
	if row.PackageType != "" {
		meta["package_type"] = row.PackageType
	}
	if row.Provider != "" {
		meta["provider"] = row.Provider
	}
	if row.Published != "" {
		meta["published"] = row.Published
	}
	if vector != "" {
		meta["cvss_vector"] = vector
	}
	if len(fixes) > 0 {
		meta["mitigation"] = "Upgrade to a fixed version: " + strings.Join(row.FixedVersions, ", ")
	}
	if len(row.References) > 0 {
		meta["references"] = []string(row.References)
	}
	if row.ApplicabilityResult != "" {
		meta["applicability"] = row.ApplicabilityResult
	}
	if row.ExternalAdvisorySource != "" {
		meta["external_advisory"] = strings.TrimSpace(row.ExternalAdvisorySource + ": " + row.ExternalAdvisorySeverity)
	}

	sev := normalizeSeverity(row.Severity)
	if strings.TrimSpace(row.Severity) == "" || strings.EqualFold(row.Severity, "unknown") {
		if score := max(row.CVSS3MaxScore, best); score > 0 {
			sev = severityFromCVSS(score)
		}
	}

	f := ParsedFinding{
		Category:       domain.CategorySCA,
		RuleID:         firstNonEmpty(row.IssueID, ident),
		Title:          title,
		Description:    firstNonEmpty(row.Description, row.Summary),
		Severity:       sev,
		CVE:            cves,
		FilePath:       row.ImpactedArtifact,
		Package:        name,
		PackageVersion: version,
		FixedVersion:   nearestFix(version, fixes),
		Purl:           ecosystemPurl(jfrogXrayEcosystem(ecosystem), name, version),
		Metadata:       meta,
	}
	if score := max(row.CVSS3MaxScore, best); score > 0 {
		f.CVSS = new(score)
	}
	return f
}

// jfrogXrayComponent splits an Xray component id ("npm://lodash:4.17.15",
// "gav://org.foo:bar:1.0", "rpm://7:curl:16:7.29.0-54.el7",
// "deb://debian:buster:libc6:2.28-10", "alpine://3.12:busybox:1.31.1") into
// its type, package name and version. OS package ids carry the distro (and,
// for rpm, the epoch) around the name.
func jfrogXrayComponent(id string) (scheme, name, version string) {
	scheme, rest, ok := strings.Cut(id, "://")
	if !ok {
		return "", "", ""
	}
	parts := strings.Split(rest, ":")
	if len(parts) < 2 {
		return scheme, rest, ""
	}
	version = parts[len(parts)-1]
	switch {
	case scheme == "rpm" && len(parts) == 4:
		name = parts[1]
		if epoch := parts[2]; epoch != "" && epoch != "0" {
			version = epoch + ":" + version
		}
	case scheme == "deb" && len(parts) == 4:
		name = parts[2]
	case scheme == "alpine" && len(parts) == 3:
		name = parts[1]
	default:
		name = strings.Join(parts[:len(parts)-1], ":")
	}
	return scheme, name, version
}

// jfrogXrayFixVersion strips the range decoration Xray puts on fix versions
// ("≥ 1:11.0.5", "[2.11.3]", "(,3.5.0]") down to the version itself.
func jfrogXrayFixVersion(v string) string {
	v = strings.TrimSpace(strings.TrimLeft(strings.TrimSpace(v), "≥>=[( ,"))
	return strings.TrimSpace(strings.TrimRight(v, "]) "))
}

func jfrogXrayEcosystem(t string) string {
	switch strings.ToLower(t) {
	case "gav", "maven":
		return "maven"
	case "pip", "pypi":
		return "pypi"
	case "go", "golang":
		return "go"
	case "gem", "rubygems":
		return "rubygems"
	}
	return t
}
