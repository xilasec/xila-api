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

// Mend parses Mend (formerly WhiteSource) SCA vulnerability exports in their
// three JSON shapes, sniffed from the top-level key:
//
//   - {"response": […]} — the Mend platform API 3.0 finding list
//     (`GET /api/v3.0/projects/{uuid}/dependencies/findings/security`);
//   - {"vulnerabilities": […]} — the legacy (API 1.x / Unified Agent)
//     project vulnerability report, one entry per vulnerability with its library;
//   - {"libraries": […]} — the Mend CLI (`mend dep --export-results`) library
//     list with nested vulnerabilities.
//
// One finding per vulnerability per library: the rule id is the Mend id
// (CVE-… or WS-…), the package is the library (group:artifact for Maven, with
// a PURL where the ecosystem is unambiguous) and the fixed version is read from
// Mend's top fix ("Upgrade to version 1.7", "group:artifact:2.13.4",
// "Name - 4.7.2,5.0.3") when it upgrades this same library — a fix that swaps
// in another artifact is kept as mitigation text only. Severity is Mend's (CVSS
// v3 rating preferred), else the score. In API 3.0 exports only ACTIVE findings
// are reported (LIBRARY_REMOVED is history); IGNORED ones are carried as risk
// accepted.
type Mend struct{}

// NewMend constructs a Mend parser.
func NewMend() Mend { return Mend{} }

// Scanner returns the tool identifier.
func (Mend) Scanner() string { return "mend" }

// PrimaryCategory is the scan-level category for Mend reports.
func (Mend) PrimaryCategory() domain.Category { return domain.CategorySCA }

type mendReport struct {
	Response        *[]mendAPI3Finding `json:"response"`
	Vulnerabilities *[]mendLegacyVuln  `json:"vulnerabilities"`
	Libraries       *[]struct {
		mendLibrary
		Vulnerabilities []mendLegacyVuln `json:"vulnerabilities"`
	} `json:"libraries"`
}

type mendLibrary struct {
	Name       string `json:"name"`
	Filename   string `json:"filename"`
	GroupID    string `json:"groupId"`
	ArtifactID string `json:"artifactId"`
	Version    string `json:"version"`
	Type       string `json:"type"`
}

type mendTopFix struct {
	FixResolution string `json:"fixResolution"`
	URL           string `json:"url"`
	Message       string `json:"message"`
}

type mendLegacyVuln struct {
	Name          string       `json:"name"`
	Type          string       `json:"type"`
	Severity      string       `json:"severity"`
	Score         flexFloat    `json:"score"`
	CVSS3Severity string       `json:"cvss3_severity"`
	CVSS3Score    flexFloat    `json:"cvss3_score"`
	Vector        string       `json:"scoreMetadataVector"`
	Description   string       `json:"description"`
	URL           string       `json:"url"`
	Project       string       `json:"project"`
	Product       string       `json:"product"`
	Library       *mendLibrary `json:"library"`
	TopFix        *mendTopFix  `json:"topFix"`
	Locations     []struct {
		Path string `json:"path"`
	} `json:"locations"`
}

type mendAPI3Finding struct {
	Name      string `json:"name"`
	Component struct {
		Name           string `json:"name"`
		LibraryType    string `json:"libraryType"`
		GroupID        string `json:"groupId"`
		ArtifactID     string `json:"artifactId"`
		Version        string `json:"version"`
		DependencyType string `json:"dependencyType"`
	} `json:"component"`
	FindingInfo struct {
		Status string `json:"status"`
	} `json:"findingInfo"`
	Project struct {
		Name string `json:"name"`
		Path string `json:"path"`
	} `json:"project"`
	Vulnerability struct {
		Name        string    `json:"name"`
		Type        string    `json:"type"`
		Description string    `json:"description"`
		Score       flexFloat `json:"score"`
		Severity    string    `json:"severity"`
	} `json:"vulnerability"`
	TopFix           *mendTopFix `json:"topFix"`
	Exploitable      bool        `json:"exploitable"`
	Vector           string      `json:"scoreMetadataVector"`
	ThreatAssessment struct {
		ExploitCodeMaturity string    `json:"exploitCodeMaturity"`
		EPSSPercentage      flexFloat `json:"epssPercentage"`
	} `json:"threatAssessment"`
}

// Parse implements Parser.
func (Mend) Parse(r io.Reader) ([]ParsedFinding, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read mend report: %w", err)
	}
	if data = bytes.TrimSpace(data); len(data) == 0 || data[0] != '{' {
		return nil, errors.New("decode mend report: expected a JSON object")
	}
	var rep mendReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, fmt.Errorf("decode mend report: %w", err)
	}

	out := []ParsedFinding{}
	switch {
	case rep.Response != nil:
		for _, f := range *rep.Response {
			if pf, ok := mendAPI3(f); ok {
				out = append(out, pf)
			}
		}
	case rep.Vulnerabilities != nil:
		for _, v := range *rep.Vulnerabilities {
			lib := mendLibrary{}
			if v.Library != nil {
				lib = *v.Library
			}
			out = append(out, mendLegacy(v, lib))
		}
	case rep.Libraries != nil:
		for _, l := range *rep.Libraries {
			for _, v := range l.Vulnerabilities {
				lib := l.mendLibrary
				if v.Library != nil {
					lib = *v.Library
				}
				out = append(out, mendLegacy(v, lib))
			}
		}
	default:
		return nil, errors.New(`decode mend report: no "response", "vulnerabilities" or "libraries" array — not a Mend SCA report`)
	}
	return mergeSameLocation(out), nil
}

func mendLegacy(v mendLegacyVuln, lib mendLibrary) ParsedFinding {
	pkg, purl := mendPackage(lib.Type, lib.GroupID, lib.ArtifactID, firstNonEmpty(lib.Filename, lib.Name), lib.Version)
	sev := firstNonEmpty(v.CVSS3Severity, v.Severity)
	cvss := v.CVSS3Score.ptr()
	if cvss == nil {
		cvss = v.Score.ptr()
	}
	meta := map[string]any{"project": v.Project, "product": v.Product, "library_file": lib.Filename}
	f := mendFinding(v.Name, v.Description, sev, cvss, v.Vector, v.URL, pkg, purl, lib.Version, meta)
	if len(v.Locations) > 0 {
		f.FilePath = v.Locations[0].Path
	}
	mendApplyFix(&f, v.TopFix, lib.GroupID, lib.ArtifactID, lib.Name, lib.Filename)
	return f
}

func mendAPI3(m mendAPI3Finding) (ParsedFinding, bool) {
	c := m.Component
	meta := map[string]any{
		"project":         m.Project.Name,
		"project_path":    m.Project.Path,
		"library_file":    c.Name,
		"dependency_type": c.DependencyType,
		"status":          m.FindingInfo.Status,
		"exploitable":     m.Exploitable,
	}
	switch m.FindingInfo.Status {
	case "ACTIVE", "":
	case "IGNORED":
		setImportedStatus(meta, domain.FindingRiskAccepted, "Mend: finding ignored", zeroTime)
	default: // LIBRARY_REMOVED and other closed states
		return ParsedFinding{}, false
	}
	if e := m.ThreatAssessment.EPSSPercentage.ptr(); e != nil {
		meta["epss_percentage"] = *e
	}
	if em := m.ThreatAssessment.ExploitCodeMaturity; em != "" && em != "NOT_DEFINED" {
		meta["exploit_maturity"] = em
	}
	pkg, purl := mendPackage(c.LibraryType, c.GroupID, c.ArtifactID, c.Name, c.Version)
	v := m.Vulnerability
	f := mendFinding(firstNonEmpty(v.Name, m.Name), v.Description, v.Severity, v.Score.ptr(), m.Vector, "", pkg, purl, c.Version, meta)
	mendApplyFix(&f, m.TopFix, c.GroupID, c.ArtifactID, c.Name)
	return f, true
}

func mendFinding(id, desc, sev string, cvss *float64, vector, url, pkg, purl, version string, meta map[string]any) ParsedFinding {
	f := ParsedFinding{
		Category:       domain.CategorySCA,
		RuleID:         id,
		Title:          strings.TrimSpace(fmt.Sprintf("%s in %s %s", id, pkg, version)),
		Description:    desc,
		CVE:            cvesFrom(id),
		Package:        pkg,
		PackageVersion: version,
		Purl:           purl,
		Metadata:       meta,
	}
	if cvss != nil && *cvss > 0 {
		f.CVSS = cvss
	}
	switch {
	case sev != "":
		f.Severity = normalizeSeverity(sev)
	case f.CVSS != nil:
		f.Severity = severityFromCVSS(*f.CVSS)
	default:
		f.Severity = domain.SeverityMedium
	}
	if vector != "" {
		meta["cvss_vector"] = vector
	}
	if url != "" {
		meta["references"] = url
	}
	return f
}

// mendPackage names a library: group:artifact (and a PURL) for Maven, the
// package name for npm/PyPI/NuGet, and otherwise the file name without its
// version and extension ("axis-1.4.jar" → "axis").
func mendPackage(libType, group, artifact, file, version string) (string, string) {
	t := strings.ToUpper(libType)
	switch {
	case t == "MAVEN_ARTIFACT" && group != "" && artifact != "":
		name := group + ":" + artifact
		return name, ecosystemPurl("maven", name, version)
	case strings.Contains(t, "NODE") && artifact != "":
		return artifact, ecosystemPurl("npm", artifact, version)
	case strings.Contains(t, "PYTHON") && artifact != "":
		return artifact, ecosystemPurl("pypi", artifact, version)
	case strings.Contains(t, "NUGET") && artifact != "":
		return artifact, ecosystemPurl("nuget", artifact, version)
	}
	if base := mendBaseName(file, version); base != "" {
		return base, ""
	}
	return firstNonEmpty(artifact, file), ""
}

// mendBaseName strips the extension and "-<version>" from a library file name.
func mendBaseName(file, version string) string {
	name := file
	for _, ext := range []string{".jar", ".dll", ".war", ".ear", ".zip", ".tgz", ".tar.gz", ".whl", ".gem", ".nupkg"} {
		if strings.HasSuffix(strings.ToLower(name), ext) {
			name = name[:len(name)-len(ext)]
			break
		}
	}
	if version != "" {
		name = strings.TrimSuffix(name, "-"+version)
	}
	return name
}

// mendApplyFix reads the fixed version from Mend's top fix. The resolution names
// the artifact to upgrade to; when that's a different artifact (axis → axis2)
// the fix is not a version of this package and stays text in metadata.
func mendApplyFix(f *ParsedFinding, fix *mendTopFix, names ...string) {
	if fix == nil {
		return
	}
	res := strings.TrimSpace(fix.FixResolution)
	if res == "" || strings.EqualFold(res, "no_fix") {
		return
	}
	f.Metadata["mitigation"] = strings.TrimSpace(fix.Message + ": " + res)
	if fix.URL != "" {
		f.Metadata["fix_url"] = fix.URL
	}
	if len(res) >= len("upgrade to version") && strings.EqualFold(res[:len("upgrade to version")], "upgrade to version") {
		res = strings.TrimSpace(res[len("upgrade to version"):])
	}
	artifact, versions := "", res
	if left, right, ok := strings.Cut(res, " - "); ok {
		artifact, versions = strings.TrimSpace(left), strings.TrimSpace(right)
	} else if i := strings.LastIndex(res, ":"); i >= 0 {
		artifact, versions = res[:i], res[i+1:]
	}
	if i := strings.LastIndex(artifact, ":"); i >= 0 {
		artifact = artifact[i+1:]
	}
	known := []string{f.Package}
	for _, n := range names {
		known = append(known, n, mendBaseName(n, f.PackageVersion))
	}
	if artifact != "" && !mendNameIn(artifact, known) {
		return
	}
	var list []string
	for v := range strings.SplitSeq(versions, ",") {
		v = strings.TrimSpace(v)
		for _, n := range known {
			if n != "" && len(v) > len(n)+1 && strings.EqualFold(v[:len(n)+1], n+"-") {
				v = v[len(n)+1:]
				break
			}
		}
		list = append(list, v)
	}
	f.FixedVersion = nearestFix(f.PackageVersion, list)
}

func mendNameIn(name string, known []string) bool {
	for _, k := range known {
		if k == "" {
			continue
		}
		if strings.EqualFold(name, k) {
			return true
		}
		if i := strings.LastIndex(k, ":"); i >= 0 && strings.EqualFold(name, k[i+1:]) {
			return true
		}
	}
	return false
}
