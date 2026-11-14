package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Clair parses Clair container-image reports in either of their JSON shapes:
//
//   - Clair v4's VulnerabilityReport (`clairctl report --out json <image>`, or
//     GET /matcher/api/v1/vulnerability_report/<digest>): packages,
//     vulnerabilities and the package_vulnerabilities join between them;
//   - clair-scanner's report (`clair-scanner --report out.json`, Clair v2):
//     a flat list of {featurename, featureversion, vulnerability, …}.
//
// One finding per (package, advisory). The advisory id is the rule id; CVEs are
// lifted from the name and links too, because distro updaters key advisories by
// RHSA/DSA/USN and only mention the CVE in prose.
type Clair struct{}

// NewClair constructs a Clair parser.
func NewClair() Clair { return Clair{} }

// Scanner returns the tool identifier.
func (Clair) Scanner() string { return "clair" }

// PrimaryCategory is the scan-level category for Clair reports.
func (Clair) PrimaryCategory() domain.Category { return domain.CategoryContainer }

type clairV4Report struct {
	ManifestHash string `json:"manifest_hash"`
	Packages     map[string]struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Kind    string `json:"kind"`
		Source  *struct {
			Name string `json:"name"`
		} `json:"source"`
	} `json:"packages"`
	Vulnerabilities map[string]struct {
		ID                 string `json:"id"`
		Updater            string `json:"updater"`
		Name               string `json:"name"`
		Description        string `json:"description"`
		Links              string `json:"links"` // space-separated
		Severity           string `json:"severity"`
		NormalizedSeverity string `json:"normalized_severity"`
		FixedInVersion     string `json:"fixed_in_version"`
		Distribution       *struct {
			PrettyName string `json:"pretty_name"`
		} `json:"distribution"`
	} `json:"vulnerabilities"`
	PackageVulnerabilities map[string][]string `json:"package_vulnerabilities"`
	// Enrichments are keyed by media type and each enricher has its own shape,
	// so they're decoded lazily (see clairCVSS).
	Enrichments map[string]json.RawMessage `json:"enrichments"`
}

type clairScannerReport struct {
	Image           string `json:"image"`
	Vulnerabilities []struct {
		FeatureName    string `json:"featurename"`
		FeatureVersion string `json:"featureversion"`
		Vulnerability  string `json:"vulnerability"`
		Namespace      string `json:"namespace"`
		Description    string `json:"description"`
		Link           string `json:"link"`
		Severity       string `json:"severity"`
		FixedBy        string `json:"fixedby"`
	} `json:"vulnerabilities"`
}

// Parse implements Parser.
func (Clair) Parse(r io.Reader) ([]ParsedFinding, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read clair report: %w", err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return nil, fmt.Errorf("decode clair report: %w", err)
	}
	switch {
	case keys["package_vulnerabilities"] != nil || keys["manifest_hash"] != nil:
		var rep clairV4Report
		if err := json.Unmarshal(raw, &rep); err != nil {
			return nil, fmt.Errorf("decode clair v4 report: %w", err)
		}
		return clairV4Findings(rep), nil
	case keys["vulnerabilities"] != nil && keys["image"] != nil:
		var rep clairScannerReport
		if err := json.Unmarshal(raw, &rep); err != nil {
			return nil, fmt.Errorf("decode clair-scanner report: %w", err)
		}
		return clairScannerFindings(rep), nil
	}
	return nil, errors.New("decode clair report: neither a Clair v4 vulnerability report nor a clair-scanner report")
}

func clairV4Findings(rep clairV4Report) []ParsedFinding {
	cvss := clairCVSS(rep.Enrichments)

	var out []ParsedFinding
	for _, pkgID := range slices.Sorted(maps.Keys(rep.PackageVulnerabilities)) {
		pkg := rep.Packages[pkgID]
		// One advisory can be matched more than once for the same package (an
		// RHSA from both the BaseOS and AppStream repositories): one finding.
		seen := map[string]bool{}
		for _, vulnID := range rep.PackageVulnerabilities[pkgID] {
			v, ok := rep.Vulnerabilities[vulnID]
			if !ok || seen[v.Name] {
				continue
			}
			seen[v.Name] = true

			severity := normalizeSeverity(v.NormalizedSeverity)
			if strings.EqualFold(v.NormalizedSeverity, "unknown") || v.NormalizedSeverity == "" {
				severity = normalizeSeverity(firstNonEmpty(v.Severity, "unknown"))
			}
			cves := cvesInText(v.Name, v.Links)
			f := ParsedFinding{
				Category:       domain.CategoryContainer,
				RuleID:         clairAdvisoryID(v.Name, cves),
				Title:          fmt.Sprintf("%s in %s", v.Name, pkg.Name),
				Description:    v.Description,
				Severity:       severity,
				CVE:            cves,
				Package:        pkg.Name,
				PackageVersion: pkg.Version,
				FixedVersion:   v.FixedInVersion,
				Metadata: map[string]any{
					"updater":         v.Updater,
					"vendor_severity": v.Severity,
					"manifest":        rep.ManifestHash,
				},
			}
			if links := strings.Fields(v.Links); len(links) > 0 {
				f.URL = links[0]
			}
			if s, ok := cvss[vulnID]; ok {
				f.CVSS = floatPtr(s)
			}
			if pkg.Source != nil && pkg.Source.Name != "" && pkg.Source.Name != pkg.Name {
				f.Metadata["source_package"] = pkg.Source.Name
			}
			if v.Distribution != nil && v.Distribution.PrettyName != "" {
				f.Metadata["distribution"] = v.Distribution.PrettyName
			}
			out = append(out, f)
		}
	}
	return out
}

func clairScannerFindings(rep clairScannerReport) []ParsedFinding {
	out := make([]ParsedFinding, 0, len(rep.Vulnerabilities))
	for _, v := range rep.Vulnerabilities {
		// The id is usually the CVE; for RHSA-style ids the CVEs are only named
		// in the advisory text.
		cves := cvesFrom(v.Vulnerability)
		if len(cves) == 0 {
			cves = cvesInText(v.Description)
		}
		out = append(out, ParsedFinding{
			Category:       domain.CategoryContainer,
			RuleID:         v.Vulnerability,
			Title:          fmt.Sprintf("%s in %s", v.Vulnerability, v.FeatureName),
			Description:    v.Description,
			Severity:       clairSeverity(v.Severity),
			CVE:            cves,
			Package:        v.FeatureName,
			PackageVersion: v.FeatureVersion,
			FixedVersion:   v.FixedBy,
			URL:            v.Link,
			Metadata:       map[string]any{"image": rep.Image, "namespace": v.Namespace},
		})
	}
	return out
}

// clairSeverity maps Clair's scale, whose top level "Defcon1" sits above Critical.
func clairSeverity(s string) domain.Severity {
	if strings.EqualFold(s, "defcon1") {
		return domain.SeverityCritical
	}
	return normalizeSeverity(s)
}

// clairCVSS reads the CVSS enricher's payload — [{"<vuln id>": [{"baseScore": …}]}]
// under a "…enricher=clair.cvss…" media type — into vuln id → base score.
// Other enrichers, or a shape this doesn't know, are ignored rather than
// failing the whole report.
func clairCVSS(enrichments map[string]json.RawMessage) map[string]float64 {
	out := map[string]float64{}
	for kind, raw := range enrichments {
		if !strings.Contains(kind, "clair.cvss") {
			continue
		}
		var entries []map[string][]struct {
			BaseScore float64 `json:"baseScore"`
		}
		if json.Unmarshal(raw, &entries) != nil {
			continue
		}
		for _, byVuln := range entries {
			for id, scores := range byVuln {
				if len(scores) > 0 && scores[0].BaseScore > 0 {
					out[id] = scores[0].BaseScore
				}
			}
		}
	}
	return out
}

var clairAdvisoryRe = regexp.MustCompile(`^[A-Z][A-Z0-9]*-[A-Za-z0-9:._-]*\d[A-Za-z0-9:._-]*$`)

// clairAdvisoryID derives a stable rule id from a Clair v4 vulnerability name,
// which depends on the updater: a bare id ("CVE-2021-3711", "GHSA-…"), an
// advisory title led by its id ("RHSA-2023:5837: nghttp2 security update
// (Important)"), or — for Red Hat's unfixed CVEs — only a prose title ("curl:
// cookie injection with none file (low)") whose CVE is in the links.
func clairAdvisoryID(name string, cves []string) string {
	first, _, _ := strings.Cut(name, " ")
	if id := clairAdvisoryRe.FindString(strings.TrimSuffix(first, ":")); id != "" {
		return id
	}
	if len(cves) == 1 {
		return cves[0]
	}
	return name
}
