package vulnmatch

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/enrichment"
	"github.com/xilasec/xila-api/internal/sbom"
)

// SourceNVD matches components that carry a CPE but no purl (C/C++ libraries,
// firmware, appliances, OS packages from scanners that only emit CPEs) against
// NVD's applicability statements. Opt-in via VULNMATCH_SOURCES: NVD answers
// one CPE per request, rate-limited (NVD_API_KEY raises the limit tenfold).
const SourceNVD = "nvd"

// CPESource resolves CPE names to the vulnerabilities affecting them. A
// MultiSource with the nvd source configured implements it; the matcher uses
// it for components that have a CPE and no purl.
type CPESource interface {
	QueryCPE(ctx context.Context, cpes []string) (map[string][]Vuln, error)
}

// cpeMatcher is the NVD client (enrichment.NVDClient in prod).
type cpeMatcher interface {
	MatchCPE(ctx context.Context, cpe string) ([]enrichment.CPEVuln, error)
}

// nvdCPETTL is how long one CPE's NVD answer is reused. A CPE costs a
// rate-limited request; the matcher runs every VULNMATCH_INTERVAL and on every
// SBOM upload, and NVD's analysis of a product changes far slower than that.
const nvdCPETTL = 12 * time.Hour

// NVDCPESource queries NVD per CPE, caching answers for nvdCPETTL.
type NVDCPESource struct {
	nvd cpeMatcher
	now func() time.Time

	mu    sync.Mutex
	cache map[string]cpeEntry
}

type cpeEntry struct {
	vulns []Vuln
	at    time.Time
}

// NewNVDCPESource wraps the NVD client.
func NewNVDCPESource(nvd cpeMatcher) *NVDCPESource {
	return &NVDCPESource{nvd: nvd, now: time.Now, cache: map[string]cpeEntry{}}
}

// QueryCPE returns the vulnerabilities per CPE (keyed by the CPE as given).
// CPEs that can't name one version (a wildcard or "-" version) are skipped:
// matching them would report every CVE the product ever had. On error, what
// was answered before it is returned with the error.
func (s *NVDCPESource) QueryCPE(ctx context.Context, cpes []string) (map[string][]Vuln, error) {
	out := make(map[string][]Vuln, len(cpes))
	for _, raw := range cpes {
		name, ok := NormalizeCPE(raw)
		if !ok {
			continue
		}
		s.mu.Lock()
		e, hit := s.cache[name]
		s.mu.Unlock()
		if hit && s.now().Sub(e.at) < nvdCPETTL {
			if len(e.vulns) > 0 {
				out[raw] = e.vulns
			}
			continue
		}
		matches, err := s.nvd.MatchCPE(ctx, name)
		if err != nil {
			return out, err
		}
		version := cpeVersion(name)
		vulns := make([]Vuln, 0, len(matches))
		for _, m := range matches {
			vulns = append(vulns, cpeVuln(m, version))
		}
		s.mu.Lock()
		s.cache[name] = cpeEntry{vulns: vulns, at: s.now()}
		s.mu.Unlock()
		if len(vulns) > 0 {
			out[raw] = vulns
		}
	}
	return out, nil
}

func cpeVuln(m enrichment.CPEVuln, version string) Vuln {
	summary := m.Description
	if i := strings.IndexAny(summary, ".\n"); i > 0 && i < 200 {
		summary = summary[:i]
	} else if len(summary) > 200 {
		summary = summary[:200] + "…"
	}
	return Vuln{
		ID:       m.CVE,
		Summary:  summary,
		Details:  m.Description,
		Severity: nvdSeverity(m.Severity, m.Score),
		CVSS:     m.Score,
		CVEs:     []string{m.CVE},
		Fixed:    cpeFixed(m.Ranges, version),
		URL:      "https://nvd.nist.gov/vuln/detail/" + m.CVE,
		Sources:  []string{SourceNVD},
	}
}

// cpeFixed is the end of the vulnerable range the installed version falls in,
// when that range ends with a first fixed version (versionEndExcluding). NVD
// lists one range per affected branch (log4j: …2.3.1, 2.4.0…2.12.2,
// 2.13.0…2.15.0), so "the" fix depends on which branch you're on.
func cpeFixed(ranges []enrichment.CPERange, version string) string {
	for _, r := range ranges {
		if r.EndExcluding == "" {
			continue
		}
		if r.StartIncluding != "" && sbom.CompareVersions(version, r.StartIncluding) < 0 {
			continue
		}
		if r.StartExcluding != "" && sbom.CompareVersions(version, r.StartExcluding) <= 0 {
			continue
		}
		if sbom.CompareVersions(version, r.EndExcluding) < 0 {
			return r.EndExcluding
		}
	}
	return ""
}

// cpeVersion is the version field of a CPE 2.3 name (NormalizeCPE output).
func cpeVersion(name string) string {
	f := splitCPE23(strings.TrimPrefix(name, "cpe:2.3:"))
	if len(f) < 4 {
		return ""
	}
	return strings.ReplaceAll(f[3], `\`, "")
}

// nvdSeverity maps NVD's baseSeverity, else derives it from the score (CVSS v3
// bands), else "" (the matcher's default applies).
func nvdSeverity(sev string, score *float64) domain.Severity {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return domain.SeverityCritical
	case "HIGH":
		return domain.SeverityHigh
	case "MEDIUM":
		return domain.SeverityMedium
	case "LOW":
		return domain.SeverityLow
	case "NONE":
		return domain.SeverityInfo
	}
	if score == nil {
		return ""
	}
	switch s := *score; {
	case s >= 9:
		return domain.SeverityCritical
	case s >= 7:
		return domain.SeverityHigh
	case s >= 4:
		return domain.SeverityMedium
	case s > 0:
		return domain.SeverityLow
	}
	return domain.SeverityInfo
}

// NormalizeCPE turns a CPE 2.3 formatted string or a CPE 2.2 URI into the CPE
// 2.3 name NVD's cpeName expects, and reports whether it names one concrete
// product version (part, vendor, product and version all set, no wildcard).
func NormalizeCPE(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	var f []string
	switch {
	case strings.HasPrefix(raw, "cpe:2.3:"):
		f = splitCPE23(strings.TrimPrefix(raw, "cpe:2.3:"))
	case strings.HasPrefix(raw, "cpe:/"):
		f = strings.Split(strings.TrimPrefix(raw, "cpe:/"), ":")
	default:
		return "", false
	}
	if len(f) < 4 {
		return "", false
	}
	for _, x := range f[:4] {
		if x == "" || x == "*" || x == "-" {
			return "", false
		}
	}
	if !strings.Contains("aho", f[0]) || len(f[0]) != 1 {
		return "", false
	}
	out := make([]string, 11)
	for i := range out {
		out[i] = "*"
		if i < len(f) && f[i] != "" {
			out[i] = f[i]
		}
	}
	return "cpe:2.3:" + strings.Join(out, ":"), true
}

// splitCPE23 splits on ':' except where escaped ("\:" is part of a value).
func splitCPE23(s string) []string {
	var out []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s):
			cur.WriteByte(s[i])
			cur.WriteByte(s[i+1])
			i++
		case s[i] == ':':
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(s[i])
		}
	}
	return append(out, cur.String())
}
