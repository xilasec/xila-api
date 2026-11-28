package vulnmatch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/netguard"
	"github.com/xilasec/xila-api/internal/secretref"
)

// DefaultVulnerableCodeURL is AboutCode's public VulnerableCode instance.
const DefaultVulnerableCodeURL = "https://public.vulnerablecode.io"

// vcBatchSize is how many purls go into one bulk_search call.
const vcBatchSize = 100

// VulnerableCodeSource asks a VulnerableCode instance
// (https://github.com/aboutcode-org/vulnerablecode — public or self-hosted)
// which advisories affect each purl, through its bulk purl search
// (POST /api/packages/bulk_search). Purls are looked up without qualifiers or
// subpath ("plain" purls), which is how VulnerableCode keys its packages.
//
// VulnerableCode names advisories VCID-…; its aliases carry the GHSA / CVE /
// ecosystem ids. The advisory's id here is its best alias (GHSA, then an
// ecosystem id, then the CVE), the VCID kept as an alias — so the finding's
// identity (and fingerprint) is the same whether OSV, GitHub or VulnerableCode
// reported it, and a run where only some of them answered never renames it.
type VulnerableCodeSource struct {
	base   string
	apiKey secretref.Value
	hc     *http.Client
}

// NewVulnerableCodeSource constructs the client. An empty baseURL uses the
// public instance; apiKey is optional (sent as "Authorization: Token …").
func NewVulnerableCodeSource(baseURL string, apiKey secretref.Value) *VulnerableCodeSource {
	if baseURL == "" {
		baseURL = DefaultVulnerableCodeURL
	}
	return &VulnerableCodeSource{base: strings.TrimRight(baseURL, "/"), apiKey: apiKey,
		hc: netguard.NewClient(60 * time.Second)}
}

// vcPackage is the subset of VulnerableCode's PackageSerializer we consume.
type vcPackage struct {
	Type       string    `json:"type"`
	Namespace  string    `json:"namespace"`
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	AffectedBy []vcVulnz `json:"affected_by_vulnerabilities"`
}

type vcVulnz struct {
	VulnerabilityID string   `json:"vulnerability_id"`
	Summary         string   `json:"summary"`
	Aliases         []string `json:"aliases"`
	References      []struct {
		Scores []struct {
			Value         string `json:"value"`
			ScoringSystem string `json:"scoring_system"`
		} `json:"scores"`
	} `json:"references"`
	FixedPackages []struct {
		Purl string `json:"purl"`
	} `json:"fixed_packages"`
}

// plainKey is a purl without qualifiers and subpath, normalized for lookup.
func plainKey(p purl) string {
	k := p.Type + "/"
	if p.Namespace != "" {
		k += p.Namespace + "/"
	}
	return strings.ToLower(k + p.Name + "@" + p.Version)
}

// Query maps each purl to the advisories VulnerableCode says affect it.
func (s *VulnerableCodeSource) Query(ctx context.Context, purls []string) (map[string][]Vuln, error) {
	out := map[string][]Vuln{}
	// plain key → the purls (as given) it stands for.
	byKey := map[string][]string{}
	var plain []string
	for _, raw := range purls {
		p, ok := parsePurl(raw)
		if !ok || p.Version == "" {
			continue
		}
		k := plainKey(p)
		if _, seen := byKey[k]; !seen {
			plain = append(plain, plainPurl(p))
		}
		byKey[k] = append(byKey[k], raw)
	}
	for start := 0; start < len(plain); start += vcBatchSize {
		end := min(start+vcBatchSize, len(plain))
		pkgs, err := s.bulkSearch(ctx, plain[start:end])
		if err != nil {
			return nil, err
		}
		for _, pkg := range pkgs {
			p := purl{Type: strings.ToLower(pkg.Type), Namespace: pkg.Namespace, Name: pkg.Name, Version: pkg.Version}
			targets := byKey[plainKey(p)]
			if len(targets) == 0 || len(pkg.AffectedBy) == 0 {
				continue
			}
			for _, v := range pkg.AffectedBy {
				vuln := s.vuln(v, p)
				for _, t := range targets {
					out[t] = append(out[t], vuln)
				}
			}
		}
	}
	return out, nil
}

// plainPurl renders a purl without qualifiers/subpath (escaping each segment).
func plainPurl(p purl) string {
	segs := []string{}
	if p.Namespace != "" {
		for n := range strings.SplitSeq(p.Namespace, "/") {
			segs = append(segs, url.PathEscape(n))
		}
	}
	segs = append(segs, url.PathEscape(p.Name))
	return "pkg:" + p.Type + "/" + strings.Join(segs, "/") + "@" + url.PathEscape(p.Version)
}

// vuln converts one VulnerableCode advisory as it applies to package p.
func (s *VulnerableCodeSource) vuln(v vcVulnz, p purl) Vuln {
	ids := append([]string{v.VulnerabilityID}, v.Aliases...)
	id := v.VulnerabilityID
	best := 99
	for _, a := range v.Aliases {
		if r := vcIDRank(a); r < best {
			id, best = a, r
		}
	}
	out := Vuln{ID: id, Summary: firstLine(v.Summary), Details: v.Summary,
		URL: s.base + "/vulnerabilities/" + url.PathEscape(v.VulnerabilityID)}
	for _, a := range ids {
		if a != id && !slices.Contains(out.Aliases, a) {
			out.Aliases = append(out.Aliases, a)
		}
		if strings.HasPrefix(a, "CVE-") && !slices.Contains(out.CVEs, a) {
			out.CVEs = append(out.CVEs, a)
		}
	}
	// The highest CVSS v3/v4 score any reference states; else a textual one.
	textual := ""
	for _, ref := range v.References {
		for _, sc := range ref.Scores {
			sys := strings.ToLower(sc.ScoringSystem)
			switch {
			case strings.HasPrefix(sys, "cvssv3") || strings.HasPrefix(sys, "cvssv4"):
				if f, err := strconv.ParseFloat(sc.Value, 64); err == nil && f >= 0 && f <= 10 && (out.CVSS == nil || f > *out.CVSS) {
					out.CVSS = &f
				}
			case sys == "generic_textual" && textual == "":
				textual = sc.Value
			}
		}
	}
	out.Severity = severityFrom(textual)
	if out.CVSS != nil {
		out.Severity = nvdSeverity("", out.CVSS)
	}
	// fixed_packages lists the fixes above the installed version: the nearest.
	cmpV := comparatorFor("ECOSYSTEM", ecosystemOf(p))
	for _, fp := range v.FixedPackages {
		f, ok := parsePurl(fp.Purl)
		if !ok || f.Version == "" {
			continue
		}
		if out.Fixed == "" || cmpV(f.Version, out.Fixed) < 0 {
			out.Fixed = f.Version
		}
	}
	return out
}

// vcIDRank prefers the id other sources use for the same advisory (see
// idRank): GHSA, then ecosystem ids, then CVE.
func vcIDRank(id string) int {
	switch {
	case strings.HasPrefix(id, "GHSA-"):
		return 0
	case strings.HasPrefix(id, "CVE-"):
		return 2
	default:
		return 1
	}
}

func (s *VulnerableCodeSource) bulkSearch(ctx context.Context, purls []string) ([]vcPackage, error) {
	body, err := json.Marshal(map[string]any{"purls": purls, "purl_only": false, "plain_purl": true})
	if err != nil {
		return nil, fmt.Errorf("vulnerablecode: encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.base+"/api/packages/bulk_search", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if key := s.apiKey.Get(); key != "" {
		req.Header.Set("Authorization", "Token "+key)
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vulnerablecode: bulk_search: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("vulnerablecode: bulk_search returned %d: %s", resp.StatusCode, b)
	}
	var out []vcPackage
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("vulnerablecode: decode: %w", err)
	}
	return out, nil
}
