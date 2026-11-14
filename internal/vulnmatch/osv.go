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
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/netguard"
)

// DefaultOSVURL is the public OSV.dev API (free, no key).
const DefaultOSVURL = "https://api.osv.dev"

// batchSize is how many PURLs go in one /v1/querybatch call.
const batchSize = 500

// OSVSource resolves PURLs to vulnerabilities using OSV.dev. It is an outbound
// HTTP call — no extra service to run — exactly like the EPSS/KEV feeds.
type OSVSource struct {
	base string
	hc   *http.Client
}

// NewOSVSource constructs the OSV client. An empty baseURL uses OSV.dev.
func NewOSVSource(baseURL string) *OSVSource {
	if baseURL == "" {
		baseURL = DefaultOSVURL
	}
	return &OSVSource{
		base: strings.TrimRight(baseURL, "/"),
		hc:   netguard.NewClient(30 * time.Second),
	}
}

// Query maps each PURL to the vulnerabilities affecting it. It batch-detects
// which packages are affected, then fetches each distinct advisory once (the same
// CVE typically hits many components), so the call count stays small.
func (o *OSVSource) Query(ctx context.Context, purls []string) (map[string][]Vuln, error) {
	out := map[string][]Vuln{}
	cache := map[string]osvRecord{} // advisory details, fetched once per id

	for start := 0; start < len(purls); start += batchSize {
		end := min(start+batchSize, len(purls))
		hits, err := o.queryBatch(ctx, purls[start:end])
		if err != nil {
			return nil, err
		}
		for p, ids := range hits {
			for _, id := range ids {
				rec, ok := cache[id]
				if !ok {
					if err := o.get(ctx, "/v1/vulns/"+url.PathEscape(id), &rec); err != nil {
						return nil, err
					}
					cache[id] = rec
				}
				out[p] = append(out[p], rec.vulnFor(p))
			}
		}
	}
	return out, nil
}

// queryBatch asks OSV which of these PURLs are affected, returning vuln ids.
func (o *OSVSource) queryBatch(ctx context.Context, purls []string) (map[string][]string, error) {
	type pkg struct {
		Purl string `json:"purl"`
	}
	type query struct {
		Package pkg `json:"package"`
	}
	qs := make([]query, len(purls))
	for i, p := range purls {
		qs[i] = query{Package: pkg{Purl: p}}
	}
	body, err := json.Marshal(map[string]any{"queries": qs})
	if err != nil {
		return nil, fmt.Errorf("osv: encode batch: %w", err)
	}

	var resp struct {
		Results []struct {
			Vulns []struct {
				ID string `json:"id"`
			} `json:"vulns"`
		} `json:"results"`
	}
	if err := o.post(ctx, "/v1/querybatch", body, &resp); err != nil {
		return nil, err
	}

	// Results are positionally aligned with the queries we sent.
	hits := map[string][]string{}
	for i, r := range resp.Results {
		if i >= len(purls) || len(r.Vulns) == 0 {
			continue
		}
		ids := make([]string, 0, len(r.Vulns))
		for _, v := range r.Vulns {
			ids = append(ids, v.ID)
		}
		hits[purls[i]] = ids
	}
	return hits, nil
}

// osvRecord is the subset of an OSV advisory (https://ossf.github.io/osv-schema/)
// we consume — from the API, the ecosystem exports, or a private import.
type osvRecord struct {
	ID        string     `json:"id"`
	Modified  time.Time  `json:"modified"`
	Published *time.Time `json:"published"`
	Withdrawn *time.Time `json:"withdrawn"`
	Aliases   []string   `json:"aliases"`
	Summary   string     `json:"summary"`
	Details   string     `json:"details"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []Affected `json:"affected"`
	// database_specific is free-form per database; only GHSA-style
	// {"severity": "HIGH"} is read, leniently.
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

// qualitativeSeverity is database_specific.severity when it's a string.
func (r osvRecord) qualitativeSeverity() string {
	var ds struct {
		Severity any `json:"severity"`
	}
	if len(r.DatabaseSpecific) == 0 || json.Unmarshal(r.DatabaseSpecific, &ds) != nil {
		return ""
	}
	s, _ := ds.Severity.(string)
	return s
}

// cvssVector is the record's CVSS v3 (else v4) vector, if any.
func (r osvRecord) cvssVector() string {
	best := ""
	for _, s := range r.Severity {
		switch s.Type {
		case "CVSS_V3":
			return s.Score
		case "CVSS_V4":
			best = s.Score
		}
	}
	return best
}

// base normalizes the advisory-level fields into our model.
func (r osvRecord) base() Vuln {
	v := Vuln{
		ID:       r.ID,
		Aliases:  r.Aliases,
		Summary:  r.Summary,
		Details:  r.Details,
		Severity: severityFrom(r.qualitativeSeverity()),
	}
	// CVE ids come through as aliases (OSV ids are often GHSA-…).
	if strings.HasPrefix(r.ID, "CVE-") {
		v.CVEs = append(v.CVEs, r.ID)
	}
	for _, a := range r.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			v.CVEs = append(v.CVEs, a)
		}
	}
	return v
}

// vulnFor is the advisory as it applies to one purl OSV said it affects: the
// "fixed in" comes from the affected entry and range that cover this version,
// not merely the record's first fix (log4shell has four release lines).
func (r osvRecord) vulnFor(purlStr string) Vuln {
	v := r.base()
	if p, ok := parsePurl(purlStr); ok {
		if hit, fixed := r.evaluate(p); hit {
			v.Fixed = fixed
			return v
		}
	}
	// The package didn't line up with our naming; fall back to the first fix.
	for _, aff := range r.Affected {
		for _, rng := range aff.Ranges {
			for _, e := range rng.Events {
				if e.Fixed != "" && v.Fixed == "" && !strings.EqualFold(rng.Type, "GIT") {
					v.Fixed = e.Fixed
				}
			}
		}
	}
	return v
}

// evaluate runs the OSV evaluation algorithm for purl p over every affected
// entry naming its package.
func (r osvRecord) evaluate(p purl) (bool, string) {
	keys := componentKeys(p)
	hit, fixed := false, ""
	for _, aff := range r.Affected {
		k := aff.key()
		if k == "" || !slices.Contains(keys, k) {
			continue
		}
		ok, f := aff.affects(p.Version)
		if !ok {
			continue
		}
		hit = true
		if f != "" && (fixed == "" || comparatorFor("ECOSYSTEM", aff.ecosystem())(f, fixed) < 0) {
			fixed = f
		}
	}
	return hit, fixed
}

// severityFrom maps a qualitative severity ("" when absent or unknown — the
// finding then defaults to medium, and NVD CVSS / EPSS / KEV drive priority).
func severityFrom(s string) domain.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return domain.SeverityCritical
	case "HIGH":
		return domain.SeverityHigh
	case "MODERATE", "MEDIUM":
		return domain.SeverityMedium
	case "LOW":
		return domain.SeverityLow
	default:
		return ""
	}
}

func (o *OSVSource) post(ctx context.Context, path string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return o.do(req, out)
}

func (o *OSVSource) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.base+path, nil)
	if err != nil {
		return err
	}
	return o.do(req, out)
}

func (o *OSVSource) do(req *http.Request, out any) error {
	resp, err := o.hc.Do(req)
	if err != nil {
		return fmt.Errorf("osv: %s: %w", req.URL.Path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("osv: %s returned %d: %s", req.URL.Path, resp.StatusCode, b)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("osv: decode %s: %w", req.URL.Path, err)
	}
	return nil
}
