package enrichment

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/netguard"
	"github.com/xilasec/xila-api/internal/secretref"
)

// DefaultNVDURL is the NVD CVE API 2.0
// (https://nvd.nist.gov/developers/vulnerabilities).
const DefaultNVDURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

const (
	// nvdBatch is the most CVE ids one `cveIds` request may carry (NVD's limit).
	nvdBatch = 100
	// NVD's published rate limits: a rolling 30-second window of 5 requests
	// without an API key, 50 with one.
	nvdWindow        = 30 * time.Second
	nvdRequestsNoKey = 5
	nvdRequestsKey   = 50
	// nvdRefresh is how long a cached NVD answer stays fresh. NVD rescoring is
	// rare; CVEs NVD hasn't analyzed yet (no metrics) are retried sooner.
	nvdRefresh        = 7 * 24 * time.Hour
	nvdRefreshPending = 24 * time.Hour
	// nvdMaxPerRun bounds one run's lookups (100 requests: ~10 minutes without
	// a key); the rest are picked up by the next run.
	nvdMaxPerRun = 10_000
)

// CVSS is one CVE's preferred CVSS metric from NVD (as cached by the finding
// repository).
type CVSS = finding.CVSSRecord

// rateLimiter allows at most n events per rolling window (NVD's model).
type rateLimiter struct {
	mu     sync.Mutex
	n      int
	window time.Duration
	sent   []time.Time
	now    func() time.Time
	sleep  func(context.Context, time.Duration) error
}

func newRateLimiter(n int, window time.Duration) *rateLimiter {
	return &rateLimiter{n: n, window: window, now: time.Now, sleep: sleepCtx}
}

// wait blocks until another request fits in the window, then records it.
func (l *rateLimiter) wait(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for {
		now := l.now()
		for len(l.sent) > 0 && now.Sub(l.sent[0]) >= l.window {
			l.sent = l.sent[1:]
		}
		if len(l.sent) < l.n {
			l.sent = append(l.sent, now)
			return nil
		}
		if err := l.sleep(ctx, l.sent[0].Add(l.window).Sub(now)); err != nil {
			return err
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// NVDClient fetches CVSS data from the NVD CVE API 2.0, batching up to 100 CVE
// ids per request (`cveIds`) and staying inside NVD's rate limit.
type NVDClient struct {
	base  string
	key   secretref.Value
	hc    *http.Client
	limit *rateLimiter
}

// NewNVDClient constructs the client. apiKey (optional) raises the rate limit
// from 5 to 50 requests per 30 seconds; it is read per request, so a rotated
// key applies at once (the rate limit is chosen by whether a key is set at
// startup).
func NewNVDClient(baseURL string, apiKey secretref.Value) *NVDClient {
	if baseURL == "" {
		baseURL = DefaultNVDURL
	}
	n := nvdRequestsNoKey
	if apiKey.Get() != "" {
		n = nvdRequestsKey
	}
	return &NVDClient{
		base: strings.TrimRight(baseURL, "/"), key: apiKey,
		hc:    netguard.NewClient(60 * time.Second),
		limit: newRateLimiter(n, nvdWindow),
	}
}

// nvdResponse is the subset of the CVE API response we consume.
type nvdResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string        `json:"id"`
			LastModified string        `json:"lastModified"`
			VulnStatus   string        `json:"vulnStatus"`
			Metrics      nvdMetricSets `json:"metrics"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Configurations []struct {
				Nodes []struct {
					CPEMatch []nvdCPEMatch `json:"cpeMatch"`
				} `json:"nodes"`
			} `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// nvdCPEMatch is one applicability criterion: a CPE pattern plus a version range.
type nvdCPEMatch struct {
	Vulnerable            bool   `json:"vulnerable"`
	Criteria              string `json:"criteria"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

type nvdMetricSets struct {
	V40 []nvdMetric `json:"cvssMetricV40"`
	V31 []nvdMetric `json:"cvssMetricV31"`
	V30 []nvdMetric `json:"cvssMetricV30"`
}

type nvdMetric struct {
	Source   string `json:"source"`
	Type     string `json:"type"` // Primary (NVD) | Secondary (CNA)
	CVSSData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"` // v3.x / v4.0
	} `json:"cvssData"`
}

// preferred picks the metric findings carry: CVSS v3.1, then v3.0, then v4.0 —
// v3 is what scanners report and severity thresholds are calibrated on, and v4
// scores aren't comparable to it — and within a version NVD's own (Primary)
// assessment over a CNA's (Secondary).
func (m nvdMetricSets) preferred() (nvdMetric, bool) {
	for _, set := range [][]nvdMetric{m.V31, m.V30, m.V40} {
		for _, x := range set {
			if strings.EqualFold(x.Type, "Primary") && x.CVSSData.VectorString != "" {
				return x, true
			}
		}
		for _, x := range set {
			if x.CVSSData.VectorString != "" {
				return x, true
			}
		}
	}
	return nvdMetric{}, false
}

// Fetch returns CVSS data for every CVE NVD knows among cves (unknown ids —
// reserved, not yet received — are simply absent).
func (c *NVDClient) Fetch(ctx context.Context, cves []string) (map[string]CVSS, error) {
	out := make(map[string]CVSS, len(cves))
	for start := 0; start < len(cves); start += nvdBatch {
		batch := cves[start:min(start+nvdBatch, len(cves))]
		for index := 0; ; {
			q := url.Values{}
			q.Set("cveIds", strings.Join(batch, ","))
			resp, err := c.page(ctx, q.Encode(), index)
			if err != nil {
				return out, err
			}
			for _, v := range resp.Vulnerabilities {
				rec := CVSS{CVE: v.CVE.ID}
				if t, err := time.Parse("2006-01-02T15:04:05.000", v.CVE.LastModified); err == nil {
					rec.LastModified = &t
				}
				if m, ok := v.CVE.Metrics.preferred(); ok {
					rec.Score = new(m.CVSSData.BaseScore)
					rec.Vector = m.CVSSData.VectorString
					rec.Version = m.CVSSData.Version
				}
				out[rec.CVE] = rec
			}
			index += len(resp.Vulnerabilities)
			if len(resp.Vulnerabilities) == 0 || index >= resp.TotalResults {
				break
			}
		}
	}
	return out, nil
}

// page performs one rate-limited request, retrying when NVD throttles (it
// answers 403 or 503 when the window is exceeded).
// query is URL-encoded; NVD's flag parameters (isVulnerable, noRejected) take
// no value, which url.Values can't express.
func (c *NVDClient) page(ctx context.Context, query string, startIndex int) (nvdResponse, error) {
	if startIndex > 0 {
		query += "&startIndex=" + strconv.Itoa(startIndex)
	}
	u := c.base + "?" + query
	for attempt := 0; ; attempt++ {
		if err := c.limit.wait(ctx); err != nil {
			return nvdResponse{}, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nvdResponse{}, err
		}
		if key := c.key.Get(); key != "" {
			req.Header.Set("apiKey", key)
		}
		res, err := c.hc.Do(req)
		if err != nil {
			return nvdResponse{}, fmt.Errorf("nvd: %w", err)
		}
		if res.StatusCode == http.StatusOK {
			var out nvdResponse
			err := json.NewDecoder(res.Body).Decode(&out)
			res.Body.Close()
			if err != nil {
				return nvdResponse{}, fmt.Errorf("nvd: decode: %w", err)
			}
			return out, nil
		}
		msg, _ := io.ReadAll(io.LimitReader(res.Body, 256))
		res.Body.Close()
		throttled := res.StatusCode == http.StatusForbidden || res.StatusCode == http.StatusTooManyRequests ||
			res.StatusCode == http.StatusServiceUnavailable
		if !throttled || attempt >= 2 {
			return nvdResponse{}, fmt.Errorf("nvd: %s: %s %s", res.Status, res.Header.Get("message"), msg)
		}
		// Throttled anyway (another client shares the key/IP): sit out a window.
		if err := c.limit.sleep(ctx, nvdWindow); err != nil {
			return nvdResponse{}, err
		}
	}
}

// CPEVuln is one CVE NVD lists as affecting a CPE.
type CPEVuln struct {
	CVE         string
	Description string
	Score       *float64
	Severity    string // NVD's baseSeverity (CRITICAL…NONE), "" when unscored
	// Ranges are the vulnerable version ranges NVD lists for the queried
	// product (same part:vendor:product), for working out a "fixed in".
	Ranges []CPERange
}

// CPERange is one vulnerable version range from an applicability criterion.
// Empty bounds are open.
type CPERange struct {
	StartIncluding, StartExcluding string
	EndIncluding, EndExcluding     string
}

// MatchCPE returns the CVEs NVD's applicability statements mark as affecting
// cpe (a full CPE 2.3 name with a concrete version). Rejected CVEs are skipped.
// Paged and rate-limited like Fetch; one CPE is at least one request.
func (c *NVDClient) MatchCPE(ctx context.Context, cpe string) ([]CPEVuln, error) {
	vendorProduct := cpeVendorProduct(cpe)
	var out []CPEVuln
	for index := 0; ; {
		q := url.Values{}
		q.Set("cpeName", cpe)
		resp, err := c.page(ctx, q.Encode()+"&isVulnerable&noRejected", index)
		if err != nil {
			return out, err
		}
		for _, v := range resp.Vulnerabilities {
			cve := v.CVE
			if strings.EqualFold(cve.VulnStatus, "Rejected") {
				continue
			}
			rec := CPEVuln{CVE: cve.ID}
			for _, d := range cve.Descriptions {
				if d.Lang == "en" {
					rec.Description = d.Value
					break
				}
			}
			if m, ok := cve.Metrics.preferred(); ok {
				rec.Score = new(m.CVSSData.BaseScore)
				rec.Severity = m.CVSSData.BaseSeverity
			}
			for _, cfg := range cve.Configurations {
				for _, n := range cfg.Nodes {
					for _, m := range n.CPEMatch {
						if m.Vulnerable && cpeVendorProduct(m.Criteria) == vendorProduct &&
							m.VersionStartIncluding+m.VersionStartExcluding+m.VersionEndIncluding+m.VersionEndExcluding != "" {
							rec.Ranges = append(rec.Ranges, CPERange{
								StartIncluding: m.VersionStartIncluding, StartExcluding: m.VersionStartExcluding,
								EndIncluding: m.VersionEndIncluding, EndExcluding: m.VersionEndExcluding,
							})
						}
					}
				}
			}
			out = append(out, rec)
		}
		index += len(resp.Vulnerabilities)
		if len(resp.Vulnerabilities) == 0 || index >= resp.TotalResults {
			return out, nil
		}
	}
}

// cpeVendorProduct is "part:vendor:product" of a CPE 2.3 name, lowercased.
func cpeVendorProduct(cpe string) string {
	f := strings.Split(cpe, ":")
	if len(f) < 5 {
		return ""
	}
	return strings.ToLower(f[2] + ":" + f[3] + ":" + f[4])
}

// NVDSource fetches CVSS data for CVE ids (NVDClient in prod; a fake in tests).
type NVDSource interface {
	Fetch(ctx context.Context, cves []string) (map[string]CVSS, error)
}

// nvdStore is the CVSS cache + the findings it stamps (finding.Repository).
type nvdStore interface {
	// StaleNVDCVEs lists CVE ids on findings whose cached NVD data is missing
	// or older than the refresh windows, at most limit.
	StaleNVDCVEs(ctx context.Context, refresh, refreshPending time.Duration, limit int) ([]string, error)
	// SaveNVD caches what NVD answered; asked-but-unknown ids are cached empty
	// so they aren't re-asked every run.
	SaveNVD(ctx context.Context, asked []string, found []CVSS) error
	// ApplyNVD stamps cached CVSS onto findings (scanID nil = all). Returns how
	// many findings changed.
	ApplyNVD(ctx context.Context, scanID *string) (int, error)
}

// NVD enriches findings with CVSS vectors and base scores from NVD. Precedence:
// a CVSS score the scanner reported always wins (it describes the reported
// package); NVD's score fills `cvss` only when the scanner gave none
// (cvss_source = "nvd"). The NVD vector + version are stored either way.
type NVD struct {
	store  nvdStore
	source NVDSource
}

// NewNVD constructs the NVD enricher.
func NewNVD(store nvdStore, source NVDSource) *NVD {
	return &NVD{store: store, source: source}
}

// Refresh fetches CVSS for every CVE whose cached data is missing or stale,
// then stamps findings. Returns how many findings changed. Partial progress is
// kept: what was fetched before an error is cached and applied.
func (n *NVD) Refresh(ctx context.Context) (int, error) {
	cves, err := n.store.StaleNVDCVEs(ctx, nvdRefresh, nvdRefreshPending, nvdMaxPerRun)
	if err != nil {
		return 0, err
	}
	var fetchErr error
	if len(cves) > 0 {
		found, err := n.source.Fetch(ctx, cves)
		fetchErr = err
		asked := cves
		if err != nil {
			asked = nil // only what came back is known to be NVD's answer
		}
		recs := make([]CVSS, 0, len(found))
		for _, r := range found {
			recs = append(recs, r)
		}
		if err := n.store.SaveNVD(context.WithoutCancel(ctx), asked, recs); err != nil {
			return 0, err
		}
		slog.InfoContext(ctx, "nvd: fetched CVSS", "asked", len(cves), "found", len(found))
	}
	changed, err := n.store.ApplyNVD(ctx, nil)
	if err != nil {
		return 0, err
	}
	if fetchErr != nil {
		return changed, fmt.Errorf("nvd fetch: %w", fetchErr)
	}
	return changed, nil
}

// Name implements scan.Applier.
func (n *NVD) Name() string { return "nvd-cvss" }

// ApplyToScan stamps cached NVD CVSS onto a scan's findings right at ingest, so
// a new finding for a known CVE carries its vector immediately (no network).
func (n *NVD) ApplyToScan(ctx context.Context, _ string, scanID string) (int, error) {
	return n.store.ApplyNVD(ctx, &scanID)
}
