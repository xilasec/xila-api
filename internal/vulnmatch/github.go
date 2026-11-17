package vulnmatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xilasec/xila-api/internal/netguard"
	"github.com/xilasec/xila-api/internal/secretref"
)

// DefaultGitHubURL is GitHub's REST API.
const DefaultGitHubURL = "https://api.github.com"

// ghEcosystems maps purl types to the GitHub Advisory Database ecosystems the
// REST API filters on ("ecosystem" parameter of GET /advisories).
var ghEcosystems = map[string]string{
	"npm":           "npm",
	"pypi":          "pip",
	"maven":         "maven",
	"golang":        "go",
	"gem":           "rubygems",
	"nuget":         "nuget",
	"composer":      "composer",
	"cargo":         "rust",
	"hex":           "erlang",
	"pub":           "pub",
	"swift":         "swift",
	"githubactions": "actions",
}

const (
	// ghAffectsMaxPackages / ghAffectsMaxChars bound one request's `affects`
	// list: the API takes up to 1000 packages, but the URL must stay within
	// what proxies and GitHub's front end accept.
	ghAffectsMaxPackages = 100
	ghAffectsMaxChars    = 4000
	ghPerPage            = 100
	// ghCacheTTL is how long one purl's answer is reused: long enough that the
	// upload-triggered match and the next scheduled sweep don't re-ask, short
	// enough that a new advisory shows up the same day.
	ghCacheTTL = 30 * time.Minute
	// ghMaxWait caps how long a run waits out a rate-limit reset before it
	// gives up on GitHub (the other sources' results still apply).
	ghMaxWait = 5 * time.Minute
)

// GitHubSource resolves purls against the GitHub Advisory Database through the
// REST API's global security advisories endpoint
// (https://docs.github.com/en/rest/security-advisories/global-advisories):
// GET /advisories?ecosystem=<eco>&affects=<name>@<version>,…, paginated with
// Link headers. A token (optional) lifts the anonymous 60 requests/hour.
type GitHubSource struct {
	base  string
	token secretref.Value
	hc    *http.Client
	now   func() time.Time
	sleep func(context.Context, time.Duration) error

	mu       sync.Mutex
	cache    map[string]ghCached
	resumeAt time.Time // rate-limit window reopens
}

type ghCached struct {
	vulns []Vuln
	at    time.Time
}

// NewGitHubSource constructs the client. An empty baseURL uses api.github.com
// (set it for GitHub Enterprise Server: https://<host>/api/v3).
func NewGitHubSource(baseURL string, token secretref.Value) *GitHubSource {
	if baseURL == "" {
		baseURL = DefaultGitHubURL
	}
	return &GitHubSource{
		base:  strings.TrimRight(baseURL, "/"),
		token: token,
		hc:    netguard.NewClient(30 * time.Second),
		now:   time.Now,
		sleep: sleepCtx,
		cache: map[string]ghCached{},
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

// ghItem is one purl to look up.
type ghItem struct {
	raw  string
	p    purl
	key  string // packageKey of its name, to match advisory packages
	name string // the name GitHub knows it by
}

// Query looks every purl up, batched per ecosystem.
func (g *GitHubSource) Query(ctx context.Context, purls []string) (map[string][]Vuln, error) {
	out := map[string][]Vuln{}
	byEco := map[string][]ghItem{}
	now := g.now()
	g.mu.Lock()
	for k, c := range g.cache {
		if now.Sub(c.at) > ghCacheTTL {
			delete(g.cache, k)
		}
	}
	for _, raw := range purls {
		if c, ok := g.cache[raw]; ok {
			if len(c.vulns) > 0 {
				out[raw] = slices.Clone(c.vulns)
			}
			continue
		}
		p, ok := parsePurl(raw)
		if !ok || p.Version == "" {
			continue
		}
		eco, ok := ghEcosystems[p.Type]
		if !ok {
			continue
		}
		osvEco, name, ok := p.osvPackage()
		if !ok {
			continue
		}
		byEco[eco] = append(byEco[eco], ghItem{raw: raw, p: p, key: packageKey(osvEco, name), name: name})
	}
	g.mu.Unlock()

	ecos := make([]string, 0, len(byEco))
	for eco := range byEco {
		ecos = append(ecos, eco)
	}
	slices.Sort(ecos)
	for _, eco := range ecos {
		for _, chunk := range ghChunks(byEco[eco]) {
			advisories, err := g.list(ctx, eco, chunk)
			if err != nil {
				return nil, err
			}
			found := matchGitHub(advisories, eco, chunk)
			g.mu.Lock()
			for _, it := range chunk {
				vs := found[it.raw]
				g.cache[it.raw] = ghCached{vulns: vs, at: now} // clean answers are cached too
				if len(vs) > 0 {
					out[it.raw] = slices.Clone(vs)
				}
			}
			g.mu.Unlock()
		}
	}
	return out, nil
}

// ghChunks splits one ecosystem's purls into request-sized `affects` lists.
func ghChunks(items []ghItem) [][]ghItem {
	var chunks [][]ghItem
	var cur []ghItem
	size := 0
	for _, it := range items {
		n := len(url.QueryEscape(it.name+"@"+it.p.Version)) + 3
		if len(cur) > 0 && (len(cur) >= ghAffectsMaxPackages || size+n > ghAffectsMaxChars) {
			chunks = append(chunks, cur)
			cur, size = nil, 0
		}
		cur = append(cur, it)
		size += n
	}
	if len(cur) > 0 {
		chunks = append(chunks, cur)
	}
	return chunks
}

// ghAdvisory is the subset of a global security advisory we consume.
type ghAdvisory struct {
	GHSAID      string `json:"ghsa_id"`
	CVEID       string `json:"cve_id"`
	HTMLURL     string `json:"html_url"`
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Identifiers []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifiers"`
	WithdrawnAt     *time.Time `json:"withdrawn_at"`
	Vulnerabilities []struct {
		Package *struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		VulnerableVersionRange string          `json:"vulnerable_version_range"`
		FirstPatchedVersion    json.RawMessage `json:"first_patched_version"`
	} `json:"vulnerabilities"`
	CVSSSeverities *struct {
		CVSSV3 *ghCVSS `json:"cvss_v3"`
		CVSSV4 *ghCVSS `json:"cvss_v4"`
	} `json:"cvss_severities"`
	CVSS *ghCVSS `json:"cvss"` // deprecated in favor of cvss_severities
}

type ghCVSS struct {
	VectorString *string  `json:"vector_string"`
	Score        *float64 `json:"score"`
}

func (c *ghCVSS) score() *float64 {
	if c == nil || c.Score == nil || *c.Score <= 0 {
		return nil
	}
	return c.Score
}

// cvssScore prefers v3 (what scanners and policies speak), then v4, then the
// deprecated single `cvss` field.
func (a ghAdvisory) cvssScore() *float64 {
	if a.CVSSSeverities != nil {
		if s := a.CVSSSeverities.CVSSV3.score(); s != nil {
			return s
		}
		if s := a.CVSSSeverities.CVSSV4.score(); s != nil {
			return s
		}
	}
	return a.CVSS.score()
}

// firstPatched reads first_patched_version: a string in the global advisories
// API, an {"identifier": …} object in older payloads.
func firstPatched(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var o struct {
		Identifier string `json:"identifier"`
	}
	if json.Unmarshal(raw, &o) == nil {
		return o.Identifier
	}
	return ""
}

// matchGitHub attributes each advisory to the purls of this chunk whose package
// it names and whose version falls in its vulnerable range. The API filtered
// by "affects any of", so an advisory naming two of our packages may cover
// only one of the versions we hold — the range decides.
func matchGitHub(advisories []ghAdvisory, eco string, chunk []ghItem) map[string][]Vuln {
	out := map[string][]Vuln{}
	for _, a := range advisories {
		if a.WithdrawnAt != nil {
			continue
		}
		for _, entry := range a.Vulnerabilities {
			if entry.Package == nil || !strings.EqualFold(entry.Package.Ecosystem, eco) {
				continue
			}
			for _, it := range chunk {
				osvEco := ecosystemOf(it.p)
				if packageKey(osvEco, entry.Package.Name) != it.key {
					continue
				}
				if !inGitHubRange(entry.VulnerableVersionRange, it.p.Version, comparatorFor("ECOSYSTEM", osvEco)) {
					continue
				}
				if slices.ContainsFunc(out[it.raw], func(v Vuln) bool { return v.ID == a.GHSAID }) {
					continue // one advisory listing the package twice
				}
				out[it.raw] = append(out[it.raw], a.toVuln(firstPatched(entry.FirstPatchedVersion)))
			}
		}
	}
	return out
}

func (a ghAdvisory) toVuln(fixed string) Vuln {
	v := Vuln{
		ID:       a.GHSAID,
		Summary:  a.Summary,
		Details:  a.Description,
		Severity: severityFrom(a.Severity),
		CVSS:     a.cvssScore(),
		Fixed:    fixed,
		URL:      a.HTMLURL,
	}
	add := func(id string) {
		if id == "" || id == a.GHSAID || slices.Contains(v.Aliases, id) {
			return
		}
		v.Aliases = append(v.Aliases, id)
		if strings.HasPrefix(id, "CVE-") {
			v.CVEs = append(v.CVEs, id)
		}
	}
	add(a.CVEID)
	for _, id := range a.Identifiers {
		add(id.Value)
	}
	return v
}

var ghConstraint = regexp.MustCompile(`^(>=|<=|>|<|=)?\s*(\S+)$`)

// inGitHubRange evaluates a vulnerable_version_range: comma-separated
// constraints that must all hold (">= 4.0.0, < 4.17.21", "<= 1.2.3",
// "= 2.0.0"). An empty range means GitHub didn't bound it — the API already
// filtered on our version, so it counts as affected. A constraint we can't read
// fails closed to "affected" for the same reason.
func inGitHubRange(rng, v string, cmpV versionCmp) bool {
	rng = strings.TrimSpace(rng)
	if rng == "" {
		return true
	}
	for part := range strings.SplitSeq(rng, ",") {
		m := ghConstraint.FindStringSubmatch(strings.TrimSpace(part))
		if m == nil {
			continue
		}
		c := cmpV(v, m[2])
		var ok bool
		switch m[1] {
		case ">=":
			ok = c >= 0
		case "<=":
			ok = c <= 0
		case ">":
			ok = c > 0
		case "<":
			ok = c < 0
		default:
			ok = c == 0
		}
		if !ok {
			return false
		}
	}
	return true
}

// list fetches every advisory affecting the chunk, following Link pagination.
func (g *GitHubSource) list(ctx context.Context, eco string, chunk []ghItem) ([]ghAdvisory, error) {
	affects := make([]string, len(chunk))
	for i, it := range chunk {
		affects[i] = it.name + "@" + it.p.Version
	}
	q := url.Values{}
	q.Set("ecosystem", eco)
	q.Set("affects", strings.Join(affects, ","))
	q.Set("per_page", strconv.Itoa(ghPerPage))
	next := g.base + "/advisories?" + q.Encode()

	var all []ghAdvisory
	for next != "" {
		// Only ever follow pagination on the configured API: the token goes along.
		if !strings.HasPrefix(next, g.base+"/") {
			return nil, fmt.Errorf("github: refusing pagination link off %s: %s", g.base, next)
		}
		var page []ghAdvisory
		link, err := g.get(ctx, next, &page)
		if err != nil {
			return nil, err
		}
		all = append(all, page...)
		next = nextLink(link)
	}
	return all, nil
}

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// nextLink extracts rel="next" from a Link header.
func nextLink(h string) string {
	if m := linkNext.FindStringSubmatch(h); m != nil {
		return m[1]
	}
	return ""
}

// get performs one request, honoring GitHub's rate limits: once the window is
// spent (X-RateLimit-Remaining: 0, or a 403/429 with Retry-After) the next
// request first waits for the reset — up to ghMaxWait, beyond which the source
// fails for this run. Throttled requests are retried. Returns the Link header.
func (g *GitHubSource) get(ctx context.Context, u string, out any) (string, error) {
	for attempt := 0; ; attempt++ {
		if err := g.waitOut(ctx, g.untilResume()); err != nil {
			return "", err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "xila-vulnmatch")
		if token := g.token.Get(); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := g.hc.Do(req)
		if err != nil {
			return "", fmt.Errorf("github: %w", err)
		}
		wait, limited := g.rateLimitWait(resp)
		if limited {
			g.mu.Lock()
			g.resumeAt = g.now().Add(wait)
			g.mu.Unlock()
		}
		if resp.StatusCode == http.StatusOK {
			err := json.NewDecoder(resp.Body).Decode(out)
			resp.Body.Close()
			if err != nil {
				return "", fmt.Errorf("github: decode advisories: %w", err)
			}
			return resp.Header.Get("Link"), nil
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		resp.Body.Close()
		throttled := resp.StatusCode == http.StatusTooManyRequests ||
			(resp.StatusCode == http.StatusForbidden && limited)
		if !throttled || attempt >= 2 {
			return "", fmt.Errorf("github: GET /advisories returned %d: %s", resp.StatusCode, body)
		}
		if !limited { // throttled without saying for how long: back off
			g.mu.Lock()
			g.resumeAt = g.now().Add(time.Duration(attempt+1) * 30 * time.Second)
			g.mu.Unlock()
		}
	}
}

// untilResume is how long until the rate-limit window reopens (0 = now).
func (g *GitHubSource) untilResume() time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	return max(g.resumeAt.Sub(g.now()), 0)
}

// rateLimitWait reads how long until requests may resume: Retry-After
// (secondary limits) or the X-RateLimit-Reset epoch once Remaining hits 0.
func (g *GitHubSource) rateLimitWait(resp *http.Response) (time.Duration, bool) {
	if ra := resp.Header.Get("Retry-After"); ra != "" {
		if secs, err := strconv.Atoi(ra); err == nil {
			return time.Duration(secs) * time.Second, true
		}
	}
	if resp.Header.Get("X-RateLimit-Remaining") != "0" {
		return 0, false
	}
	reset, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64)
	if err != nil {
		return time.Minute, true
	}
	return max(time.Unix(reset, 0).Sub(g.now())+time.Second, 0), true
}

var errGitHubRateLimited = errors.New("github: rate limit exhausted (set VULNMATCH_GITHUB_TOKEN for a higher limit)")

func (g *GitHubSource) waitOut(ctx context.Context, d time.Duration) error {
	if d > ghMaxWait {
		return fmt.Errorf("%w; resets in %s", errGitHubRateLimited, d.Round(time.Second))
	}
	if d <= 0 {
		return nil
	}
	return g.sleep(ctx, d)
}
