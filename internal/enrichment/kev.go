package enrichment

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// Default catalog URLs (each overridable: a mirror, a proxy).
const (
	DefaultCISAKEVURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	// DefaultENISAKEVURL is the EU Vulnerability Database search API filtered to
	// exploited vulnerabilities; it pages (100 per page at most).
	DefaultENISAKEVURL     = "https://euvdservices.enisa.europa.eu/api/search?exploited=true"
	DefaultVulnCheckKEVURL = "https://api.vulncheck.com/v3/index/vulncheck-kev"
)

const (
	maxKEVBytes = 64 << 20 // one download (CISA's whole catalog is ~1.5 MB)
	maxKEVPages = 1000     // a runaway paginator stops here
	euvdPage    = 100      // the EUVD API's largest page
)

// KEVCatalog is one known-exploited-vulnerabilities catalog. Fetch returns
// every vulnerability id it asserts — an entry contributes each id it names
// (CVE, GHSA, EUVD) — uppercased.
type KEVCatalog interface {
	Name() string
	Fetch(ctx context.Context) ([]string, error)
}

// KEVCatalogs builds the configured catalogs. urls overrides a catalog's URL
// by name; vulncheck needs vulnCheckToken. client must be the guarded
// outbound client (internal/netguard).
func KEVCatalogs(names []string, urls map[string]string, vulnCheckToken string, client *http.Client) ([]KEVCatalog, error) {
	var out []KEVCatalog
	seen := map[string]bool{}
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		u := urls[n]
		switch n {
		case domain.KEVCISA:
			out = append(out, &cisaCatalog{url: cmp.Or(u, DefaultCISAKEVURL), client: client})
		case domain.KEVENISA:
			out = append(out, &euvdCatalog{url: cmp.Or(u, DefaultENISAKEVURL), pageSize: euvdPage, client: client})
		case domain.KEVVulnCheck:
			if vulnCheckToken == "" {
				return nil, fmt.Errorf("kev source %q needs VULNCHECK_API_TOKEN", n)
			}
			out = append(out, &vulnCheckCatalog{url: cmp.Or(u, DefaultVulnCheckKEVURL), token: vulnCheckToken, client: client})
		default:
			return nil, fmt.Errorf("unknown kev source %q (%s)", n, strings.Join(domain.KEVCatalogs, ", "))
		}
	}
	return out, nil
}

// ids collects normalized vulnerability ids, deduplicated.
type ids struct {
	seen map[string]bool
	list []string
}

func (s *ids) add(raw ...string) {
	if s.seen == nil {
		s.seen = map[string]bool{}
	}
	for _, id := range raw {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id == "" || s.seen[id] {
			continue
		}
		s.seen[id] = true
		s.list = append(s.list, id)
	}
}

// ParseCISAKEV reads CISA's known_exploited_vulnerabilities.json.
func ParseCISAKEV(r io.Reader) ([]string, error) {
	var doc struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("cisa kev: %w", err)
	}
	var out ids
	for _, v := range doc.Vulnerabilities {
		out.add(v.CveID)
	}
	return out.list, nil
}

// EUVDPage is one page of the EU Vulnerability Database search API.
type EUVDPage struct {
	IDs   []string // every id of every item: EUVD id + aliases (CVE, GHSA)
	Items int      // items on this page
	Total int      // items across all pages
}

// ParseEUVDPage reads one page of ENISA's EUVD search API
// (/api/search?exploited=true): {"items":[{"id":"EUVD-…","aliases":"CVE-…\nGHSA-…\n"}],"total":N}.
func ParseEUVDPage(r io.Reader) (EUVDPage, error) {
	var doc struct {
		Items []struct {
			ID      string `json:"id"`
			Aliases string `json:"aliases"`
		} `json:"items"`
		Total int `json:"total"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return EUVDPage{}, fmt.Errorf("enisa euvd: %w", err)
	}
	var out ids
	for _, it := range doc.Items {
		out.add(it.ID)
		out.add(strings.Fields(it.Aliases)...)
	}
	return EUVDPage{IDs: out.list, Items: len(doc.Items), Total: doc.Total}, nil
}

// VulnCheckPage is one page of VulnCheck's index API.
type VulnCheckPage struct {
	IDs        []string
	NextCursor string // "" on the last page
}

// ParseVulnCheckKEVPage reads one page of VulnCheck's vulncheck-kev index
// (/v3/index/vulncheck-kev): {"_meta":{"next_cursor":…},"data":[{"cve":[…]}]}.
func ParseVulnCheckKEVPage(r io.Reader) (VulnCheckPage, error) {
	var doc struct {
		Meta struct {
			NextCursor string `json:"next_cursor"`
		} `json:"_meta"`
		Data []struct {
			CVE []string `json:"cve"`
		} `json:"data"`
	}
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return VulnCheckPage{}, fmt.Errorf("vulncheck kev: %w", err)
	}
	var out ids
	for _, d := range doc.Data {
		out.add(d.CVE...)
	}
	return VulnCheckPage{IDs: out.list, NextCursor: doc.Meta.NextCursor}, nil
}

// get fetches u (with an optional bearer token) and hands the bounded body to
// parse.
func get(ctx context.Context, client *http.Client, u, token string, parse func(io.Reader) error) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", redact(u), res.StatusCode)
	}
	lr := &io.LimitedReader{R: res.Body, N: maxKEVBytes + 1}
	if err := parse(lr); err != nil {
		return err
	}
	if lr.N <= 0 {
		return fmt.Errorf("%s: larger than %d bytes", redact(u), maxKEVBytes)
	}
	return nil
}

// redact drops the query (cursors) from a URL for error messages.
func redact(u string) string {
	if p, err := url.Parse(u); err == nil {
		p.RawQuery = ""
		return p.String()
	}
	return u
}

// nonEmpty refuses an empty catalog: a real one always lists entries, and
// replacing a source's stored entries with nothing would drop every assertion.
func nonEmpty(name string, list []string) ([]string, error) {
	if len(list) == 0 {
		return nil, fmt.Errorf("%s: catalog is empty", name)
	}
	return list, nil
}

type cisaCatalog struct {
	url    string
	client *http.Client
}

func (c *cisaCatalog) Name() string { return domain.KEVCISA }

func (c *cisaCatalog) Fetch(ctx context.Context) ([]string, error) {
	var list []string
	err := get(ctx, c.client, c.url, "", func(r io.Reader) (err error) {
		list, err = ParseCISAKEV(r)
		return err
	})
	if err != nil {
		return nil, err
	}
	return nonEmpty(domain.KEVCISA, list)
}

type euvdCatalog struct {
	url      string
	pageSize int
	client   *http.Client
}

func (c *euvdCatalog) Name() string { return domain.KEVENISA }

// Fetch walks the search API's pages until it has every item.
func (c *euvdCatalog) Fetch(ctx context.Context) ([]string, error) {
	base, err := url.Parse(c.url)
	if err != nil {
		return nil, fmt.Errorf("enisa url: %w", err)
	}
	var all ids
	seenItems := 0
	for page := range maxKEVPages {
		q := base.Query()
		q.Set("page", strconv.Itoa(page))
		q.Set("size", strconv.Itoa(c.pageSize))
		base.RawQuery = q.Encode()
		var p EUVDPage
		if err := get(ctx, c.client, base.String(), "", func(r io.Reader) (err error) {
			p, err = ParseEUVDPage(r)
			return err
		}); err != nil {
			return nil, err
		}
		all.add(p.IDs...)
		seenItems += p.Items
		if p.Items == 0 || p.Items < c.pageSize || seenItems >= p.Total {
			return nonEmpty(domain.KEVENISA, all.list)
		}
	}
	return nil, fmt.Errorf("enisa: more than %d pages", maxKEVPages)
}

type vulnCheckCatalog struct {
	url    string
	token  string
	client *http.Client
}

func (c *vulnCheckCatalog) Name() string { return domain.KEVVulnCheck }

// Fetch follows the index's cursor (start_cursor, then _meta.next_cursor)
// until a page comes back without one.
func (c *vulnCheckCatalog) Fetch(ctx context.Context) ([]string, error) {
	base, err := url.Parse(c.url)
	if err != nil {
		return nil, fmt.Errorf("vulncheck url: %w", err)
	}
	var all ids
	cursor := ""
	for range maxKEVPages {
		q := base.Query()
		q.Del("cursor")
		q.Del("start_cursor")
		if cursor == "" {
			q.Set("start_cursor", "true")
		} else {
			q.Set("cursor", cursor)
		}
		base.RawQuery = q.Encode()
		var p VulnCheckPage
		if err := get(ctx, c.client, base.String(), c.token, func(r io.Reader) (err error) {
			p, err = ParseVulnCheckKEVPage(r)
			return err
		}); err != nil {
			return nil, err
		}
		all.add(p.IDs...)
		if p.NextCursor == "" || p.NextCursor == cursor {
			return nonEmpty(domain.KEVVulnCheck, all.list)
		}
		cursor = p.NextCursor
	}
	return nil, fmt.Errorf("vulncheck: more than %d pages", maxKEVPages)
}

// sortedSources returns the distinct catalog names, sorted.
func sortedSources(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for s := range set {
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}
