package vulnmatch

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/netguard"
)

// JVN iPedia (https://jvndb.jvn.jp), Japan's vulnerability database, run by
// IPA and JPCERT/CC. Its RSS feeds (JVNRSS 2.0) name every entry's JVNDB id,
// the CVEs it covers, CVSS and products — as CPEs without versions. Without a
// version range nothing can say whether an installed version is affected, so
// the jvn source does not match inventory: it is CVE alias enrichment. An
// advisory any other source matched gains the JVNDB ids of its CVEs as
// aliases (and "jvn" among its sources), which feed rules and search can use.
// It never creates, removes or renames a finding, so its failure can't close
// anything.

// DefaultJVNURL is JVN iPedia.
const DefaultJVNURL = "https://jvndb.jvn.jp"

// JVNEntry is one JVN iPedia advisory.
type JVNEntry struct {
	ID         string     `json:"id"`
	Title      string     `json:"title"`
	URL        string     `json:"url"`
	CVEs       []string   `json:"cves"`
	CPEs       []string   `json:"cpes"`
	CVSSScore  *float64   `json:"cvss_score"`
	CVSSVector string     `json:"cvss_vector"`
	Severity   string     `json:"severity"`
	Published  *time.Time `json:"published"`
	Modified   *time.Time `json:"modified"`
}

type jvnRSS struct {
	Items []struct {
		Title      string `xml:"http://purl.org/rss/1.0/ title"`
		Link       string `xml:"http://purl.org/rss/1.0/ link"`
		Identifier string `xml:"http://jvn.jp/rss/mod_sec/ identifier"`
		References []struct {
			Source string `xml:"source,attr"`
			ID     string `xml:"id,attr"`
		} `xml:"http://jvn.jp/rss/mod_sec/ references"`
		CPEs []string `xml:"http://jvn.jp/rss/mod_sec/ cpe"`
		CVSS []struct {
			Version  string `xml:"version,attr"`
			Score    string `xml:"score,attr"`
			Severity string `xml:"severity,attr"`
			Vector   string `xml:"vector,attr"`
		} `xml:"http://jvn.jp/rss/mod_sec/ cvss"`
		Issued   string `xml:"http://purl.org/dc/terms/ issued"`
		Modified string `xml:"http://purl.org/dc/terms/ modified"`
	} `xml:"http://purl.org/rss/1.0/ item"`
}

// ParseJVNRSS decodes a JVN iPedia RSS feed (jvndb.rdf, jvndb_new.rdf,
// years/jvndb_YYYY.rdf). Entries without a JVNDB id are skipped.
func ParseJVNRSS(r io.Reader) ([]JVNEntry, error) {
	var doc jvnRSS
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("jvn: decode feed: %w", err)
	}
	out := make([]JVNEntry, 0, len(doc.Items))
	for _, it := range doc.Items {
		id := strings.TrimSpace(it.Identifier)
		if !strings.HasPrefix(id, "JVNDB-") {
			continue
		}
		e := JVNEntry{ID: id, Title: strings.TrimSpace(it.Title), URL: strings.TrimSpace(it.Link),
			CVEs: []string{}, CPEs: []string{}}
		for _, ref := range it.References {
			cve := strings.ToUpper(strings.TrimSpace(ref.ID))
			if (ref.Source == "CVE" || ref.Source == "NVD") && strings.HasPrefix(cve, "CVE-") && !slices.Contains(e.CVEs, cve) {
				e.CVEs = append(e.CVEs, cve)
			}
		}
		slices.Sort(e.CVEs)
		for _, c := range it.CPEs {
			if c = strings.TrimSpace(c); c != "" && !slices.Contains(e.CPEs, c) {
				e.CPEs = append(e.CPEs, c)
			}
		}
		// The newest CVSS version the entry states.
		best := -1.0
		for _, c := range it.CVSS {
			v, err := strconv.ParseFloat(c.Version, 64)
			score, serr := strconv.ParseFloat(c.Score, 64)
			if err != nil || serr != nil || v <= best {
				continue
			}
			best = v
			e.CVSSScore, e.CVSSVector, e.Severity = &score, c.Vector, strings.ToLower(c.Severity)
		}
		e.Published, e.Modified = jvnTime(it.Issued), jvnTime(it.Modified)
		out = append(out, e)
	}
	return out, nil
}

// jvnTime parses JVN's W3C-DTF timestamps ("2024-02-07T13:38+09:00" — often
// without seconds).
func jvnTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04Z07:00", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			t = t.UTC()
			return &t
		}
	}
	return nil
}

// aliasSource resolves CVEs to the JVN entries naming them.
type aliasSource interface {
	ByCVE(ctx context.Context, cves []string) (map[string][]JVNEntry, error)
}

// enrichAliases adds each advisory's JVNDB ids (via its CVEs) to its aliases
// and "jvn" to its sources. Returns a new map; vulns is never modified. On a
// lookup failure the advisories are returned unchanged (logged).
func enrichAliases(ctx context.Context, src aliasSource, vulns map[string][]Vuln) map[string][]Vuln {
	var cves []string
	seen := map[string]bool{}
	for _, vs := range vulns {
		for _, v := range vs {
			for _, c := range v.CVEs {
				if !seen[c] {
					seen[c] = true
					cves = append(cves, c)
				}
			}
		}
	}
	if len(cves) == 0 {
		return vulns
	}
	byCVE, err := src.ByCVE(ctx, cves)
	if err != nil {
		slog.WarnContext(ctx, "vulnmatch: jvn alias enrichment failed; advisories keep their other ids", "error", err)
		return vulns
	}
	out := make(map[string][]Vuln, len(vulns))
	for key, vs := range vulns {
		cp := slices.Clone(vs)
		for i := range cp {
			var add []string
			for _, c := range cp[i].CVEs {
				for _, e := range byCVE[c] {
					if e.ID != cp[i].ID && !slices.Contains(cp[i].Aliases, e.ID) && !slices.Contains(add, e.ID) {
						add = append(add, e.ID)
					}
				}
			}
			if len(add) == 0 {
				continue
			}
			slices.Sort(add)
			cp[i].Aliases = append(slices.Clone(cp[i].Aliases), add...)
			if !slices.Contains(cp[i].Sources, SourceJVN) {
				cp[i].Sources = append(slices.Clone(cp[i].Sources), SourceJVN)
			}
		}
		out[key] = cp
	}
	return out
}

// JVNRepository is the local JVN iPedia mirror (jvn_advisories).
type JVNRepository struct{ db *pgxpool.Pool }

// NewJVNRepository constructs the mirror store.
func NewJVNRepository(db *pgxpool.Pool) *JVNRepository { return &JVNRepository{db: db} }

// Upsert stores entries, replacing ones already mirrored.
func (r *JVNRepository) Upsert(ctx context.Context, entries []JVNEntry) error {
	if len(entries) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, e := range entries {
		batch.Queue(`
			INSERT INTO jvn_advisories (id, title, url, cves, cpes, cvss_score, cvss_vector, severity, published, modified)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
			ON CONFLICT (id) DO UPDATE SET title = EXCLUDED.title, url = EXCLUDED.url, cves = EXCLUDED.cves,
				cpes = EXCLUDED.cpes, cvss_score = EXCLUDED.cvss_score, cvss_vector = EXCLUDED.cvss_vector,
				severity = EXCLUDED.severity, published = EXCLUDED.published, modified = EXCLUDED.modified,
				imported_at = now()`,
			e.ID, e.Title, e.URL, e.CVEs, e.CPEs, e.CVSSScore, e.CVSSVector, e.Severity, e.Published, e.Modified)
	}
	if err := r.db.SendBatch(ctx, batch).Close(); err != nil {
		return fmt.Errorf("jvn: store entries: %w", err)
	}
	return nil
}

// ByCVE returns the mirrored entries naming each CVE.
func (r *JVNRepository) ByCVE(ctx context.Context, cves []string) (map[string][]JVNEntry, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, title, url, cves, cpes, cvss_score, cvss_vector, severity, published, modified
		FROM jvn_advisories WHERE cves && $1 ORDER BY id`, cves)
	if err != nil {
		return nil, fmt.Errorf("jvn: lookup: %w", err)
	}
	defer rows.Close()
	want := map[string]bool{}
	for _, c := range cves {
		want[c] = true
	}
	out := map[string][]JVNEntry{}
	for rows.Next() {
		var e JVNEntry
		if err := rows.Scan(&e.ID, &e.Title, &e.URL, &e.CVEs, &e.CPEs, &e.CVSSScore, &e.CVSSVector,
			&e.Severity, &e.Published, &e.Modified); err != nil {
			return nil, fmt.Errorf("jvn: scan: %w", err)
		}
		for _, c := range e.CVEs {
			if want[c] {
				out[c] = append(out[c], e)
			}
		}
	}
	return out, rows.Err()
}

// JVNStats describes the mirror.
type JVNStats struct {
	Entries    int        `json:"entries"`
	LastImport *time.Time `json:"last_import"`
}

// Stats reports the mirror's size and freshness.
func (r *JVNRepository) Stats(ctx context.Context) (JVNStats, error) {
	var s JVNStats
	err := r.db.QueryRow(ctx, `SELECT count(*), max(imported_at) FROM jvn_advisories`).Scan(&s.Entries, &s.LastImport)
	return s, err
}

// JVNMirror downloads JVN iPedia's English RSS feeds into the mirror: every
// yearly feed from FromYear when the mirror is empty, then the current and
// previous year plus the recently-updated feed (jvndb.rdf) on each sync.
type JVNMirror struct {
	repo     *JVNRepository
	base     string
	fromYear int
	hc       *http.Client
	now      func() time.Time
}

// NewJVNMirror constructs the syncer. An empty baseURL uses JVN iPedia.
func NewJVNMirror(repo *JVNRepository, baseURL string, fromYear int) *JVNMirror {
	if baseURL == "" {
		baseURL = DefaultJVNURL
	}
	return &JVNMirror{repo: repo, base: strings.TrimRight(baseURL, "/"), fromYear: fromYear,
		hc: netguard.NewClient(2 * time.Minute), now: time.Now}
}

// JVNSyncResult reports one sync.
type JVNSyncResult struct {
	Feeds   int `json:"feeds"`
	Entries int `json:"entries"`
}

// maxJVNFeed bounds one feed download (yearly feeds are a few MB).
const maxJVNFeed = 64 << 20

// Sync downloads and stores the feeds. Feeds that fail are reported together
// after the others were stored.
func (m *JVNMirror) Sync(ctx context.Context) (JVNSyncResult, error) {
	st, err := m.repo.Stats(ctx)
	if err != nil {
		return JVNSyncResult{}, err
	}
	year := m.now().UTC().Year()
	from := year - 1
	if st.Entries == 0 && m.fromYear > 0 && m.fromYear < from {
		from = m.fromYear
	}
	feeds := []string{}
	for y := from; y <= year; y++ {
		feeds = append(feeds, fmt.Sprintf("/en/rss/years/jvndb_%d.rdf", y))
	}
	feeds = append(feeds, "/en/rss/jvndb.rdf")
	var res JVNSyncResult
	var errs []error
	for _, f := range feeds {
		n, err := m.syncFeed(ctx, f)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		res.Feeds++
		res.Entries += n
	}
	return res, errors.Join(errs...)
}

func (m *JVNMirror) syncFeed(ctx context.Context, feed string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.base+feed, nil)
	if err != nil {
		return 0, err
	}
	resp, err := m.hc.Do(req)
	if err != nil {
		return 0, fmt.Errorf("jvn: %s: %w", feed, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, nil // a year JVN hasn't published (yet)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("jvn: %s returned %d", feed, resp.StatusCode)
	}
	entries, err := ParseJVNRSS(io.LimitReader(resp.Body, maxJVNFeed))
	if err != nil {
		return 0, fmt.Errorf("jvn: %s: %w", feed, err)
	}
	if err := m.repo.Upsert(ctx, entries); err != nil {
		return 0, err
	}
	return len(entries), nil
}
