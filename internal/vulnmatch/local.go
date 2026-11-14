package vulnmatch

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/netguard"
)

// DefaultOSVMirrorURL serves OSV's per-ecosystem exports (<Ecosystem>/all.zip).
const DefaultOSVMirrorURL = "https://osv-vulnerabilities.storage.googleapis.com"

const (
	// importBatch is how many advisories go into one upsert statement.
	importBatch = 500
	// maxEntryBytes bounds one OSV JSON document inside an export (the largest
	// real records — kernel CVEs with long version lists — are well under it).
	maxEntryBytes = 16 << 20
	// lookupBatch bounds the match keys sent in one lookup query.
	lookupBatch = 1000
)

// OSVRepository stores the local OSV mirror (osv_advisories).
type OSVRepository struct {
	db *pgxpool.Pool
}

// NewOSVRepository constructs the mirror store.
func NewOSVRepository(db *pgxpool.Pool) *OSVRepository {
	return &OSVRepository{db: db}
}

// ImportResult summarizes one import. Re-importing the same export changes
// nothing: a stored advisory is only replaced by a newer `modified`.
type ImportResult struct {
	Records   int `json:"records"`   // OSV documents read
	Inserted  int `json:"inserted"`  // new advisories
	Updated   int `json:"updated"`   // replaced by a newer `modified`
	Unchanged int `json:"unchanged"` // already stored at this (or a newer) `modified`
	Skipped   int `json:"skipped"`   // not OSV JSON (no id/modified) — counted, not fatal
}

func (r *ImportResult) add(o ImportResult) {
	r.Records += o.Records
	r.Inserted += o.Inserted
	r.Updated += o.Updated
	r.Unchanged += o.Unchanged
	r.Skipped += o.Skipped
}

// osvRow is one advisory as stored: the match keys derived, affected[] verbatim.
type osvRow struct {
	ID         string          `json:"id"`
	Modified   time.Time       `json:"modified"`
	Published  *time.Time      `json:"published"`
	Withdrawn  *time.Time      `json:"withdrawn"`
	Ecosystems []string        `json:"ecosystems"`
	Packages   []string        `json:"packages"`
	Aliases    []string        `json:"aliases"`
	Summary    string          `json:"summary"`
	Details    string          `json:"details"`
	Severity   string          `json:"severity"`
	CVSSVector string          `json:"cvss_vector"`
	Affected   json.RawMessage `json:"affected"`
}

// parseOSVDocument reads one OSV JSON document into a storable row.
func parseOSVDocument(b []byte) (osvRow, bool) {
	var rec osvRecord
	var raw struct {
		Affected json.RawMessage `json:"affected"`
	}
	if json.Unmarshal(b, &rec) != nil || json.Unmarshal(b, &raw) != nil {
		return osvRow{}, false
	}
	if rec.ID == "" || rec.Modified.IsZero() {
		return osvRow{}, false
	}
	row := osvRow{
		ID: rec.ID, Modified: rec.Modified, Published: rec.Published, Withdrawn: rec.Withdrawn,
		Aliases: nonNil(rec.Aliases), Summary: clean(rec.Summary), Details: clean(rec.Details),
		Severity: rec.qualitativeSeverity(), CVSSVector: rec.cvssVector(),
		Affected: raw.Affected, Ecosystems: []string{}, Packages: []string{},
	}
	if len(row.Affected) == 0 || string(row.Affected) == "null" {
		row.Affected = json.RawMessage("[]")
	}
	// Postgres jsonb rejects NUL; no real advisory needs one.
	row.Affected = json.RawMessage(strings.ReplaceAll(string(row.Affected), `\u0000`, ""))
	for _, a := range rec.Affected {
		if k := a.key(); k != "" && !slices.Contains(row.Packages, k) {
			row.Packages = append(row.Packages, k)
		}
		if e := a.ecosystem(); e != "" && !slices.Contains(row.Ecosystems, e) {
			row.Ecosystems = append(row.Ecosystems, e)
		}
	}
	return row, true
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func clean(s string) string { return strings.ReplaceAll(s, "\x00", "") }

// ImportZip imports an OSV ecosystem export (all.zip: one OSV JSON document
// per entry), streaming entry by entry and upserting in batches — memory stays
// bounded whatever the export's size. Idempotent by (id, modified).
func (r *OSVRepository) ImportZip(ctx context.Context, ra io.ReaderAt, size int64) (ImportResult, error) {
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return ImportResult{}, fmt.Errorf("%w: %v", ErrInvalidExport, err)
	}
	var res ImportResult
	batch := make([]osvRow, 0, importBatch)
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		ins, upd, err := r.upsert(ctx, batch)
		if err != nil {
			return err
		}
		res.Inserted += ins
		res.Updated += upd
		res.Unchanged += len(batch) - ins - upd
		batch = batch[:0]
		return nil
	}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.EqualFold(path.Ext(f.Name), ".json") {
			continue
		}
		if err := ctx.Err(); err != nil {
			return res, err
		}
		b, err := readEntry(f)
		if err != nil {
			return res, fmt.Errorf("%w: %s: %v", ErrInvalidExport, f.Name, err)
		}
		res.Records++
		row, ok := parseOSVDocument(b)
		if !ok {
			res.Skipped++
			continue
		}
		// One statement can't touch a row twice: keep the newest of duplicates.
		if i := slices.IndexFunc(batch, func(o osvRow) bool { return o.ID == row.ID }); i >= 0 {
			res.Unchanged++
			if row.Modified.After(batch[i].Modified) {
				batch[i] = row
			}
			continue
		}
		batch = append(batch, row)
		if len(batch) == importBatch {
			if err := flush(); err != nil {
				return res, err
			}
		}
	}
	if err := flush(); err != nil {
		return res, err
	}
	return res, nil
}

// ErrInvalidExport is returned for an upload that isn't a readable zip.
var ErrInvalidExport = errors.New("not a readable OSV export zip")

func readEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, maxEntryBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxEntryBytes {
		return nil, fmt.Errorf("entry larger than %d bytes", maxEntryBytes)
	}
	return b, nil
}

// upsert stores a batch, replacing a stored advisory only with a newer one.
// Returns how many rows were inserted and updated.
func (r *OSVRepository) upsert(ctx context.Context, rows []osvRow) (inserted, updated int, err error) {
	payload, err := json.Marshal(rows)
	if err != nil {
		return 0, 0, fmt.Errorf("encode advisories: %w", err)
	}
	const q = `
		INSERT INTO osv_advisories (id, modified, published, withdrawn, ecosystems, packages, aliases,
			summary, details, severity, cvss_vector, affected, imported_at)
		SELECT r.id, r.modified, r.published, r.withdrawn, r.ecosystems, r.packages, r.aliases,
			r.summary, r.details, r.severity, r.cvss_vector, r.affected, now()
		FROM jsonb_to_recordset($1::jsonb) AS r(id text, modified timestamptz, published timestamptz,
			withdrawn timestamptz, ecosystems text[], packages text[], aliases text[], summary text,
			details text, severity text, cvss_vector text, affected jsonb)
		ON CONFLICT (id) DO UPDATE SET
			modified = EXCLUDED.modified, published = EXCLUDED.published, withdrawn = EXCLUDED.withdrawn,
			ecosystems = EXCLUDED.ecosystems, packages = EXCLUDED.packages, aliases = EXCLUDED.aliases,
			summary = EXCLUDED.summary, details = EXCLUDED.details, severity = EXCLUDED.severity,
			cvss_vector = EXCLUDED.cvss_vector, affected = EXCLUDED.affected, imported_at = now()
		WHERE osv_advisories.modified < EXCLUDED.modified
		RETURNING (xmax = 0)`
	out, err := r.db.Query(ctx, q, string(payload))
	if err != nil {
		return 0, 0, fmt.Errorf("upsert osv advisories: %w", err)
	}
	isInsert, err := pgx.CollectRows(out, pgx.RowTo[bool])
	if err != nil {
		return 0, 0, fmt.Errorf("upsert osv advisories: %w", err)
	}
	for _, ins := range isInsert {
		if ins {
			inserted++
		} else {
			updated++
		}
	}
	return inserted, updated, nil
}

// storedAdvisory is a locally stored advisory (mirror or private), ready to
// evaluate against component versions.
type storedAdvisory struct {
	ID       string
	Aliases  []string
	Summary  string
	Details  string
	Severity domain.Severity
	URL      string
	Packages []string
	Affected []Affected
}

// Lookup returns the non-withdrawn mirrored advisories naming any of keys.
func (r *OSVRepository) Lookup(ctx context.Context, keys []string) ([]storedAdvisory, error) {
	const q = `SELECT id, aliases, summary, details, severity, packages, affected
		FROM osv_advisories WHERE packages && $1::text[] AND withdrawn IS NULL`
	var out []storedAdvisory
	for start := 0; start < len(keys); start += lookupBatch {
		rows, err := r.db.Query(ctx, q, keys[start:min(start+lookupBatch, len(keys))])
		if err != nil {
			return nil, fmt.Errorf("lookup osv advisories: %w", err)
		}
		for rows.Next() {
			var a storedAdvisory
			var sev string
			if err := rows.Scan(&a.ID, &a.Aliases, &a.Summary, &a.Details, &sev, &a.Packages, &a.Affected); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scan osv advisory: %w", err)
			}
			a.Severity = severityFrom(sev)
			out = append(out, a)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("lookup osv advisories: %w", err)
		}
	}
	return out, nil
}

// MirrorStats describes what the local mirror holds.
type MirrorStats struct {
	Advisories int              `json:"advisories"`
	Ecosystems []EcosystemStats `json:"ecosystems"`
}

// EcosystemStats is one ecosystem's share of the mirror.
type EcosystemStats struct {
	Ecosystem    string     `json:"ecosystem"`
	Advisories   int        `json:"advisories"`
	LastModified *time.Time `json:"last_modified"`
	LastImported *time.Time `json:"last_imported"`
}

// Stats reports the mirror's size per ecosystem.
func (r *OSVRepository) Stats(ctx context.Context) (MirrorStats, error) {
	st := MirrorStats{Ecosystems: []EcosystemStats{}}
	if err := r.db.QueryRow(ctx, `SELECT count(*) FROM osv_advisories`).Scan(&st.Advisories); err != nil {
		return st, fmt.Errorf("count osv advisories: %w", err)
	}
	rows, err := r.db.Query(ctx, `
		SELECT e, count(*), max(modified), max(imported_at)
		FROM osv_advisories, unnest(ecosystems) AS e GROUP BY e ORDER BY e COLLATE "C"`)
	if err != nil {
		return st, fmt.Errorf("osv mirror stats: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e EcosystemStats
		if err := rows.Scan(&e.Ecosystem, &e.Advisories, &e.LastModified, &e.LastImported); err != nil {
			return st, err
		}
		st.Ecosystems = append(st.Ecosystems, e)
	}
	return st, rows.Err()
}

// advisoryLookup finds stored advisories by match key (mirror or private).
type advisoryLookup interface {
	Lookup(ctx context.Context, keys []string) ([]storedAdvisory, error)
}

// storedSource evaluates locally stored OSV-format advisories — the mirror
// (osv-local) or the private database — with the OSV range algorithm.
type storedSource struct {
	store advisoryLookup
}

// NewLocalSource is the osv-local source: the imported OSV mirror, no network.
func NewLocalSource(repo *OSVRepository) Source { return storedSource{store: repo} }

// Query maps each purl to the stored advisories whose affected ranges/versions
// cover its version.
func (s storedSource) Query(ctx context.Context, purls []string) (map[string][]Vuln, error) {
	byKey := map[string][]purl{}
	raw := map[purl]string{}
	var keys []string
	for _, ps := range purls {
		p, ok := parsePurl(ps)
		if !ok || p.Version == "" {
			continue
		}
		raw[p] = ps
		for _, k := range componentKeys(p) {
			if _, seen := byKey[k]; !seen {
				keys = append(keys, k)
			}
			byKey[k] = append(byKey[k], p)
		}
	}
	out := map[string][]Vuln{}
	if len(keys) == 0 {
		return out, nil
	}
	advisories, err := s.store.Lookup(ctx, keys)
	if err != nil {
		return nil, err
	}
	for _, a := range advisories {
		rec := osvRecord{ID: a.ID, Aliases: a.Aliases, Summary: a.Summary, Details: a.Details, Affected: a.Affected}
		seen := map[purl]bool{}
		for _, k := range a.Packages {
			for _, p := range byKey[k] {
				if seen[p] {
					continue
				}
				seen[p] = true
				hit, fixed := rec.evaluate(p)
				if !hit {
					continue
				}
				v := rec.base()
				v.Severity, v.Fixed, v.URL = a.Severity, fixed, a.URL
				out[raw[p]] = append(out[raw[p]], v)
			}
		}
	}
	return out, nil
}

// Mirror keeps the local OSV mirror current by downloading OSV's ecosystem
// exports (VULNMATCH_OSV_MIRROR_URL/<Ecosystem>/all.zip) on a schedule. Point
// the URL at an internal HTTP server holding the same files to stay offline.
type Mirror struct {
	repo       *OSVRepository
	base       string
	ecosystems []string
	hc         *http.Client
}

// NewMirror constructs the downloader. An empty baseURL uses OSV's bucket.
func NewMirror(repo *OSVRepository, baseURL string, ecosystems []string) *Mirror {
	if baseURL == "" {
		baseURL = DefaultOSVMirrorURL
	}
	return &Mirror{
		repo: repo, base: strings.TrimRight(baseURL, "/"), ecosystems: ecosystems,
		// No overall timeout: exports run to hundreds of MB. The context bounds it.
		hc: func() *http.Client {
			t := netguard.Transport()
			t.ResponseHeaderTimeout = time.Minute
			return netguard.WrapTransport(t, 0)
		}(),
	}
}

// Sync downloads and imports every configured ecosystem. One ecosystem failing
// doesn't stop the others; their errors are joined.
func (m *Mirror) Sync(ctx context.Context) (ImportResult, error) {
	var total ImportResult
	var errs []error
	for _, eco := range m.ecosystems {
		res, err := m.syncOne(ctx, eco)
		total.add(res)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", eco, err))
			continue
		}
		slog.InfoContext(ctx, "osv mirror: ecosystem imported", "ecosystem", eco,
			"records", res.Records, "inserted", res.Inserted, "updated", res.Updated)
	}
	return total, errors.Join(errs...)
}

func (m *Mirror) syncOne(ctx context.Context, eco string) (ImportResult, error) {
	u := m.base + "/" + url.PathEscape(eco) + "/all.zip"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ImportResult{}, err
	}
	resp, err := m.hc.Do(req)
	if err != nil {
		return ImportResult{}, fmt.Errorf("download %s: %w", u, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ImportResult{}, fmt.Errorf("download %s: %s", u, resp.Status)
	}
	// zip needs random access: spool to a temp file rather than memory.
	tmp, err := os.CreateTemp("", "osv-*.zip")
	if err != nil {
		return ImportResult{}, err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	size, err := io.Copy(tmp, resp.Body)
	if err != nil {
		return ImportResult{}, fmt.Errorf("download %s: %w", u, err)
	}
	return m.repo.ImportZip(ctx, tmp, size)
}
