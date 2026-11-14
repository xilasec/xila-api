// Package pkgmeta tells whether SBOM components are outdated. Like
// Dependency-Track's repository meta analyzers, it asks each ecosystem's
// package registry (npm, PyPI, Maven, Go, Cargo, NuGet, RubyGems, Packagist)
// for every published version of the packages in current SBOM inventory,
// caches the answer per package (package_meta), and derives per component purl
// whether a newer stable release exists and how many releases behind it is
// (package_status) — which component listings filter on and the policy engine
// reads through Repository.Info.
package pkgmeta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNoMeta is returned when a package has never been looked up.
var ErrNoMeta = errors.New("no metadata for this package")

// ErrSbomNotFound is returned by SbomFreshness for a missing snapshot.
var ErrSbomNotFound = errors.New("sbom not found")

// Meta is the cached registry metadata of one package.
type Meta struct {
	BasePurl        string     `json:"base_purl"`
	Ecosystem       string     `json:"ecosystem"`
	LatestVersion   string     `json:"latest_version"` // "" until fetched or when nothing stable exists
	LatestPublished *time.Time `json:"latest_published_at"`
	Versions        []Version  `json:"versions"` // newest first
	FetchedAt       *time.Time `json:"fetched_at"`
	NextFetchAt     time.Time  `json:"next_fetch_at"`
	LastError       string     `json:"last_error"`
	ErrorCount      int        `json:"error_count"`
}

// Freshness counts a snapshot's components by outdated state.
type Freshness struct {
	Total    int `json:"total"`
	Outdated int `json:"outdated"`
	UpToDate int `json:"up_to_date"`
	Unknown  int `json:"unknown"` // no purl, unsupported ecosystem, not fetched (yet), or not in the registry
}

// status is one package_status row.
type status struct {
	Purl, Base, Version string
	Info
}

// due is a package whose metadata should be (re)fetched.
type due struct {
	Base       string
	ErrorCount int // consecutive failures so far
}

// Repository provides access to package_meta and package_status.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// InventoryPurls returns the distinct purls of current inventory — the newest
// snapshot per (project version, artifact) — optionally of one project.
func (r *Repository) InventoryPurls(ctx context.Context, projectID string) ([]string, error) {
	const q = `
		WITH latest AS (
			SELECT DISTINCT ON (version_id, artifact) id FROM sboms
			WHERE $1::uuid IS NULL OR project_id = $1
			ORDER BY version_id, artifact, created_at DESC
		)
		SELECT DISTINCT c.purl FROM sbom_components c
		WHERE c.purl <> '' AND c.sbom_id IN (SELECT id FROM latest)`
	var scope *string
	if projectID != "" {
		scope = &projectID
	}
	rows, err := r.db.Query(ctx, q, scope)
	if err != nil {
		return nil, fmt.Errorf("list inventory purls: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// Due returns the packages among bases that were never looked up, or whose
// next fetch time has come.
func (r *Repository) Due(ctx context.Context, bases []string, now time.Time) ([]due, error) {
	const q = `
		SELECT b.base, COALESCE(m.error_count, 0)
		FROM unnest($1::text[]) AS b(base)
		LEFT JOIN package_meta m ON m.base_purl = b.base
		WHERE m.base_purl IS NULL OR m.next_fetch_at <= $2
		ORDER BY m.next_fetch_at NULLS FIRST, b.base`
	rows, err := r.db.Query(ctx, q, bases, now)
	if err != nil {
		return nil, fmt.Errorf("list due packages: %w", err)
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (due, error) {
		var d due
		err := row.Scan(&d.Base, &d.ErrorCount)
		return d, err
	})
}

// Unknown returns the packages among bases that were never looked up.
func (r *Repository) Unknown(ctx context.Context, bases []string) ([]string, error) {
	const q = `
		SELECT b.base FROM unnest($1::text[]) AS b(base)
		WHERE NOT EXISTS (SELECT 1 FROM package_meta m WHERE m.base_purl = b.base)`
	rows, err := r.db.Query(ctx, q, bases)
	if err != nil {
		return nil, fmt.Errorf("list unknown packages: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// SaveFetched records a successful fetch, clearing any error state.
func (r *Repository) SaveFetched(ctx context.Context, m Meta) error {
	versions, err := json.Marshal(m.Versions)
	if err != nil {
		return err
	}
	const q = `
		INSERT INTO package_meta (base_purl, ecosystem, latest_version, latest_published_at, versions,
			fetched_at, next_fetch_at, last_error, error_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, '', 0)
		ON CONFLICT (base_purl) DO UPDATE SET
			ecosystem = EXCLUDED.ecosystem, latest_version = EXCLUDED.latest_version,
			latest_published_at = EXCLUDED.latest_published_at, versions = EXCLUDED.versions,
			fetched_at = EXCLUDED.fetched_at, next_fetch_at = EXCLUDED.next_fetch_at,
			last_error = '', error_count = 0, updated_at = now()`
	_, err = r.db.Exec(ctx, q, m.BasePurl, m.Ecosystem, m.LatestVersion, m.LatestPublished, versions,
		m.FetchedAt, m.NextFetchAt)
	if err != nil {
		return fmt.Errorf("save package meta: %w", err)
	}
	return nil
}

// SaveFailed records a failed fetch. Previously fetched data is kept — stale
// beats unknown — and only the error and backoff state change.
func (r *Repository) SaveFailed(ctx context.Context, base, ecosystem, msg string, errorCount int, next time.Time) error {
	const q = `
		INSERT INTO package_meta (base_purl, ecosystem, next_fetch_at, last_error, error_count)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (base_purl) DO UPDATE SET
			next_fetch_at = EXCLUDED.next_fetch_at, last_error = EXCLUDED.last_error,
			error_count = EXCLUDED.error_count, updated_at = now()`
	if _, err := r.db.Exec(ctx, q, base, ecosystem, next, msg, errorCount); err != nil {
		return fmt.Errorf("save package meta failure: %w", err)
	}
	return nil
}

const metaColumns = `base_purl, ecosystem, latest_version, latest_published_at, versions,
	fetched_at, next_fetch_at, last_error, error_count`

func scanMeta(row pgx.Row) (Meta, error) {
	var m Meta
	err := row.Scan(&m.BasePurl, &m.Ecosystem, &m.LatestVersion, &m.LatestPublished, &m.Versions,
		&m.FetchedAt, &m.NextFetchAt, &m.LastError, &m.ErrorCount)
	if m.Versions == nil {
		m.Versions = []Version{}
	}
	return m, err
}

// Get returns one package's metadata, including a failed lookup's error state.
func (r *Repository) Get(ctx context.Context, base string) (Meta, error) {
	m, err := scanMeta(r.db.QueryRow(ctx, `SELECT `+metaColumns+` FROM package_meta WHERE base_purl = $1`, base))
	if errors.Is(err, pgx.ErrNoRows) {
		return Meta{}, ErrNoMeta
	}
	if err != nil {
		return Meta{}, fmt.Errorf("get package meta: %w", err)
	}
	return m, nil
}

// Metas returns the successfully fetched metadata among bases.
func (r *Repository) Metas(ctx context.Context, bases []string) (map[string]Meta, error) {
	rows, err := r.db.Query(ctx, `SELECT `+metaColumns+` FROM package_meta
		WHERE base_purl = ANY($1) AND fetched_at IS NOT NULL`, bases)
	if err != nil {
		return nil, fmt.Errorf("list package meta: %w", err)
	}
	defer rows.Close()
	out := map[string]Meta{}
	for rows.Next() {
		m, err := scanMeta(rows)
		if err != nil {
			return nil, fmt.Errorf("scan package meta: %w", err)
		}
		out[m.BasePurl] = m
	}
	return out, rows.Err()
}

// PurlsNeedingStatus returns the component purls (of any snapshot, so history
// pages show freshness too) of supported ecosystems that have no status yet —
// optionally only in one project — plus every purl of the refreshed packages,
// whose status may have changed with the new metadata.
func (r *Repository) PurlsNeedingStatus(ctx context.Context, refreshed []string, projectID string) ([]string, error) {
	const q = `
		SELECT DISTINCT c.purl FROM sbom_components c
		LEFT JOIN package_status ps ON ps.purl = c.purl
		WHERE c.purl <> ''
		  AND lower(split_part(substr(c.purl, 5), '/', 1)) = ANY($3)
		  AND ((ps.purl IS NULL AND ($2::uuid IS NULL OR c.project_id = $2)) OR ps.base_purl = ANY($1))`
	var scope *string
	if projectID != "" {
		scope = &projectID
	}
	if refreshed == nil {
		refreshed = []string{}
	}
	rows, err := r.db.Query(ctx, q, refreshed, scope, Ecosystems)
	if err != nil {
		return nil, fmt.Errorf("list purls needing status: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// componentHashes is one hashed component of a purl whose status is being
// recomputed.
type componentHashes struct {
	ID, Purl  string
	Hashes    map[string]string
	Integrity *string
}

// ComponentHashes returns the components with SBOM hashes among purls.
func (r *Repository) ComponentHashes(ctx context.Context, purls []string) ([]componentHashes, error) {
	rows, err := r.db.Query(ctx, `SELECT id, purl, hashes, integrity FROM sbom_components
		WHERE purl = ANY($1) AND hashes <> '{}'::jsonb`, purls)
	if err != nil {
		return nil, fmt.Errorf("list component hashes: %w", err)
	}
	defer rows.Close()
	var out []componentHashes
	for rows.Next() {
		var c componentHashes
		if err := rows.Scan(&c.ID, &c.Purl, &c.Hashes, &c.Integrity); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// SaveIntegrity writes components' integrity verdicts ("" = unknown → NULL).
func (r *Repository) SaveIntegrity(ctx context.Context, ids []string, verdicts []string) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	tag, err := r.db.Exec(ctx, `UPDATE sbom_components c SET integrity = NULLIF(u.v, '')
		FROM (SELECT unnest($1::uuid[]) AS id, unnest($2::text[]) AS v) u
		WHERE c.id = u.id AND c.integrity IS DISTINCT FROM NULLIF(u.v, '')`, ids, verdicts)
	if err != nil {
		return 0, fmt.Errorf("save integrity: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// statusBatch bounds the rows written per statement.
const statusBatch = 5000

// SaveStatuses upserts component statuses — rewriting a row only when its
// value changed, so a sweep over an unchanged inventory writes nothing — and
// deletes the statuses of purls that became unknown. Returns rows written.
func (r *Repository) SaveStatuses(ctx context.Context, upserts []status, deletes []string) (int, error) {
	const q = `
		INSERT INTO package_status (purl, base_purl, version, latest_version, outdated, versions_behind,
			published_at, latest_published_at)
		SELECT * FROM unnest($1::text[], $2::text[], $3::text[], $4::text[], $5::bool[], $6::int[],
			$7::timestamptz[], $8::timestamptz[])
		ON CONFLICT (purl) DO UPDATE SET
			base_purl = EXCLUDED.base_purl, version = EXCLUDED.version,
			latest_version = EXCLUDED.latest_version, outdated = EXCLUDED.outdated,
			versions_behind = EXCLUDED.versions_behind, published_at = EXCLUDED.published_at,
			latest_published_at = EXCLUDED.latest_published_at, computed_at = now()
		WHERE (package_status.base_purl, package_status.version, package_status.latest_version,
		       package_status.outdated, package_status.versions_behind, package_status.published_at,
		       package_status.latest_published_at)
		      IS DISTINCT FROM
		      (EXCLUDED.base_purl, EXCLUDED.version, EXCLUDED.latest_version, EXCLUDED.outdated,
		       EXCLUDED.versions_behind, EXCLUDED.published_at, EXCLUDED.latest_published_at)`
	written := 0
	for chunk := range slices.Chunk(upserts, statusBatch) {
		n := len(chunk)
		purls, bases, versions, latest := make([]string, n), make([]string, n), make([]string, n), make([]string, n)
		outdated, behind := make([]bool, n), make([]int32, n)
		published, latestPublished := make([]*time.Time, n), make([]*time.Time, n)
		for i, s := range chunk {
			purls[i], bases[i], versions[i], latest[i] = s.Purl, s.Base, s.Version, s.Latest
			outdated[i], published[i], latestPublished[i] = s.Outdated, s.Published, s.LatestPublished
			if s.VersionsBehind != nil {
				behind[i] = int32(*s.VersionsBehind)
			}
		}
		tag, err := r.db.Exec(ctx, q, purls, bases, versions, latest, outdated, behind, published, latestPublished)
		if err != nil {
			return written, fmt.Errorf("save package status: %w", err)
		}
		written += int(tag.RowsAffected())
	}
	if len(deletes) > 0 {
		tag, err := r.db.Exec(ctx, `DELETE FROM package_status WHERE purl = ANY($1)`, deletes)
		if err != nil {
			return written, fmt.Errorf("delete package status: %w", err)
		}
		written += int(tag.RowsAffected())
	}
	return written, nil
}

// Info reports the freshness of each purl (keyed by the input string;
// qualifiers and subpath are ignored). Purls that can't be parsed, have no
// version, or whose package metadata was never successfully fetched are
// absent — unknown is never "up to date". It evaluates the cached metadata
// with the same rules that fill package_status, so the two always agree.
func (r *Repository) Info(ctx context.Context, purls []string) (map[string]Info, error) {
	parsed := map[string]PURL{}
	var bases []string
	for _, s := range purls {
		p, err := ParsePURL(s)
		if err != nil || p.Version == "" || !Supported(p.Type) {
			continue
		}
		parsed[s] = p
		bases = append(bases, p.Base())
	}
	out := map[string]Info{}
	if len(bases) == 0 {
		return out, nil
	}
	metas, err := r.Metas(ctx, bases)
	if err != nil {
		return nil, err
	}
	for s, p := range parsed {
		m, ok := metas[p.Base()]
		if !ok {
			continue
		}
		if info, ok := evaluate(p.Type, m, p.Version); ok {
			out[s] = info
		}
	}
	return out, nil
}

// SbomFreshness counts one snapshot's components by outdated state.
func (r *Repository) SbomFreshness(ctx context.Context, sbomID string) (Freshness, error) {
	const q = `
		SELECT count(c.id),
		       count(c.id) FILTER (WHERE ps.outdated),
		       count(c.id) FILTER (WHERE NOT ps.outdated),
		       count(c.id) FILTER (WHERE ps.purl IS NULL)
		FROM sboms s
		LEFT JOIN sbom_components c ON c.sbom_id = s.id
		LEFT JOIN package_status ps ON ps.purl = c.purl
		WHERE s.id = $1
		GROUP BY s.id`
	var f Freshness
	err := r.db.QueryRow(ctx, q, sbomID).Scan(&f.Total, &f.Outdated, &f.UpToDate, &f.Unknown)
	if errors.Is(err, pgx.ErrNoRows) {
		return Freshness{}, ErrSbomNotFound
	}
	if err != nil {
		return Freshness{}, fmt.Errorf("sbom freshness: %w", err)
	}
	return f, nil
}
