package vulnmatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
)

// Advisory is a private (internal) advisory in OSV's shape: which packages and
// versions it affects (affected[] with ranges and/or versions), evaluated by
// the same algorithm as the OSV mirror. Packages are named by OSV ecosystem +
// name, or by purl (without version) for internal package types.
type Advisory struct {
	ID         string          `json:"id"`
	Summary    string          `json:"summary"`
	Details    string          `json:"details"`
	Severity   domain.Severity `json:"severity"`
	CVSSVector string          `json:"cvss_vector"`
	Aliases    []string        `json:"aliases"`
	Affected   []Affected      `json:"affected"`
	Published  time.Time       `json:"published"`
	Withdrawn  *time.Time      `json:"withdrawn"`
	CreatedBy  *string         `json:"created_by"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

// Errors returned by the advisory repository.
var (
	ErrAdvisoryNotFound  = errors.New("advisory not found")
	ErrAdvisoryDuplicate = errors.New("an advisory with this id already exists")
)

var advisoryIDRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9._:-]{1,60}$`)

// Validate checks an advisory before it is stored and normalizes it. A
// malformed range would silently match nothing (or everything), so the OSV
// schema's rules are enforced: each event sets exactly one field, every range
// has an introduced event, and fixed / last_affected don't mix.
func (a *Advisory) Validate() error {
	a.Summary = strings.TrimSpace(a.Summary)
	if a.Summary == "" {
		return errors.New("summary is required")
	}
	if a.ID != "" && !advisoryIDRe.MatchString(a.ID) {
		return errors.New("id must look like PREFIX-…, e.g. XILA-2026-0001")
	}
	if !a.Severity.Valid() {
		return fmt.Errorf("severity must be one of critical, high, medium, low, info")
	}
	if a.Aliases == nil {
		a.Aliases = []string{}
	}
	for i, al := range a.Aliases {
		a.Aliases[i] = strings.TrimSpace(al)
		if a.Aliases[i] == "" {
			return errors.New("aliases must not be empty")
		}
	}
	if len(a.Affected) == 0 {
		return errors.New("at least one affected package is required")
	}
	for i := range a.Affected {
		if err := a.Affected[i].validate(); err != nil {
			return fmt.Errorf("affected[%d]: %w", i, err)
		}
	}
	return nil
}

func (a *Affected) validate() error {
	p := &a.Package
	p.Ecosystem, p.Name, p.Purl = strings.TrimSpace(p.Ecosystem), strings.TrimSpace(p.Name), strings.TrimSpace(p.Purl)
	switch {
	case p.Ecosystem != "" && p.Name != "":
		if !osvEcosystemNames[p.Ecosystem] {
			return fmt.Errorf("unknown ecosystem %q (use an OSV ecosystem name such as npm, PyPI, Maven, Go — or a purl)", p.Ecosystem)
		}
	case p.Purl != "":
		pp, ok := parsePurl(p.Purl)
		if !ok {
			return fmt.Errorf("invalid purl %q", p.Purl)
		}
		if pp.Version != "" {
			return errors.New("package purl must not carry a version; put versions in ranges or versions")
		}
	default:
		return errors.New("package needs ecosystem + name, or a purl")
	}
	if len(a.Ranges) == 0 && len(a.Versions) == 0 {
		return errors.New("give at least one range or an explicit versions list")
	}
	if a.Versions == nil {
		a.Versions = []string{}
	}
	for i, r := range a.Ranges {
		switch strings.ToUpper(r.Type) {
		case "SEMVER", "ECOSYSTEM", "GIT":
			a.Ranges[i].Type = strings.ToUpper(r.Type)
		default:
			return fmt.Errorf("ranges[%d]: type must be SEMVER, ECOSYSTEM or GIT", i)
		}
		introduced, fixed, last := false, false, false
		for _, e := range r.Events {
			n := 0
			for _, s := range []string{e.Introduced, e.Fixed, e.LastAffected, e.Limit} {
				if s != "" {
					n++
				}
			}
			if n != 1 {
				return fmt.Errorf("ranges[%d]: each event sets exactly one of introduced, fixed, last_affected, limit", i)
			}
			introduced = introduced || e.Introduced != ""
			fixed = fixed || e.Fixed != ""
			last = last || e.LastAffected != ""
		}
		if !introduced {
			return fmt.Errorf("ranges[%d]: needs an introduced event (\"0\" = from the first version)", i)
		}
		if fixed && last {
			return fmt.Errorf("ranges[%d]: use fixed or last_affected, not both", i)
		}
	}
	return nil
}

// packages are the match keys of an advisory's affected packages.
func (a Advisory) packages() []string {
	keys := []string{}
	for _, aff := range a.Affected {
		if k := aff.key(); k != "" && !slices.Contains(keys, k) {
			keys = append(keys, k)
		}
	}
	return keys
}

// AdvisoryRepository stores private advisories (private_advisories).
type AdvisoryRepository struct {
	db *pgxpool.Pool
	// urlBase prefixes advisory links on findings (PUBLIC_URL; "" = relative).
	urlBase string
}

// NewAdvisoryRepository constructs the store. publicURL makes the links on
// findings absolute.
func NewAdvisoryRepository(db *pgxpool.Pool, publicURL string) *AdvisoryRepository {
	return &AdvisoryRepository{db: db, urlBase: strings.TrimRight(publicURL, "/")}
}

const advisoryColumns = `id, summary, details, severity, cvss_vector, aliases, affected,
	published, withdrawn, created_by, created_at, updated_at`

func scanAdvisory(row pgx.Row) (Advisory, error) {
	var a Advisory
	err := row.Scan(&a.ID, &a.Summary, &a.Details, &a.Severity, &a.CVSSVector, &a.Aliases, &a.Affected,
		&a.Published, &a.Withdrawn, &a.CreatedBy, &a.CreatedAt, &a.UpdatedAt)
	if a.Affected == nil {
		a.Affected = []Affected{}
	}
	return a, err
}

// AdvisoryFilter narrows the advisory list.
type AdvisoryFilter struct {
	Query            string // id / alias / summary / package substring
	IncludeWithdrawn bool
	Limit, Offset    int
}

// List returns advisories, newest first.
func (r *AdvisoryRepository) List(ctx context.Context, f AdvisoryFilter) ([]Advisory, error) {
	const q = `SELECT ` + advisoryColumns + ` FROM private_advisories
		WHERE ($1 OR withdrawn IS NULL)
		  AND ($2 = '' OR id ILIKE '%' || $2 || '%' OR summary ILIKE '%' || $2 || '%'
		       OR array_to_string(aliases, ' ') ILIKE '%' || $2 || '%'
		       OR array_to_string(packages, ' ') ILIKE '%' || $2 || '%')
		ORDER BY published DESC, id DESC LIMIT $3 OFFSET $4`
	rows, err := r.db.Query(ctx, q, f.IncludeWithdrawn, strings.TrimSpace(f.Query), f.Limit, f.Offset)
	if err != nil {
		return nil, fmt.Errorf("list advisories: %w", err)
	}
	defer rows.Close()
	out := []Advisory{}
	for rows.Next() {
		a, err := scanAdvisory(rows)
		if err != nil {
			return nil, fmt.Errorf("scan advisory: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Get returns one advisory.
func (r *AdvisoryRepository) Get(ctx context.Context, id string) (Advisory, error) {
	a, err := scanAdvisory(r.db.QueryRow(ctx, `SELECT `+advisoryColumns+` FROM private_advisories WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Advisory{}, ErrAdvisoryNotFound
	}
	if err != nil {
		return Advisory{}, fmt.Errorf("get advisory: %w", err)
	}
	return a, nil
}

// Create stores a new advisory. Without an id it is numbered
// XILA-<year>-<NNNN>, the next free number of the year.
func (r *AdvisoryRepository) Create(ctx context.Context, a Advisory, userID *string) (Advisory, error) {
	affected, err := json.Marshal(a.Affected)
	if err != nil {
		return Advisory{}, err
	}
	published := a.Published
	if published.IsZero() {
		published = time.Now()
	}
	const q = `
		INSERT INTO private_advisories (id, summary, details, severity, cvss_vector, aliases, affected,
			packages, published, withdrawn, created_by)
		VALUES (
			COALESCE(NULLIF($1, ''), (
				SELECT 'XILA-' || to_char(now(), 'YYYY') || '-' ||
					lpad((COALESCE(max(substring(id FROM '^XILA-\d{4}-(\d+)$')::int), 0) + 1)::text, 4, '0')
				FROM private_advisories WHERE id LIKE 'XILA-' || to_char(now(), 'YYYY') || '-%')),
			$2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING ` + advisoryColumns
	for attempt := 0; ; attempt++ {
		out, err := scanAdvisory(r.db.QueryRow(ctx, q, a.ID, a.Summary, a.Details, a.Severity, a.CVSSVector,
			nonNil(a.Aliases), affected, a.packages(), published, a.Withdrawn, userID))
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			// Two creates raced for the same generated number: take the next one.
			if a.ID == "" && attempt < 3 {
				continue
			}
			return Advisory{}, ErrAdvisoryDuplicate
		}
		if err != nil {
			return Advisory{}, fmt.Errorf("create advisory: %w", err)
		}
		return out, nil
	}
}

// Update replaces an advisory's content (its id and authorship stay).
func (r *AdvisoryRepository) Update(ctx context.Context, a Advisory) (Advisory, error) {
	affected, err := json.Marshal(a.Affected)
	if err != nil {
		return Advisory{}, err
	}
	const q = `UPDATE private_advisories SET summary = $2, details = $3, severity = $4, cvss_vector = $5,
			aliases = $6, affected = $7, packages = $8, published = COALESCE($9, published),
			withdrawn = $10, updated_at = now()
		WHERE id = $1 RETURNING ` + advisoryColumns
	var published *time.Time
	if !a.Published.IsZero() {
		published = &a.Published
	}
	out, err := scanAdvisory(r.db.QueryRow(ctx, q, a.ID, a.Summary, a.Details, a.Severity, a.CVSSVector,
		nonNil(a.Aliases), affected, a.packages(), published, a.Withdrawn))
	if errors.Is(err, pgx.ErrNoRows) {
		return Advisory{}, ErrAdvisoryNotFound
	}
	if err != nil {
		return Advisory{}, fmt.Errorf("update advisory: %w", err)
	}
	return out, nil
}

// Upsert creates or replaces an advisory by id (OSV import).
func (r *AdvisoryRepository) Upsert(ctx context.Context, a Advisory, userID *string) (created bool, err error) {
	affected, err := json.Marshal(a.Affected)
	if err != nil {
		return false, err
	}
	published := a.Published
	if published.IsZero() {
		published = time.Now()
	}
	const q = `
		INSERT INTO private_advisories (id, summary, details, severity, cvss_vector, aliases, affected,
			packages, published, withdrawn, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		ON CONFLICT (id) DO UPDATE SET summary = EXCLUDED.summary, details = EXCLUDED.details,
			severity = EXCLUDED.severity, cvss_vector = EXCLUDED.cvss_vector, aliases = EXCLUDED.aliases,
			affected = EXCLUDED.affected, packages = EXCLUDED.packages, published = EXCLUDED.published,
			withdrawn = EXCLUDED.withdrawn, updated_at = now()
		RETURNING (xmax = 0)`
	err = r.db.QueryRow(ctx, q, a.ID, a.Summary, a.Details, a.Severity, a.CVSSVector, nonNil(a.Aliases), affected,
		a.packages(), published, a.Withdrawn, userID).Scan(&created)
	if err != nil {
		return false, fmt.Errorf("upsert advisory: %w", err)
	}
	return created, nil
}

// Delete removes an advisory. (Withdrawing keeps the record; both stop it
// matching, so its findings auto-close on the next match.)
func (r *AdvisoryRepository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM private_advisories WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete advisory: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAdvisoryNotFound
	}
	return nil
}

// Lookup returns the published, non-withdrawn advisories naming any of keys.
func (r *AdvisoryRepository) Lookup(ctx context.Context, keys []string) ([]storedAdvisory, error) {
	const q = `SELECT id, aliases, summary, details, severity, packages, affected
		FROM private_advisories
		WHERE packages && $1::text[] AND withdrawn IS NULL AND published <= now()`
	var out []storedAdvisory
	for start := 0; start < len(keys); start += lookupBatch {
		rows, err := r.db.Query(ctx, q, keys[start:min(start+lookupBatch, len(keys))])
		if err != nil {
			return nil, fmt.Errorf("lookup private advisories: %w", err)
		}
		for rows.Next() {
			var a storedAdvisory
			if err := rows.Scan(&a.ID, &a.Aliases, &a.Summary, &a.Details, &a.Severity, &a.Packages, &a.Affected); err != nil {
				rows.Close()
				return nil, fmt.Errorf("scan private advisory: %w", err)
			}
			a.URL = r.urlBase + "/advisories/" + a.ID
			out = append(out, a)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("lookup private advisories: %w", err)
		}
	}
	return out, nil
}

// NewPrivateSource is the private source: the internal advisory database.
func NewPrivateSource(repo *AdvisoryRepository) Source { return storedSource{store: repo} }

// AdvisoryFromOSV converts an OSV JSON document into a private advisory. The
// qualitative severity comes from database_specific.severity (GHSA style),
// defaulting to medium; the CVSS v3/v4 vector is kept as given.
func AdvisoryFromOSV(b []byte) (Advisory, error) {
	var rec osvRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return Advisory{}, fmt.Errorf("not an OSV document: %w", err)
	}
	if rec.ID == "" {
		return Advisory{}, errors.New("OSV document has no id")
	}
	sev := severityFrom(rec.qualitativeSeverity())
	if s := domain.Severity(strings.ToLower(rec.qualitativeSeverity())); s.Valid() {
		sev = s
	}
	if sev == "" {
		sev = domain.SeverityMedium
	}
	a := Advisory{
		ID: rec.ID, Summary: rec.Summary, Details: rec.Details, Severity: sev,
		CVSSVector: rec.cvssVector(), Aliases: rec.Aliases, Affected: rec.Affected,
		Withdrawn: rec.Withdrawn,
	}
	if a.Summary == "" {
		a.Summary = firstLine(rec.Details)
	}
	if rec.Published != nil {
		a.Published = *rec.Published
	}
	return a, nil
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
