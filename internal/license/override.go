package license

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrOverrideNotFound: no license override with that id in that project.
var ErrOverrideNotFound = errors.New("license override not found")

// Override is a curated, concluded SPDX expression for one package
// (optionally one version range) in one project, applied at ingest instead
// of the SBOM's own resolved license (M13 13.12).
type Override struct {
	ID           string    `json:"id"`
	ProjectID    string    `json:"project_id"`
	Purl         string    `json:"purl"`          // base purl: no version, qualifiers or subpath
	VersionRange string    `json:"version_range"` // "" = every version
	License      string    `json:"license"`
	Comment      string    `json:"comment"`
	CreatedBy    *string   `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// OverrideInput is the create/update request body.
type OverrideInput struct {
	Purl         string `json:"purl"`
	VersionRange string `json:"version_range"`
	License      string `json:"license"`
	Comment      string `json:"comment"`
}

// Validate normalizes and checks an OverrideInput: a purl, a well-formed SPDX
// expression (checked with the same parser the rest of the package uses), and
// (if given) a parseable version range.
func (in *OverrideInput) Validate() error {
	in.Purl = BasePurl(strings.TrimSpace(in.Purl))
	if in.Purl == "" {
		return errors.New("purl is required")
	}
	in.License = strings.TrimSpace(in.License)
	if in.License == "" {
		return errors.New("license is required")
	}
	if _, err := ParseExpression(in.License); err != nil {
		return fmt.Errorf("license: %w", err)
	}
	in.VersionRange = strings.TrimSpace(in.VersionRange)
	if in.VersionRange != "" {
		if _, err := parseOverrideRange(in.VersionRange); err != nil {
			return err
		}
	}
	return nil
}

// BasePurl strips a purl down to its package coordinates: no version,
// qualifiers or subpath, the identity a license override is keyed on.
func BasePurl(purl string) string {
	if i := strings.IndexAny(purl, "@?#"); i >= 0 {
		return purl[:i]
	}
	return purl
}

const overrideColumns = `id, project_id, purl, version_range, license, comment, created_by, created_at, updated_at`

func scanOverride(row pgx.Row) (Override, error) {
	var o Override
	err := row.Scan(&o.ID, &o.ProjectID, &o.Purl, &o.VersionRange, &o.License, &o.Comment, &o.CreatedBy, &o.CreatedAt, &o.UpdatedAt)
	return o, err
}

// OverrideRepository stores a project's license overrides.
type OverrideRepository struct {
	db *pgxpool.Pool
}

func NewOverrideRepository(db *pgxpool.Pool) *OverrideRepository { return &OverrideRepository{db: db} }

// List returns a project's overrides, newest first.
func (r *OverrideRepository) List(ctx context.Context, projectID string) ([]Override, error) {
	rows, err := r.db.Query(ctx, `SELECT `+overrideColumns+` FROM license_overrides WHERE project_id = $1 ORDER BY created_at DESC`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list license overrides: %w", err)
	}
	defer rows.Close()
	out := []Override{}
	for rows.Next() {
		o, err := scanOverride(rows)
		if err != nil {
			return nil, fmt.Errorf("scan license override: %w", err)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ListAll returns every project's overrides, for building a Matcher once per
// ingest or reapply pass.
func (r *OverrideRepository) ListAll(ctx context.Context) ([]Override, error) {
	rows, err := r.db.Query(ctx, `SELECT `+overrideColumns+` FROM license_overrides ORDER BY project_id, created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list all license overrides: %w", err)
	}
	defer rows.Close()
	out := []Override{}
	for rows.Next() {
		o, err := scanOverride(rows)
		if err != nil {
			return nil, fmt.Errorf("scan license override: %w", err)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// Get returns one override, scoped to projectID so a caller can't reach
// another project's row by guessing its id.
func (r *OverrideRepository) Get(ctx context.Context, projectID, id string) (Override, error) {
	o, err := scanOverride(r.db.QueryRow(ctx, `SELECT `+overrideColumns+` FROM license_overrides WHERE id = $1 AND project_id = $2`, id, projectID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Override{}, ErrOverrideNotFound
	}
	return o, err
}

// Create stores a new override. createdBy may be "".
func (r *OverrideRepository) Create(ctx context.Context, projectID string, in OverrideInput, createdBy string) (Override, error) {
	var createdByArg any
	if createdBy != "" {
		createdByArg = createdBy
	}
	return scanOverride(r.db.QueryRow(ctx, `
		INSERT INTO license_overrides (project_id, purl, version_range, license, comment, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING `+overrideColumns,
		projectID, in.Purl, in.VersionRange, in.License, in.Comment, createdByArg))
}

// Update replaces an override's fields.
func (r *OverrideRepository) Update(ctx context.Context, projectID, id string, in OverrideInput) (Override, error) {
	o, err := scanOverride(r.db.QueryRow(ctx, `
		UPDATE license_overrides SET purl = $3, version_range = $4, license = $5, comment = $6, updated_at = now()
		WHERE id = $1 AND project_id = $2
		RETURNING `+overrideColumns,
		id, projectID, in.Purl, in.VersionRange, in.License, in.Comment))
	if errors.Is(err, pgx.ErrNoRows) {
		return Override{}, ErrOverrideNotFound
	}
	return o, err
}

// Delete removes an override.
func (r *OverrideRepository) Delete(ctx context.Context, projectID, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM license_overrides WHERE id = $1 AND project_id = $2`, id, projectID)
	if err != nil {
		return fmt.Errorf("delete license override: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrOverrideNotFound
	}
	return nil
}

// --- applying overrides at ingest ---

// overrideRangePart is one comparator of a version range ("op", "version").
type overrideRangePart struct {
	op      string
	version string
}

var overrideRangeOps = []string{">=", "<=", "!=", "==", ">", "<", "="}

func parseOverrideRange(s string) ([]overrideRangePart, error) {
	var out []overrideRangePart
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		op := ""
		for _, o := range overrideRangeOps {
			if strings.HasPrefix(part, o) {
				op = o
				break
			}
		}
		v := strings.TrimSpace(strings.TrimPrefix(part, op))
		if op == "" || v == "" {
			return nil, fmt.Errorf("bad version range %q (use e.g. \">=1.2.0, <2.0.0\")", s)
		}
		out = append(out, overrideRangePart{op, v})
	}
	return out, nil
}

// VersionComparator compares two version strings the way the ecosystem that
// owns version does (sbom.CompareVersions); injected so this package doesn't
// import sbom (which would import license, a cycle).
type VersionComparator func(a, b string) int

func rangeContains(cmp VersionComparator, parts []overrideRangePart, v string) bool {
	for _, p := range parts {
		c := cmp(v, p.version)
		var ok bool
		switch p.op {
		case ">=":
			ok = c >= 0
		case "<=":
			ok = c <= 0
		case ">":
			ok = c > 0
		case "<":
			ok = c < 0
		case "==", "=":
			ok = c == 0
		case "!=":
			ok = c != 0
		}
		if !ok {
			return false
		}
	}
	return true
}

// Matcher resolves (project, purl, version) to the override that applies, if
// any, loading a project's overrides once and reusing them for every
// component of that project's snapshot.
type Matcher struct {
	byProject map[string][]Override
	cmp       VersionComparator
}

// NewMatcher builds a Matcher over every project's overrides (loaded once per
// ingest run) with the given version comparator.
func NewMatcher(overrides []Override, cmp VersionComparator) *Matcher {
	m := &Matcher{byProject: map[string][]Override{}, cmp: cmp}
	for _, o := range overrides {
		m.byProject[o.ProjectID] = append(m.byProject[o.ProjectID], o)
	}
	return m
}

// Match returns the override applying to purl@version in projectID, "" base
// purl matches, "" version matches any (nil, false when none apply). Parsed
// ranges that fail to parse (shouldn't happen: Validate already checked them)
// never match, rather than panicking or matching everything.
func (m *Matcher) Match(projectID, purl, version string) (Override, bool) {
	if m == nil {
		return Override{}, false
	}
	base := BasePurl(purl)
	for _, o := range m.byProject[projectID] {
		if o.Purl != base {
			continue
		}
		if o.VersionRange == "" {
			return o, true
		}
		parts, err := parseOverrideRange(o.VersionRange)
		if err != nil {
			continue
		}
		if rangeContains(m.cmp, parts, version) {
			return o, true
		}
	}
	return Override{}, false
}

// MatchLicense is Match flattened to primitives (the shape
// sbom.Service.WithLicenseOverrides consumes without importing this
// package's Override type), resolved through Resolve the same way an SBOM's
// own license terms are, so ids/categories/resolved follow the one rule.
func (m *Matcher) MatchLicense(projectID, purl, version string) (expr string, ids, categories []string, resolved bool, overrideID string, ok bool) {
	o, found := m.Match(projectID, purl, version)
	if !found {
		return "", nil, nil, false, "", false
	}
	expr, ids, categories, resolved = Resolve([]string{o.License})
	return expr, ids, categories, resolved, o.ID, true
}

// LicenseOverrideMatcher is Matcher's MatchLicense method, as an interface so
// callers (OverrideHandler, Reapplier) can be built in terms of it without
// requiring the concrete type; *Matcher satisfies it.
type LicenseOverrideMatcher interface {
	MatchLicense(projectID, purl, version string) (expr string, ids, categories []string, resolved bool, overrideID string, ok bool)
}
