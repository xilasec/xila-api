// Package component tracks which SBOM components are internal (first-party),
// by admin-defined patterns over a component's ecosystem, group (namespace)
// and name. Internal components are never sent to public registries
// (internal/pkgmeta) or public advisory sources (internal/vulnmatch): the
// flag is computed on sbom_components at ingest (sbom.InternalMatcher) and
// recomputed here whenever the patterns change.
package component

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PatternType is how GroupPattern/NamePattern are matched.
type PatternType string

// Supported pattern types.
const (
	PatternGlob  PatternType = "glob"
	PatternRegex PatternType = "regex"
)

// ErrNotFound is returned for an unknown pattern id.
var ErrNotFound = errors.New("component pattern not found")

// ValidationError is a pattern the API must reject (400).
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

func invalid(format string, args ...any) error {
	return &ValidationError{msg: fmt.Sprintf(format, args...)}
}

// Pattern is one admin-defined rule: a component whose ecosystem ("" = any),
// group and name match GroupPattern/NamePattern (each "" = matches anything)
// is internal.
type Pattern struct {
	ID           string      `json:"id"`
	Ecosystem    string      `json:"ecosystem"`
	GroupPattern string      `json:"group_pattern"`
	NamePattern  string      `json:"name_pattern"`
	PatternType  PatternType `json:"pattern_type"`
	CreatedAt    time.Time   `json:"created_at"`
	UpdatedAt    time.Time   `json:"updated_at"`
}

// Validate checks and normalizes p: at least one of GroupPattern/NamePattern
// is required, and a regex pattern must compile.
func (p *Pattern) Validate() error {
	p.Ecosystem = strings.ToLower(strings.TrimSpace(p.Ecosystem))
	p.GroupPattern = strings.TrimSpace(p.GroupPattern)
	p.NamePattern = strings.TrimSpace(p.NamePattern)
	if p.PatternType == "" {
		p.PatternType = PatternGlob
	}
	if p.PatternType != PatternGlob && p.PatternType != PatternRegex {
		return invalid("pattern_type must be glob or regex")
	}
	if p.GroupPattern == "" && p.NamePattern == "" {
		return invalid("group_pattern or name_pattern is required")
	}
	if _, err := compileOne(p.PatternType, p.GroupPattern); err != nil {
		return invalid("group_pattern: %v", err)
	}
	if _, err := compileOne(p.PatternType, p.NamePattern); err != nil {
		return invalid("name_pattern: %v", err)
	}
	return nil
}

// Repository stores component patterns (component_patterns).
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs the store.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

const columns = `id, ecosystem, group_pattern, name_pattern, pattern_type, created_at, updated_at`

func scan(row pgx.Row) (Pattern, error) {
	var p Pattern
	err := row.Scan(&p.ID, &p.Ecosystem, &p.GroupPattern, &p.NamePattern, &p.PatternType, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

// List returns every pattern.
func (r *Repository) List(ctx context.Context) ([]Pattern, error) {
	rows, err := r.db.Query(ctx, `SELECT `+columns+` FROM component_patterns ORDER BY created_at, id`)
	if err != nil {
		return nil, fmt.Errorf("list component patterns: %w", err)
	}
	defer rows.Close()
	out := []Pattern{}
	for rows.Next() {
		p, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("scan component pattern: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Get returns one pattern.
func (r *Repository) Get(ctx context.Context, id string) (Pattern, error) {
	p, err := scan(r.db.QueryRow(ctx, `SELECT `+columns+` FROM component_patterns WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Pattern{}, ErrNotFound
	}
	if err != nil {
		return Pattern{}, fmt.Errorf("get component pattern: %w", err)
	}
	return p, nil
}

// Create stores a validated pattern.
func (r *Repository) Create(ctx context.Context, p Pattern, actor *string) (Pattern, error) {
	out, err := scan(r.db.QueryRow(ctx, `
		INSERT INTO component_patterns (ecosystem, group_pattern, name_pattern, pattern_type, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING `+columns,
		p.Ecosystem, p.GroupPattern, p.NamePattern, p.PatternType, actor))
	if err != nil {
		return Pattern{}, fmt.Errorf("create component pattern: %w", err)
	}
	return out, nil
}

// Update replaces a validated pattern's fields.
func (r *Repository) Update(ctx context.Context, p Pattern) (Pattern, error) {
	out, err := scan(r.db.QueryRow(ctx, `
		UPDATE component_patterns SET ecosystem = $2, group_pattern = $3, name_pattern = $4, pattern_type = $5, updated_at = now()
		WHERE id = $1
		RETURNING `+columns,
		p.ID, p.Ecosystem, p.GroupPattern, p.NamePattern, p.PatternType))
	if errors.Is(err, pgx.ErrNoRows) {
		return Pattern{}, ErrNotFound
	}
	if err != nil {
		return Pattern{}, fmt.Errorf("update component pattern: %w", err)
	}
	return out, nil
}

// Delete removes a pattern.
func (r *Repository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM component_patterns WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete component pattern: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// recomputeBatch bounds how much SBOM inventory Recompute scans per query;
// it is a straight SELECT DISTINCT, so this only guards pathological tables.
const recomputeBatch = 200_000

// Recompute re-evaluates match against every distinct (ecosystem, group,
// name) combination currently in sbom_components and writes the ones whose
// computed flag changed. Called after patterns change; cheap when nothing
// moved (the UPDATE is a no-op WHERE internal IS DISTINCT FROM the new value).
func (r *Repository) Recompute(ctx context.Context, match func(ecosystem, group, name string) bool) (int, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT purl_ecosystem(purl), "group", name FROM sbom_components LIMIT $1`, recomputeBatch)
	if err != nil {
		return 0, fmt.Errorf("list component identities: %w", err)
	}
	type triple struct{ eco, group, name string }
	var triples []triple
	for rows.Next() {
		var t triple
		if err := rows.Scan(&t.eco, &t.group, &t.name); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan component identity: %w", err)
		}
		triples = append(triples, t)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("list component identities: %w", err)
	}
	total := 0
	for _, t := range triples {
		want := match(t.eco, t.group, t.name)
		tag, err := r.db.Exec(ctx, `
			UPDATE sbom_components SET internal = $4
			WHERE "group" = $2 AND name = $3 AND purl_ecosystem(purl) = $1 AND internal IS DISTINCT FROM $4`,
			t.eco, t.group, t.name, want)
		if err != nil {
			return total, fmt.Errorf("recompute internal flag: %w", err)
		}
		total += int(tag.RowsAffected())
	}
	return total, nil
}
