// Package customparser implements no-code parsers (M12 12.4, DefectDojo Pro
// "Universal Parser" parity): an instance admin maps the fields of any CSV,
// JSON or XML report onto findings from the UI, with no Go code.
//
// internal/scanner.CustomParser (ValidateCustomDefinition + NewCustomParser)
// is the pure compiler + mapping engine; this package owns persistence
// (custom_parsers), admin HTTP (CRUD + a dry-run preview) and resolving a
// scanner name to a compiled parser for the upload path (service.go's
// Resolve), which internal/scan falls back to when no built-in parser
// matches.
package customparser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/scanner"
)

// Domain errors.
var (
	ErrNotFound  = errors.New("custom parser not found")
	ErrDuplicate = errors.New("a custom parser or built-in scanner already has this name")
)

// Definition is a stored no-code parser: the mapping (scanner.CustomDefinition)
// plus persistence metadata. Deleting a Definition never touches the findings
// its parser already created — they keep their scanner name as history, like
// removing support for a built-in tool would.
type Definition struct {
	ID string `json:"id"`
	scanner.CustomDefinition
	CreatedBy *string   `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Repository stores custom parser definitions.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

const defColumns = `id, name, category, format, record_selector, fields, created_by, created_at, updated_at`

func scanDefinition(row pgx.Row) (Definition, error) {
	var (
		d   Definition
		raw []byte
	)
	if err := row.Scan(&d.ID, &d.Name, &d.Category, &d.Format, &d.RecordSelector, &raw, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt); err != nil {
		return Definition{}, err
	}
	if err := json.Unmarshal(raw, &d.Fields); err != nil {
		return Definition{}, fmt.Errorf("decode custom parser fields: %w", err)
	}
	return d, nil
}

// List returns every custom parser, by name.
func (r *Repository) List(ctx context.Context) ([]Definition, error) {
	rows, err := r.db.Query(ctx, `SELECT `+defColumns+` FROM custom_parsers ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list custom parsers: %w", err)
	}
	defer rows.Close()
	out := []Definition{}
	for rows.Next() {
		d, err := scanDefinition(rows)
		if err != nil {
			return nil, fmt.Errorf("scan custom parser: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Get fetches a custom parser by id.
func (r *Repository) Get(ctx context.Context, id string) (Definition, error) {
	d, err := scanDefinition(r.db.QueryRow(ctx, `SELECT `+defColumns+` FROM custom_parsers WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Definition{}, ErrNotFound
	}
	if err != nil {
		return Definition{}, fmt.Errorf("get custom parser: %w", err)
	}
	return d, nil
}

// GetByName fetches a custom parser by its scanner name — the upload path's
// lookup (scan.Service falls back to this when no built-in parser matches).
func (r *Repository) GetByName(ctx context.Context, name string) (Definition, error) {
	d, err := scanDefinition(r.db.QueryRow(ctx, `SELECT `+defColumns+` FROM custom_parsers WHERE name = $1`, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return Definition{}, ErrNotFound
	}
	if err != nil {
		return Definition{}, fmt.Errorf("get custom parser by name: %w", err)
	}
	return d, nil
}

// Create stores a validated definition; actor ("" for none) is its author.
func (r *Repository) Create(ctx context.Context, d Definition, actor string) (Definition, error) {
	fields, err := json.Marshal(d.Fields)
	if err != nil {
		return Definition{}, fmt.Errorf("encode custom parser fields: %w", err)
	}
	var id string
	err = r.db.QueryRow(ctx, `
		INSERT INTO custom_parsers (name, category, format, record_selector, fields, created_by)
		VALUES ($1, $2, $3, $4, $5, NULLIF($6, '')::uuid) RETURNING id`,
		d.Name, d.Category, d.Format, d.RecordSelector, fields, actor).Scan(&id)
	if err != nil {
		return Definition{}, writeErr(err)
	}
	return r.Get(ctx, id)
}

// Update replaces a custom parser's mapping in place (same id, so findings it
// already created keep referencing the same scanner name).
func (r *Repository) Update(ctx context.Context, d Definition) (Definition, error) {
	fields, err := json.Marshal(d.Fields)
	if err != nil {
		return Definition{}, fmt.Errorf("encode custom parser fields: %w", err)
	}
	tag, err := r.db.Exec(ctx, `
		UPDATE custom_parsers SET name = $2, category = $3, format = $4, record_selector = $5, fields = $6, updated_at = now()
		WHERE id = $1`,
		d.ID, d.Name, d.Category, d.Format, d.RecordSelector, fields)
	if err == nil && tag.RowsAffected() == 0 {
		err = ErrNotFound
	}
	if err != nil {
		return Definition{}, writeErr(err)
	}
	return r.Get(ctx, d.ID)
}

// Delete removes a custom parser definition. Findings it already created keep
// their scanner name as history — the same as removing a built-in parser
// would leave its past findings alone.
func (r *Repository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM custom_parsers WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete custom parser: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func writeErr(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return ErrDuplicate
	}
	if errors.Is(err, ErrNotFound) {
		return err
	}
	return fmt.Errorf("write custom parser: %w", err)
}
