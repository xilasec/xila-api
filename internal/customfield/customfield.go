// Package customfield implements typed custom fields: admin-defined fields
// (text, number, date, enum, user) on projects, assets and findings.
//
// Values are stored in a jsonb `custom` column on each entity (key → JSON
// scalar) and validated against the definitions on every write here — the
// type, enum membership, and, for a user field, that the user can see the
// entity. Readers (lists, exports, CEL documents) read the column with the
// row; ParseFilters/AppendSQL is the one ?cf.<key>= filter every list shares.
package customfield

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Entity is the kind of record a field is defined on.
type Entity string

// Entities.
const (
	EntityProject Entity = "project"
	EntityAsset   Entity = "asset"
	EntityFinding Entity = "finding"
)

// Valid reports whether e is a known entity.
func (e Entity) Valid() bool {
	return e == EntityProject || e == EntityAsset || e == EntityFinding
}

// Type is a field's value type.
type Type string

// Types. A value is stored as: text → string, number → JSON number,
// date → "YYYY-MM-DD", enum → one of the options, user → a user id.
const (
	TypeText   Type = "text"
	TypeNumber Type = "number"
	TypeDate   Type = "date"
	TypeEnum   Type = "enum"
	TypeUser   Type = "user"
)

// Valid reports whether t is a known type.
func (t Type) Valid() bool {
	switch t {
	case TypeText, TypeNumber, TypeDate, TypeEnum, TypeUser:
		return true
	}
	return false
}

// Limits.
const (
	MaxTextLength = 1000
	MaxOptions    = 100
	maxOption     = 100
	maxLabel      = 100
)

// Domain errors.
var (
	ErrNotFound       = errors.New("custom field not found")
	ErrDuplicate      = errors.New("a field with this key already exists on this entity")
	ErrNoOrg          = errors.New("organization not found")
	ErrEntityNotFound = errors.New("not found")
)

// ValidationError is a bad definition or value: the caller's fault (400).
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

func invalid(format string, args ...any) error {
	return &ValidationError{msg: fmt.Sprintf(format, args...)}
}

// Definition is one admin-defined field. Entity, Key and Type are fixed once
// created (stored values and expressions depend on them); the rest is editable.
type Definition struct {
	ID       string   `json:"id"`
	Entity   Entity   `json:"entity"`
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	Type     Type     `json:"type"`
	Options  []string `json:"options"`
	Required bool     `json:"required"`
	// OrgID scopes the field to one organization's entities; nil = all.
	OrgID     *string   `json:"org_id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// keyPattern keeps a key a plain CEL identifier (finding.custom.<key>) and a
// safe query parameter name (?cf.<key>=).
var keyPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,39}$`)

// celReserved can't be selected as finding.custom.<key>.
var celReserved = []string{"true", "false", "null", "in", "as", "break", "const", "continue", "else",
	"for", "function", "if", "import", "let", "loop", "package", "namespace", "return", "var", "void", "while"}

// ValidKey reports whether k is an acceptable field key.
func ValidKey(k string) bool { return keyPattern.MatchString(k) && !slices.Contains(celReserved, k) }

// Validate checks and normalizes a definition before it is stored.
func (d *Definition) Validate() error {
	if !d.Entity.Valid() {
		return invalid("entity must be project, asset or finding")
	}
	if !ValidKey(d.Key) {
		return invalid("key must be 1–40 lowercase letters, digits or _, start with a letter, and not be a reserved word")
	}
	d.Label = strings.TrimSpace(d.Label)
	if d.Label == "" || len([]rune(d.Label)) > maxLabel {
		return invalid("label is required (at most %d characters)", maxLabel)
	}
	if !d.Type.Valid() {
		return invalid("type must be text, number, date, enum or user")
	}
	opts := []string{}
	for _, o := range d.Options {
		o = strings.TrimSpace(o)
		if o == "" || len([]rune(o)) > maxOption {
			return invalid("options are 1–%d characters", maxOption)
		}
		if !slices.Contains(opts, o) {
			opts = append(opts, o)
		}
	}
	d.Options = opts
	switch {
	case d.Type == TypeEnum && len(opts) == 0:
		return invalid("an enum field needs at least one option")
	case d.Type != TypeEnum && len(opts) > 0:
		return invalid("only an enum field has options")
	case len(opts) > MaxOptions:
		return invalid("at most %d options", MaxOptions)
	}
	if d.OrgID != nil && uuid.Validate(*d.OrgID) != nil {
		return invalid("org_id must be an organization id")
	}
	return nil
}

// Normalize checks one value against the field's type and returns it as it is
// stored. nil (and an empty text) means "unset". A user value is only checked
// for shape here; who may be named is the Service's job.
func (d Definition) Normalize(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	switch d.Type {
	case TypeNumber:
		n, ok := v.(float64)
		if !ok || math.IsNaN(n) || math.IsInf(n, 0) {
			return nil, invalid("%s must be a number", d.Key)
		}
		return n, nil
	case TypeText:
		s, ok := v.(string)
		if !ok {
			return nil, invalid("%s must be text", d.Key)
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, nil
		}
		if len([]rune(s)) > MaxTextLength {
			return nil, invalid("%s is at most %d characters", d.Key, MaxTextLength)
		}
		return s, nil
	case TypeDate:
		s, ok := v.(string)
		if !ok {
			return nil, invalid("%s must be a date (YYYY-MM-DD)", d.Key)
		}
		if _, err := time.Parse(time.DateOnly, s); err != nil {
			return nil, invalid("%s must be a date (YYYY-MM-DD)", d.Key)
		}
		return s, nil
	case TypeEnum:
		s, ok := v.(string)
		if !ok || !slices.Contains(d.Options, s) {
			return nil, invalid("%s must be one of: %s", d.Key, strings.Join(d.Options, ", "))
		}
		return s, nil
	case TypeUser:
		s, ok := v.(string)
		if !ok || uuid.Validate(s) != nil {
			return nil, invalid("%s must be a user id", d.Key)
		}
		return strings.ToLower(s), nil
	}
	return nil, invalid("%s has an unknown type", d.Key)
}

// Sample is a value of the field's type — what CEL schemas dry-run against.
func (d Definition) Sample() any {
	switch d.Type {
	case TypeNumber:
		return 1.0
	case TypeDate:
		return "2026-01-01"
	case TypeEnum:
		if len(d.Options) > 0 {
			return d.Options[0]
		}
	case TypeUser:
		return "00000000-0000-4000-8000-000000000000"
	}
	return "text"
}

// Samples maps every definition's key to a sample value.
func Samples(defs []Definition) map[string]any {
	out := make(map[string]any, len(defs))
	for _, d := range defs {
		out[d.Key] = d.Sample()
	}
	return out
}

// AppliesTo reports whether the field applies to an entity in orgID.
func (d Definition) AppliesTo(orgID string) bool { return d.OrgID == nil || *d.OrgID == orgID }

// Repository stores definitions and the per-entity values.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

const columns = `id, entity, key, label, type, options, required, org_id, created_at, updated_at`

func scan(row pgx.Row) (Definition, error) {
	var d Definition
	err := row.Scan(&d.ID, &d.Entity, &d.Key, &d.Label, &d.Type, &d.Options, &d.Required, &d.OrgID, &d.CreatedAt, &d.UpdatedAt)
	return d, err
}

func writeErr(err error, what string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return ErrDuplicate
		case "23503":
			return ErrNoOrg
		}
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return fmt.Errorf("%s custom field: %w", what, err)
}

// List returns the definitions of one entity ("" = all), in display order.
func (r *Repository) List(ctx context.Context, entity Entity) ([]Definition, error) {
	rows, err := r.db.Query(ctx, `SELECT `+columns+` FROM custom_field_definitions
		WHERE $1 = '' OR entity = $1 ORDER BY entity, created_at, key`, string(entity))
	if err != nil {
		return nil, fmt.Errorf("list custom fields: %w", err)
	}
	defer rows.Close()
	out := []Definition{}
	for rows.Next() {
		d, err := scan(rows)
		if err != nil {
			return nil, fmt.Errorf("scan custom field: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Get returns one definition.
func (r *Repository) Get(ctx context.Context, id string) (Definition, error) {
	d, err := scan(r.db.QueryRow(ctx, `SELECT `+columns+` FROM custom_field_definitions WHERE id = $1`, id))
	if err != nil {
		return Definition{}, writeErr(err, "get")
	}
	return d, nil
}

// Create stores a validated definition.
func (r *Repository) Create(ctx context.Context, d Definition) (Definition, error) {
	out, err := scan(r.db.QueryRow(ctx, `
		INSERT INTO custom_field_definitions (entity, key, label, type, options, required, org_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING `+columns,
		d.Entity, d.Key, d.Label, d.Type, d.Options, d.Required, d.OrgID))
	if err != nil {
		return Definition{}, writeErr(err, "create")
	}
	return out, nil
}

// Update replaces the editable parts (label, options, required, org scope).
func (r *Repository) Update(ctx context.Context, d Definition) (Definition, error) {
	out, err := scan(r.db.QueryRow(ctx, `
		UPDATE custom_field_definitions SET label = $2, options = $3, required = $4, org_id = $5, updated_at = now()
		WHERE id = $1 RETURNING `+columns, d.ID, d.Label, d.Options, d.Required, d.OrgID))
	if err != nil {
		return Definition{}, writeErr(err, "update")
	}
	return out, nil
}

// entityTable is the table holding an entity's values.
var entityTable = map[Entity]string{EntityProject: "projects", EntityAsset: "assets", EntityFinding: "findings"}

// Delete removes a definition and every value stored under it, in one
// transaction (a finding's removal is recorded in its history as actor).
func (r *Repository) Delete(ctx context.Context, id, actor string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	var entity Entity
	var key string
	if err := tx.QueryRow(ctx, `SELECT entity, key FROM custom_field_definitions WHERE id = $1 FOR UPDATE`, id).
		Scan(&entity, &key); err != nil {
		return writeErr(err, "delete")
	}
	if _, err := tx.Exec(ctx, `SELECT set_config('xila.actor', $1, true), set_config('xila.note', $2, true)`,
		actor, "custom field "+key+" deleted"); err != nil {
		return fmt.Errorf("set actor: %w", err)
	}
	// The table name comes from a fixed map, never from input.
	if _, err := tx.Exec(ctx, `UPDATE `+entityTable[entity]+` SET custom = custom - $1::text, updated_at = now()
		WHERE custom ? $1::text`, key); err != nil { // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- table name from a fixed map
		return fmt.Errorf("strip custom values: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM custom_field_definitions WHERE id = $1`, id); err != nil {
		return fmt.Errorf("delete custom field: %w", err)
	}
	return tx.Commit(ctx)
}

// Target is the entity a value write is for: its project (whose members a
// user field may name), its organization (which scoped fields apply) and its
// current values.
type Target struct {
	ProjectID string
	OrgID     string
	Custom    map[string]any
}

// targetSQL loads a Target per entity.
var targetSQL = map[Entity]string{
	EntityProject: `SELECT p.id, t.org_id, p.custom FROM projects p JOIN teams t ON t.id = p.team_id WHERE p.id = $1`,
	EntityAsset: `SELECT a.project_id, t.org_id, a.custom FROM assets a
		JOIN projects p ON p.id = a.project_id JOIN teams t ON t.id = p.team_id WHERE a.id = $1`,
	EntityFinding: `SELECT f.project_id, t.org_id, f.custom FROM findings f
		JOIN projects p ON p.id = f.project_id JOIN teams t ON t.id = p.team_id WHERE f.id = $1`,
}

// Target loads the entity a write is for.
func (r *Repository) Target(ctx context.Context, entity Entity, id string) (Target, error) {
	var t Target
	err := r.db.QueryRow(ctx, targetSQL[entity], id).Scan(&t.ProjectID, &t.OrgID, &t.Custom)
	if errors.Is(err, pgx.ErrNoRows) {
		return Target{}, ErrEntityNotFound
	}
	if err != nil {
		return Target{}, fmt.Errorf("load %s: %w", entity, err)
	}
	return t, nil
}

// OrgOfProject returns the organization a project belongs to.
func (r *Repository) OrgOfProject(ctx context.Context, projectID string) (string, error) {
	var org string
	err := r.db.QueryRow(ctx, `SELECT t.org_id FROM projects p JOIN teams t ON t.id = p.team_id WHERE p.id = $1`, projectID).Scan(&org)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrEntityNotFound
	}
	if err != nil {
		return "", fmt.Errorf("project org: %w", err)
	}
	return org, nil
}

// SetValues merges set into a project's or asset's values and drops unset
// (findings go through the finding repository, which records history).
func (r *Repository) SetValues(ctx context.Context, entity Entity, id string, set map[string]any, unset []string) (map[string]any, error) {
	if entity != EntityProject && entity != EntityAsset {
		return nil, fmt.Errorf("set values: unsupported entity %q", entity)
	}
	var out map[string]any
	// The table name comes from a fixed map, never from input.
	err := r.db.QueryRow(ctx, `UPDATE `+entityTable[entity]+` SET custom = (custom || $2::jsonb) - $3::text[],
		updated_at = now() WHERE id = $1 RETURNING custom`, id, set, unset).Scan(&out) // nosemgrep: go.lang.security.audit.database.string-formatted-query.string-formatted-query -- table name from a fixed map
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrEntityNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("set custom values: %w", err)
	}
	return out, nil
}
