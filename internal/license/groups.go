package license

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	// ErrGroupNotFound is returned for a custom group id that doesn't exist.
	ErrGroupNotFound = errors.New("license group not found")
	// ErrInvalidGroupRef is returned for a ref that is neither a group id nor
	// category:<a ScanCode category>.
	ErrInvalidGroupRef = errors.New("invalid license group reference")
	// ErrDuplicateGroup is returned when a group name is taken.
	ErrDuplicateGroup = errors.New("license group name already exists")
)

// CategoryRefPrefix prefixes a built-in group's ref: "category:Copyleft".
const CategoryRefPrefix = "category:"

// Group is a named set of license ids, e.g. "approved for distribution".
type Group struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	LicenseIDs  []string  `json:"license_ids"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// BuiltinGroup is the implicit group of every catalog license in one ScanCode
// category.
type BuiltinGroup struct {
	Ref      string `json:"ref"`
	Category string `json:"category"`
	Count    int    `json:"count"`
}

// BuiltinGroups lists one built-in group per ScanCode category.
func BuiltinGroups() []BuiltinGroup {
	out := make([]BuiltinGroup, 0, len(categories))
	for _, c := range categories {
		out = append(out, BuiltinGroup{Ref: CategoryRefPrefix + c, Category: c, Count: len(loadCatalog().members[c])})
	}
	return out
}

// Groups stores custom license groups (table license_groups) and resolves
// group refs for license policies.
type Groups struct {
	db *pgxpool.Pool
}

// NewGroups constructs a Groups repository.
func NewGroups(db *pgxpool.Pool) *Groups { return &Groups{db: db} }

const groupColumns = `id, name, description, license_ids, created_at, updated_at`

func scanGroup(row pgx.Row) (Group, error) {
	var g Group
	err := row.Scan(&g.ID, &g.Name, &g.Description, &g.LicenseIDs, &g.CreatedAt, &g.UpdatedAt)
	if g.LicenseIDs == nil {
		g.LicenseIDs = []string{}
	}
	return g, err
}

// Members returns the license ids of a group ref — a custom group's id, or
// "category:<Category>" for every catalog id in that ScanCode category (matched
// case-insensitively). Ids are canonical case, as Expr.IDs() reports them.
func (g *Groups) Members(ctx context.Context, ref string) ([]string, error) {
	ref = strings.TrimSpace(ref)
	if cat, ok := strings.CutPrefix(ref, CategoryRefPrefix); ok {
		if _, known := CanonicalCategory(cat); !known {
			return nil, fmt.Errorf("%w: unknown category %q", ErrInvalidGroupRef, cat)
		}
		return CategoryMembers(cat), nil
	}
	if uuid.Validate(ref) != nil {
		return nil, fmt.Errorf("%w: %q", ErrInvalidGroupRef, ref)
	}
	grp, err := g.Get(ctx, ref)
	if err != nil {
		return nil, err
	}
	return grp.LicenseIDs, nil
}

// List returns custom groups by name.
func (g *Groups) List(ctx context.Context, limit, offset int) ([]Group, error) {
	rows, err := g.db.Query(ctx, `SELECT `+groupColumns+` FROM license_groups ORDER BY name LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list license groups: %w", err)
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		grp, err := scanGroup(rows)
		if err != nil {
			return nil, fmt.Errorf("scan license group: %w", err)
		}
		out = append(out, grp)
	}
	return out, rows.Err()
}

// Get returns one custom group.
func (g *Groups) Get(ctx context.Context, id string) (Group, error) {
	grp, err := scanGroup(g.db.QueryRow(ctx, `SELECT `+groupColumns+` FROM license_groups WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Group{}, ErrGroupNotFound
	}
	if err != nil {
		return Group{}, fmt.Errorf("get license group: %w", err)
	}
	return grp, nil
}

// Create stores a new group. Its ids must already be canonical (NormalizeIDs).
func (g *Groups) Create(ctx context.Context, grp Group) (Group, error) {
	out, err := scanGroup(g.db.QueryRow(ctx, `
		INSERT INTO license_groups (name, description, license_ids) VALUES ($1, $2, $3)
		RETURNING `+groupColumns, grp.Name, grp.Description, grp.LicenseIDs))
	return out, groupWriteErr(err)
}

// Update replaces a group's name, description and members.
func (g *Groups) Update(ctx context.Context, grp Group) (Group, error) {
	out, err := scanGroup(g.db.QueryRow(ctx, `
		UPDATE license_groups SET name = $2, description = $3, license_ids = $4, updated_at = now()
		WHERE id = $1 RETURNING `+groupColumns, grp.ID, grp.Name, grp.Description, grp.LicenseIDs))
	if errors.Is(err, pgx.ErrNoRows) {
		return Group{}, ErrGroupNotFound
	}
	return out, groupWriteErr(err)
}

// Delete removes a group.
func (g *Groups) Delete(ctx context.Context, id string) error {
	tag, err := g.db.Exec(ctx, `DELETE FROM license_groups WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete license group: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrGroupNotFound
	}
	return nil
}

func groupWriteErr(err error) error {
	var pg *pgconn.PgError
	if errors.As(err, &pg) && pg.Code == "23505" {
		return ErrDuplicateGroup
	}
	if err != nil {
		return fmt.Errorf("write license group: %w", err)
	}
	return nil
}

// Containing lists the custom groups that include a license id.
func (g *Groups) Containing(ctx context.Context, id string) ([]GroupRef, error) {
	rows, err := g.db.Query(ctx, `SELECT id, name FROM license_groups WHERE $1 = ANY(license_ids) ORDER BY name`, id)
	if err != nil {
		return nil, fmt.Errorf("license groups containing: %w", err)
	}
	defer rows.Close()
	out := []GroupRef{}
	for rows.Next() {
		var r GroupRef
		if err := rows.Scan(&r.ID, &r.Name); err != nil {
			return nil, fmt.Errorf("scan license group: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// NormalizeIDs canonicalizes group members: each must be a catalog license id
// (any case; returned canonical) or a LicenseRef-* (kept verbatim). Duplicates
// are dropped; the result is sorted. The error names every unknown id.
func NormalizeIDs(ids []string) ([]string, error) {
	out := []string{}
	var unknown []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if info, ok := Lookup(id); ok {
			id = info.ID
		} else if !licenseRef.MatchString(id) {
			unknown = append(unknown, id)
			continue
		}
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("unknown license ids: %s", strings.Join(unknown, ", "))
	}
	slices.Sort(out)
	return out, nil
}
