// Package team implements CRUD for teams, the top of the ownership hierarchy.
package team

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Domain errors.
var (
	ErrNotFound  = errors.New("team not found")
	ErrDuplicate = errors.New("team slug already exists")
	ErrNoOrg     = errors.New("organization not found")
)

// Team groups projects for ownership and portfolio-level reporting.
type Team struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Repository provides access to the teams table.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

const teamColumns = `id, org_id, slug, name, description, created_at, updated_at`

func scanTeam(row pgx.Row) (Team, error) {
	var t Team
	err := row.Scan(&t.ID, &t.OrgID, &t.Slug, &t.Name, &t.Description, &t.CreatedAt, &t.UpdatedAt)
	return t, err
}

// Create inserts a new team.
func (r *Repository) Create(ctx context.Context, orgID, slug, name, description string) (Team, error) {
	const q = `INSERT INTO teams (org_id, slug, name, description) VALUES ($1, $2, $3, $4) RETURNING ` + teamColumns
	t, err := scanTeam(r.db.QueryRow(ctx, q, orgID, slug, name, description))

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" { // FK: org missing
		return Team{}, ErrNoOrg
	}
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return Team{}, ErrDuplicate
	}
	if err != nil {
		return Team{}, fmt.Errorf("insert team: %w", err)
	}
	return t, nil
}

// GetBySlug fetches a team by org and slug, returning ErrNotFound when
// absent. Used by idempotent seeders (e.g. internal/demo) that look a team up
// before creating it.
func (r *Repository) GetBySlug(ctx context.Context, orgID, slug string) (Team, error) {
	const q = `SELECT ` + teamColumns + ` FROM teams WHERE org_id = $1 AND slug = $2`
	t, err := scanTeam(r.db.QueryRow(ctx, q, orgID, slug))
	if errors.Is(err, pgx.ErrNoRows) {
		return Team{}, ErrNotFound
	}
	if err != nil {
		return Team{}, fmt.Errorf("get team by slug: %w", err)
	}
	return t, nil
}

// List returns all teams ordered by name.
// ListByIDs returns the teams with the given ids (empty ids -> no teams).
func (r *Repository) ListByIDs(ctx context.Context, ids []string) ([]Team, error) {
	teams := []Team{}
	if len(ids) == 0 {
		return teams, nil
	}
	const q = `SELECT ` + teamColumns + ` FROM teams WHERE id = ANY($1) ORDER BY name`
	rows, err := r.db.Query(ctx, q, ids)
	if err != nil {
		return nil, fmt.Errorf("list teams by ids: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		t, err := scanTeam(rows)
		if err != nil {
			return nil, fmt.Errorf("scan team: %w", err)
		}
		teams = append(teams, t)
	}
	return teams, rows.Err()
}

func (r *Repository) List(ctx context.Context) ([]Team, error) {
	const q = `SELECT ` + teamColumns + ` FROM teams ORDER BY name`
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list teams: %w", err)
	}
	defer rows.Close()

	teams := []Team{}
	for rows.Next() {
		t, err := scanTeam(rows)
		if err != nil {
			return nil, fmt.Errorf("scan team: %w", err)
		}
		teams = append(teams, t)
	}
	return teams, rows.Err()
}

// Get returns a team by id.
func (r *Repository) Get(ctx context.Context, id string) (Team, error) {
	const q = `SELECT ` + teamColumns + ` FROM teams WHERE id = $1`
	t, err := scanTeam(r.db.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Team{}, ErrNotFound
	}
	if err != nil {
		return Team{}, fmt.Errorf("get team: %w", err)
	}
	return t, nil
}

// Update applies partial changes; nil fields are left untouched.
func (r *Repository) Update(ctx context.Context, id string, name, description *string) (Team, error) {
	const q = `
		UPDATE teams
		SET name        = COALESCE($2, name),
		    description = COALESCE($3, description),
		    updated_at  = now()
		WHERE id = $1
		RETURNING ` + teamColumns
	t, err := scanTeam(r.db.QueryRow(ctx, q, id, name, description))
	if errors.Is(err, pgx.ErrNoRows) {
		return Team{}, ErrNotFound
	}
	if err != nil {
		return Team{}, fmt.Errorf("update team: %w", err)
	}
	return t, nil
}

// Delete removes a team (and cascades to its projects).
func (r *Repository) Delete(ctx context.Context, id string) error {
	const q = `DELETE FROM teams WHERE id = $1`
	tag, err := r.db.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("delete team: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
