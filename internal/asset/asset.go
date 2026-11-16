// Package asset manages the concrete things a project secures — repositories,
// container images, cloud resources, hosts — that findings attach to.
package asset

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/domain"
)

// Domain errors.
var (
	ErrNotFound  = errors.New("asset not found")
	ErrDuplicate = errors.New("asset already exists for this project")
	ErrNoProject = errors.New("project does not exist")
)

// Asset is a securable thing owned by a project.
type Asset struct {
	ID         string           `json:"id"`
	ProjectID  string           `json:"project_id"`
	Type       domain.AssetType `json:"type"`
	Name       string           `json:"name"`
	Identifier string           `json:"identifier"`
	Metadata   map[string]any   `json:"metadata"`
	// Exposure is where the asset can be reached from; nil = unknown, which
	// never discounts a finding's priority. ExposureSource says who set it
	// ("manual" or "inferred") and ExposureReason records the evidence.
	Exposure          *domain.Exposure `json:"exposure"`
	ExposureSource    *string          `json:"exposure_source"`
	ExposureReason    string           `json:"exposure_reason"`
	ExposureUpdatedAt *time.Time       `json:"exposure_updated_at"`
	// Custom holds the asset's custom-field values (internal/customfield).
	Custom    map[string]any `json:"custom"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

// Exposure sources.
const (
	ExposureManual   = "manual"
	ExposureInferred = "inferred"
)

// Repository provides access to the assets table.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

const assetColumns = `id, project_id, type, name, identifier, metadata,
	exposure, exposure_source, exposure_reason, exposure_updated_at, custom, created_at, updated_at`

func scanAsset(row pgx.Row) (Asset, error) {
	var a Asset
	err := row.Scan(&a.ID, &a.ProjectID, &a.Type, &a.Name, &a.Identifier, &a.Metadata,
		&a.Exposure, &a.ExposureSource, &a.ExposureReason, &a.ExposureUpdatedAt, &a.Custom, &a.CreatedAt, &a.UpdatedAt)
	return a, err
}

// Create inserts a new asset.
func (r *Repository) Create(ctx context.Context, a Asset) (Asset, error) {
	const q = `
		INSERT INTO assets (project_id, type, name, identifier, metadata)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING ` + assetColumns
	metadata := a.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	out, err := scanAsset(r.db.QueryRow(ctx, q, a.ProjectID, a.Type, a.Name, a.Identifier, metadata))

	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505": // unique_violation
			return Asset{}, ErrDuplicate
		case "23503": // foreign_key_violation
			return Asset{}, ErrNoProject
		}
	}
	if err != nil {
		return Asset{}, fmt.Errorf("insert asset: %w", err)
	}
	return out, nil
}

// Filter narrows an asset listing.
type Filter struct {
	ProjectID  string
	ProjectIDs []string // RBAC scope: non-nil restricts to these projects
	Type       domain.AssetType
	// Custom filters on custom fields (?cf.<key>=…).
	Custom []customfield.Cond
}

// List returns assets matching the filter, newest first.
func (r *Repository) List(ctx context.Context, f Filter) ([]Asset, error) {
	q := `SELECT ` + assetColumns + ` FROM assets WHERE 1 = 1`
	var args []any
	if f.ProjectID != "" {
		args = append(args, f.ProjectID)
		q += fmt.Sprintf(" AND project_id = $%d", len(args))
	}
	if f.ProjectIDs != nil {
		args = append(args, f.ProjectIDs)
		q += fmt.Sprintf(" AND project_id = ANY($%d)", len(args))
	}
	if f.Type != "" {
		args = append(args, f.Type)
		q += fmt.Sprintf(" AND type = $%d", len(args))
	}
	cond, args := customfield.AppendSQL(f.Custom, "custom", args)
	q += cond + ` ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	defer rows.Close()

	assets := []Asset{}
	for rows.Next() {
		a, err := scanAsset(rows)
		if err != nil {
			return nil, fmt.Errorf("scan asset: %w", err)
		}
		assets = append(assets, a)
	}
	return assets, rows.Err()
}

// Get returns an asset by id.
func (r *Repository) Get(ctx context.Context, id string) (Asset, error) {
	const q = `SELECT ` + assetColumns + ` FROM assets WHERE id = $1`
	a, err := scanAsset(r.db.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Asset{}, ErrNotFound
	}
	if err != nil {
		return Asset{}, fmt.Errorf("get asset: %w", err)
	}
	return a, nil
}

// Exists reports whether an asset with the given id exists.
func (r *Repository) Exists(ctx context.Context, id string) (bool, error) {
	const q = `SELECT EXISTS(SELECT 1 FROM assets WHERE id = $1)`
	var ok bool
	if err := r.db.QueryRow(ctx, q, id).Scan(&ok); err != nil {
		return false, fmt.Errorf("asset exists: %w", err)
	}
	return ok, nil
}

// Update applies partial changes; nil fields are left untouched.
func (r *Repository) Update(ctx context.Context, id string, name, identifier *string) (Asset, error) {
	const q = `
		UPDATE assets
		SET name       = COALESCE($2, name),
		    identifier = COALESCE($3, identifier),
		    updated_at = now()
		WHERE id = $1
		RETURNING ` + assetColumns
	a, err := scanAsset(r.db.QueryRow(ctx, q, id, name, identifier))
	if errors.Is(err, pgx.ErrNoRows) {
		return Asset{}, ErrNotFound
	}
	if err != nil {
		return Asset{}, fmt.Errorf("update asset: %w", err)
	}
	return a, nil
}

// Delete removes an asset (findings/scans keep their history, asset_id nulled).
func (r *Repository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM assets WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete asset: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetExposure records a person's exposure assessment (source "manual", which
// inference never overwrites). ExposureUnknown clears it — back to unknown, and
// open to inference again.
func (r *Repository) SetExposure(ctx context.Context, id string, e domain.Exposure, reason string) (Asset, error) {
	const q = `
		UPDATE assets
		SET exposure            = NULLIF($2, ''),
		    exposure_source     = CASE WHEN $2 = '' THEN NULL ELSE 'manual' END,
		    exposure_reason     = CASE WHEN $2 = '' THEN '' ELSE $3 END,
		    exposure_updated_at = now(),
		    updated_at          = now()
		WHERE id = $1
		RETURNING ` + assetColumns
	a, err := scanAsset(r.db.QueryRow(ctx, q, id, string(e), reason))
	if errors.Is(err, pgx.ErrNoRows) {
		return Asset{}, ErrNotFound
	}
	if err != nil {
		return Asset{}, fmt.Errorf("set exposure: %w", err)
	}
	return a, nil
}

// RaiseExposure stores inferred exposure evidence: only when nobody set the
// asset's exposure by hand and the evidence is more reachable than what is
// stored — inference never lowers an exposure. It reports whether it wrote.
func (r *Repository) RaiseExposure(ctx context.Context, id string, e domain.Exposure, reason string) (bool, error) {
	// The ranks mirror domain.Exposure.Rank (NULL = 0).
	const q = `
		UPDATE assets
		SET exposure = $2, exposure_source = 'inferred', exposure_reason = $3,
		    exposure_updated_at = now(), updated_at = now()
		WHERE id = $1 AND exposure_source IS DISTINCT FROM 'manual'
		  AND COALESCE(array_position(ARRAY['isolated', 'internal', 'internet'], exposure), 0)
		    < COALESCE(array_position(ARRAY['isolated', 'internal', 'internet'], $2::text), 0)`
	tag, err := r.db.Exec(ctx, q, id, string(e), reason)
	if err != nil {
		return false, fmt.Errorf("raise exposure: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// ResolveHosts returns the id of the project's host asset for each name
// (identifier = name), creating the missing ones. Existing rows aren't
// rewritten: a rescan of the same network touches nothing here.
func (r *Repository) ResolveHosts(ctx context.Context, projectID string, hosts []string) (map[string]string, error) {
	if _, err := r.db.Exec(ctx, `
		INSERT INTO assets (project_id, type, name, identifier)
		SELECT $1, 'host', h, h FROM unnest($2::text[]) AS h
		ON CONFLICT (project_id, type, identifier) DO NOTHING`, projectID, hosts); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return nil, ErrNoProject
		}
		return nil, fmt.Errorf("create host assets: %w", err)
	}
	rows, err := r.db.Query(ctx, `SELECT identifier, id FROM assets
		WHERE project_id = $1 AND type = 'host' AND identifier = ANY($2)`, projectID, hosts)
	if err != nil {
		return nil, fmt.Errorf("host assets: %w", err)
	}
	defer rows.Close()
	out := make(map[string]string, len(hosts))
	for rows.Next() {
		var name, id string
		if err := rows.Scan(&name, &id); err != nil {
			return nil, err
		}
		out[name] = id
	}
	return out, rows.Err()
}
