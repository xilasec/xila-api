// Package federation implements workload identity federation: CI platforms and
// clusters (GitHub Actions, GitLab CI, Kubernetes) exchange their own OIDC
// identity token for a short-lived Xila session of a service account (OAuth
// 2.0 Token Exchange, RFC 8693), so pipelines store no Xila secret. Admins
// define the trusted issuers and the bindings — claim conditions → service
// account (and optionally one project).
package federation

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Repository errors.
var (
	ErrNotFound         = errors.New("not found")
	ErrDuplicateIssuer  = errors.New("an issuer with that URL already exists")
	ErrUnknownReference = errors.New("unknown issuer, service account or project")
)

// Issuer is a trusted OIDC issuer.
type Issuer struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	IssuerURL string    `json:"issuer_url"`
	Audience  string    `json:"audience"`
	Enabled   bool      `json:"enabled"`
	CreatedBy *string   `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Binding maps tokens from an issuer whose claims meet every condition to a
// service account, optionally confining the session to one project.
type Binding struct {
	ID                 string            `json:"id"`
	IssuerID           string            `json:"issuer_id"`
	IssuerName         string            `json:"issuer_name"`
	ServiceAccountID   string            `json:"service_account_id"`
	ServiceAccountName string            `json:"service_account_name"`
	ProjectID          *string           `json:"project_id"`
	Name               string            `json:"name"`
	Conditions         map[string]string `json:"conditions"`
	Enabled            bool              `json:"enabled"`
	CreatedBy          *string           `json:"created_by"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

// Repository persists issuers and bindings.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

const issuerCols = `id, name, issuer_url, audience, enabled, created_by, created_at, updated_at`

func scanIssuer(row pgx.Row) (Issuer, error) {
	var i Issuer
	err := row.Scan(&i.ID, &i.Name, &i.IssuerURL, &i.Audience, &i.Enabled, &i.CreatedBy, &i.CreatedAt, &i.UpdatedAt)
	return i, err
}

func pgCode(err error) string {
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		return pgErr.Code
	}
	return ""
}

// CreateIssuer stores a trusted issuer.
func (r *Repository) CreateIssuer(ctx context.Context, i Issuer, createdBy string) (Issuer, error) {
	out, err := scanIssuer(r.db.QueryRow(ctx, `INSERT INTO federation_issuers (name, issuer_url, audience, enabled, created_by)
		VALUES ($1, $2, $3, $4, $5) RETURNING `+issuerCols, i.Name, i.IssuerURL, i.Audience, i.Enabled, createdBy))
	if pgCode(err) == "23505" {
		return Issuer{}, ErrDuplicateIssuer
	}
	if err != nil {
		return Issuer{}, fmt.Errorf("insert issuer: %w", err)
	}
	return out, nil
}

// UpdateIssuer replaces an issuer's settings.
func (r *Repository) UpdateIssuer(ctx context.Context, i Issuer) (Issuer, error) {
	out, err := scanIssuer(r.db.QueryRow(ctx, `UPDATE federation_issuers
		SET name = $2, issuer_url = $3, audience = $4, enabled = $5, updated_at = now()
		WHERE id = $1 RETURNING `+issuerCols, i.ID, i.Name, i.IssuerURL, i.Audience, i.Enabled))
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return Issuer{}, ErrNotFound
	case pgCode(err) == "23505":
		return Issuer{}, ErrDuplicateIssuer
	case err != nil:
		return Issuer{}, fmt.Errorf("update issuer: %w", err)
	}
	return out, nil
}

// GetIssuer returns one issuer.
func (r *Repository) GetIssuer(ctx context.Context, id string) (Issuer, error) {
	i, err := scanIssuer(r.db.QueryRow(ctx, `SELECT `+issuerCols+` FROM federation_issuers WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Issuer{}, ErrNotFound
	}
	if err != nil {
		return Issuer{}, fmt.Errorf("get issuer: %w", err)
	}
	return i, nil
}

// EnabledIssuerByURL finds the enabled issuer a token claims to come from.
func (r *Repository) EnabledIssuerByURL(ctx context.Context, url string) (Issuer, error) {
	i, err := scanIssuer(r.db.QueryRow(ctx, `SELECT `+issuerCols+` FROM federation_issuers WHERE issuer_url = $1 AND enabled`, url))
	if errors.Is(err, pgx.ErrNoRows) {
		return Issuer{}, ErrNotFound
	}
	if err != nil {
		return Issuer{}, fmt.Errorf("get issuer by url: %w", err)
	}
	return i, nil
}

// ListIssuers returns every issuer, by name.
func (r *Repository) ListIssuers(ctx context.Context) ([]Issuer, error) {
	rows, err := r.db.Query(ctx, `SELECT `+issuerCols+` FROM federation_issuers ORDER BY name, created_at`)
	if err != nil {
		return nil, fmt.Errorf("list issuers: %w", err)
	}
	defer rows.Close()
	out := []Issuer{}
	for rows.Next() {
		i, err := scanIssuer(rows)
		if err != nil {
			return nil, fmt.Errorf("scan issuer: %w", err)
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// DeleteIssuer removes an issuer and (cascade) its bindings.
func (r *Repository) DeleteIssuer(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM federation_issuers WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete issuer: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const bindingSelect = `
	SELECT b.id, b.issuer_id, i.name, b.service_account_id, s.name, b.project_id, b.name, b.conditions,
		b.enabled, b.created_by, b.created_at, b.updated_at
	FROM federation_bindings b
	JOIN federation_issuers i ON i.id = b.issuer_id
	JOIN service_accounts s ON s.user_id = b.service_account_id`

func scanBinding(row pgx.Row) (Binding, error) {
	var b Binding
	err := row.Scan(&b.ID, &b.IssuerID, &b.IssuerName, &b.ServiceAccountID, &b.ServiceAccountName, &b.ProjectID,
		&b.Name, &b.Conditions, &b.Enabled, &b.CreatedBy, &b.CreatedAt, &b.UpdatedAt)
	return b, err
}

func (r *Repository) listBindings(ctx context.Context, where string, args ...any) ([]Binding, error) {
	rows, err := r.db.Query(ctx, bindingSelect+where+` ORDER BY b.created_at, b.id`, args...)
	if err != nil {
		return nil, fmt.Errorf("list bindings: %w", err)
	}
	defer rows.Close()
	out := []Binding{}
	for rows.Next() {
		b, err := scanBinding(rows)
		if err != nil {
			return nil, fmt.Errorf("scan binding: %w", err)
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ListBindings returns every binding, oldest first.
func (r *Repository) ListBindings(ctx context.Context) ([]Binding, error) {
	return r.listBindings(ctx, "")
}

// EnabledBindings returns the issuer's enabled bindings, oldest first.
func (r *Repository) EnabledBindings(ctx context.Context, issuerID string) ([]Binding, error) {
	return r.listBindings(ctx, ` WHERE b.issuer_id = $1 AND b.enabled`, issuerID)
}

// GetBinding returns one binding.
func (r *Repository) GetBinding(ctx context.Context, id string) (Binding, error) {
	b, err := scanBinding(r.db.QueryRow(ctx, bindingSelect+` WHERE b.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Binding{}, ErrNotFound
	}
	if err != nil {
		return Binding{}, fmt.Errorf("get binding: %w", err)
	}
	return b, nil
}

// CreateBinding stores a binding.
func (r *Repository) CreateBinding(ctx context.Context, b Binding, createdBy string) (Binding, error) {
	var id string
	err := r.db.QueryRow(ctx, `INSERT INTO federation_bindings
		(issuer_id, service_account_id, project_id, name, conditions, enabled, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		b.IssuerID, b.ServiceAccountID, b.ProjectID, b.Name, b.Conditions, b.Enabled, createdBy).Scan(&id)
	if pgCode(err) == "23503" {
		return Binding{}, ErrUnknownReference
	}
	if err != nil {
		return Binding{}, fmt.Errorf("insert binding: %w", err)
	}
	return r.GetBinding(ctx, id)
}

// UpdateBinding replaces a binding's settings.
func (r *Repository) UpdateBinding(ctx context.Context, b Binding) (Binding, error) {
	tag, err := r.db.Exec(ctx, `UPDATE federation_bindings
		SET issuer_id = $2, service_account_id = $3, project_id = $4, name = $5, conditions = $6, enabled = $7, updated_at = now()
		WHERE id = $1`, b.ID, b.IssuerID, b.ServiceAccountID, b.ProjectID, b.Name, b.Conditions, b.Enabled)
	if pgCode(err) == "23503" {
		return Binding{}, ErrUnknownReference
	}
	if err != nil {
		return Binding{}, fmt.Errorf("update binding: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return Binding{}, ErrNotFound
	}
	return r.GetBinding(ctx, b.ID)
}

// DeleteBinding removes a binding.
func (r *Repository) DeleteBinding(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM federation_bindings WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete binding: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
