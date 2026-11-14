// Package apitoken issues and validates long-lived API tokens for CI/service
// access. Only a hash of each token is stored; the plaintext is shown once.
package apitoken

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotFound is returned when a token does not exist (or the hash doesn't match).
var ErrNotFound = errors.New("api token not found")

// Token is an issued API token. The secret itself is never stored or returned
// after creation — only its Prefix (for display).
type Token struct {
	ID         string     `json:"id"`
	CreatedBy  string     `json:"created_by"`
	ProjectID  *string    `json:"project_id"`
	Name       string     `json:"name"`
	Prefix     string     `json:"prefix"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	// OwnerIsService: the token is a service account's key (set by GetByHash).
	OwnerIsService bool `json:"-"`
}

// Repository provides access to the api_tokens table.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

const cols = `id, created_by, project_id, name, prefix, created_at, last_used_at, expires_at`

func scanToken(row pgx.Row) (Token, error) {
	var t Token
	err := row.Scan(&t.ID, &t.CreatedBy, &t.ProjectID, &t.Name, &t.Prefix,
		&t.CreatedAt, &t.LastUsedAt, &t.ExpiresAt)
	return t, err
}

// Create stores a token row and its hash.
func (r *Repository) Create(ctx context.Context, t Token, hash string) (Token, error) {
	const q = `
		INSERT INTO api_tokens (created_by, project_id, name, prefix, token_hash, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING ` + cols
	out, err := scanToken(r.db.QueryRow(ctx, q, t.CreatedBy, t.ProjectID, t.Name, t.Prefix, hash, t.ExpiresAt))
	if err != nil {
		return Token{}, fmt.Errorf("insert api token: %w", err)
	}
	return out, nil
}

// GetByHash looks up a token by its stored hash.
func (r *Repository) GetByHash(ctx context.Context, hash string) (Token, error) {
	// A deactivated owner's tokens stop working with the account (and work
	// again on reactivation — deactivating is reversible, unlike deleting).
	const q = `SELECT t.id, t.created_by, t.project_id, t.name, t.prefix, t.created_at, t.last_used_at, t.expires_at,
		u.kind = 'service'
		FROM api_tokens t JOIN users u ON u.id = t.created_by
		WHERE t.token_hash = $1 AND u.disabled_at IS NULL`
	var t Token
	err := r.db.QueryRow(ctx, q, hash).Scan(&t.ID, &t.CreatedBy, &t.ProjectID, &t.Name, &t.Prefix,
		&t.CreatedAt, &t.LastUsedAt, &t.ExpiresAt, &t.OwnerIsService)
	if errors.Is(err, pgx.ErrNoRows) {
		return Token{}, ErrNotFound
	}
	if err != nil {
		return Token{}, fmt.Errorf("get api token: %w", err)
	}
	return t, nil
}

// ListByUser returns a user's tokens, newest first.
func (r *Repository) ListByUser(ctx context.Context, userID string) ([]Token, error) {
	const q = `SELECT ` + cols + ` FROM api_tokens WHERE created_by = $1 ORDER BY created_at DESC`
	rows, err := r.db.Query(ctx, q, userID)
	if err != nil {
		return nil, fmt.Errorf("list api tokens: %w", err)
	}
	defer rows.Close()

	tokens := []Token{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, fmt.Errorf("scan api token: %w", err)
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// Delete removes a token owned by the user (revocation).
func (r *Repository) Delete(ctx context.Context, id, userID string) error {
	const q = `DELETE FROM api_tokens WHERE id = $1 AND created_by = $2`
	tag, err := r.db.Exec(ctx, q, id, userID)
	if err != nil {
		return fmt.Errorf("delete api token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchLastUsed records that a token was just used (best effort).
func (r *Repository) TouchLastUsed(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx, `UPDATE api_tokens SET last_used_at = now() WHERE id = $1`, id)
	return err
}
