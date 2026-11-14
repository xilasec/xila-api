// Package serviceaccount manages non-human principals. A service account is a
// users row of kind 'service' (no password, no sign-in, never an admin) plus
// its metadata here, so it takes roles through ordinary org / team / project
// membership and every RBAC path applies to it unchanged. It authenticates with
// admin-issued, always-expiring API keys or with a federated session minted by
// the workload-identity token exchange (internal/federation).
package serviceaccount

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
	ErrNotFound  = errors.New("service account not found")
	ErrDuplicate = errors.New("a service account with that name already exists")
)

// EmailDomain is the reserved (RFC 2606 .invalid) domain of service-account
// emails: <name>@service-accounts.invalid. It is how membership endpoints,
// which take an email, grant a service account a role.
const EmailDomain = "service-accounts.invalid"

// Account is a service account.
type Account struct {
	ID          string `json:"id"` // the users row id
	Name        string `json:"name"`
	Description string `json:"description"`
	// Email identifies the account to membership endpoints and in audit trails.
	Email       string     `json:"email"`
	CreatedBy   *string    `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	SuspendedAt *time.Time `json:"suspended_at"`
	// ActiveKeys counts unexpired API keys.
	ActiveKeys int `json:"active_keys"`
}

// Repository persists service accounts.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

const accountSelect = `
	SELECT u.id, s.name, s.description, u.email, s.created_by, s.created_at, u.disabled_at,
		(SELECT count(*) FROM api_tokens t WHERE t.created_by = u.id AND (t.expires_at IS NULL OR t.expires_at > now()))
	FROM service_accounts s JOIN users u ON u.id = s.user_id`

func scanAccount(row pgx.Row) (Account, error) {
	var a Account
	err := row.Scan(&a.ID, &a.Name, &a.Description, &a.Email, &a.CreatedBy, &a.CreatedAt, &a.SuspendedAt, &a.ActiveKeys)
	return a, err
}

// Create inserts the account's users row and its metadata in one transaction.
func (r *Repository) Create(ctx context.Context, name, description, createdBy string) (Account, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Account{}, fmt.Errorf("begin create service account: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	var id string
	err = tx.QueryRow(ctx, `INSERT INTO users (email, kind, is_admin, is_owner) VALUES ($1, 'service', false, false) RETURNING id`,
		name+"@"+EmailDomain).Scan(&id)
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
		return Account{}, ErrDuplicate
	}
	if err != nil {
		return Account{}, fmt.Errorf("insert service account user: %w", err)
	}
	_, err = tx.Exec(ctx, `INSERT INTO service_accounts (user_id, name, description, created_by) VALUES ($1, $2, $3, $4)`,
		id, name, description, createdBy)
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
		return Account{}, ErrDuplicate
	}
	if err != nil {
		return Account{}, fmt.Errorf("insert service account: %w", err)
	}
	a, err := scanAccount(tx.QueryRow(ctx, accountSelect+` WHERE u.id = $1`, id))
	if err != nil {
		return Account{}, fmt.Errorf("load service account: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Account{}, fmt.Errorf("commit service account: %w", err)
	}
	return a, nil
}

// List returns every service account, by name.
func (r *Repository) List(ctx context.Context) ([]Account, error) {
	rows, err := r.db.Query(ctx, accountSelect+` ORDER BY s.name`)
	if err != nil {
		return nil, fmt.Errorf("list service accounts: %w", err)
	}
	defer rows.Close()
	out := []Account{}
	for rows.Next() {
		a, err := scanAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("scan service account: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Get returns one service account.
func (r *Repository) Get(ctx context.Context, id string) (Account, error) {
	a, err := scanAccount(r.db.QueryRow(ctx, accountSelect+` WHERE u.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrNotFound
	}
	if err != nil {
		return Account{}, fmt.Errorf("get service account: %w", err)
	}
	return a, nil
}

// SetDescription updates the account's description.
func (r *Repository) SetDescription(ctx context.Context, id, description string) (Account, error) {
	tag, err := r.db.Exec(ctx, `UPDATE service_accounts SET description = $2 WHERE user_id = $1`, id, description)
	if err != nil {
		return Account{}, fmt.Errorf("update service account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return Account{}, ErrNotFound
	}
	return r.Get(ctx, id)
}

// SetSuspended suspends or resumes an account. Suspending ends everything it
// holds at once: the token version bump kills every federated session, and its
// API keys are deleted (a resumed account gets new keys, never the old ones
// back). While suspended, the token exchange refuses it.
func (r *Repository) SetSuspended(ctx context.Context, id string, suspended bool) (Account, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Account{}, fmt.Errorf("begin suspend: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	tag, err := tx.Exec(ctx, `
		UPDATE users SET
			disabled_at   = CASE WHEN $2 THEN COALESCE(disabled_at, now()) END,
			token_version = token_version + CASE WHEN $2 AND disabled_at IS NULL THEN 1 ELSE 0 END,
			updated_at    = now()
		WHERE id = $1 AND kind = 'service'`, id, suspended)
	if err != nil {
		return Account{}, fmt.Errorf("suspend service account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return Account{}, ErrNotFound
	}
	if suspended {
		if _, err := tx.Exec(ctx, `DELETE FROM api_tokens WHERE created_by = $1`, id); err != nil {
			return Account{}, fmt.Errorf("revoke service account keys: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return Account{}, fmt.Errorf("commit suspend: %w", err)
	}
	return r.Get(ctx, id)
}

// Delete removes the account; its memberships, keys and federation bindings
// cascade with the users row.
func (r *Repository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM users WHERE id = $1 AND kind = 'service'`, id)
	if err != nil {
		return fmt.Errorf("delete service account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
