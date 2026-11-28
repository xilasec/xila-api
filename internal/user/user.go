// Package user holds the user entity and its persistence.
package user

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Domain errors returned by the repository.
var (
	ErrNotFound  = errors.New("user not found")
	ErrDuplicate = errors.New("email already registered")
	// ErrOwnerProtected is returned when something tries to demote or delete the
	// instance owner. Nothing may.
	ErrOwnerProtected = errors.New("the instance owner cannot be modified")
	// ErrNotOwner is returned when a non-owner tries to transfer ownership.
	ErrNotOwner = errors.New("only the instance owner can transfer ownership")
	// ErrDisabled is returned when a deactivated account tries to sign in (or is
	// chosen as the new owner).
	ErrDisabled = errors.New("account is deactivated")
	// ErrMFAEnabled: an enrollment step that needs MFA to be off.
	ErrMFAEnabled = errors.New("two-factor authentication is already enabled; disable it first")
)

// User is a platform account. PasswordHash is never serialized to JSON.
type User struct {
	ID           string `json:"id"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"`
	IsAdmin      bool   `json:"is_admin"`
	// IsOwner marks the single instance owner: always an admin, and no one — not
	// even another admin — can demote or delete them. Ownership moves only by the
	// owner handing it over.
	IsOwner bool `json:"is_owner"`
	// AdminSource is where IsAdmin came from: "manual" (granted by a person) or
	// "sso" (an IdP group mapping, re-evaluated — and revocable — on each SSO
	// login).
	AdminSource string    `json:"admin_source"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	// DisabledAt is set while the account is deactivated: no password, SSO or
	// API-token access, and every session is revoked.
	DisabledAt *time.Time `json:"disabled_at"`
	// HasPassword is false for SSO-only accounts.
	HasPassword       bool       `json:"has_password"`
	PasswordChangedAt *time.Time `json:"password_changed_at"`
	// TokenVersion is embedded in every JWT; bumping it revokes them all.
	TokenVersion int `json:"-"`
	// MFAEnabled: password sign-in also needs a TOTP or recovery code.
	MFAEnabled bool `json:"mfa_enabled"`
	// Kind is KindUser for a person, KindService for a service account (a
	// non-human principal: no password, no sign-in, never an admin).
	Kind string `json:"kind"`
}

// Account kinds (users.kind).
const (
	KindUser    = "user"
	KindService = "service"
)

// IsService reports whether the account is a service account.
func (u User) IsService() bool { return u.Kind == KindService }

// Disabled reports whether the account is deactivated.
func (u User) Disabled() bool { return u.DisabledAt != nil }

// Repository provides access to the users table.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository backed by the given pool.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// password_hash is nullable (SSO users have none); coalesce so it scans into a string.
const userColumns = `id, email, COALESCE(password_hash, '') AS password_hash, is_admin, is_owner, admin_source, created_at, updated_at,
	disabled_at, password_changed_at, token_version, mfa_enabled_at IS NOT NULL, kind`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.IsOwner, &u.AdminSource, &u.CreatedAt, &u.UpdatedAt,
		&u.DisabledAt, &u.PasswordChangedAt, &u.TokenVersion, &u.MFAEnabled, &u.Kind)
	u.HasPassword = u.PasswordHash != ""
	return u, err
}

// Create inserts a new user. The very first user in an empty instance becomes the
// admin **and the owner** (bootstrap); everyone after is a regular user. An empty
// passwordHash creates a passwordless account (SSO-only, pre-provisioned).
func (r *Repository) Create(ctx context.Context, email, passwordHash string) (User, error) {
	const q = `
		INSERT INTO users (email, password_hash, is_admin, is_owner)
		VALUES ($1, NULLIF($2, ''), NOT EXISTS (SELECT 1 FROM users), NOT EXISTS (SELECT 1 FROM users))
		RETURNING ` + userColumns

	u, err := scanUser(r.db.QueryRow(ctx, q, email, passwordHash))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
		return User{}, ErrDuplicate
	}
	if err != nil {
		return User{}, fmt.Errorf("insert user: %w", err)
	}
	return u, nil
}

// GetByEmail fetches a user by email, returning ErrNotFound when absent.
func (r *Repository) GetByEmail(ctx context.Context, email string) (User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE email = $1`
	u, err := scanUser(r.db.QueryRow(ctx, q, email))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("get user by email: %w", err)
	}
	return u, nil
}

// HasUsers reports whether the instance has any user yet (i.e. is past bootstrap).
func (r *Repository) HasUsers(ctx context.Context) (bool, error) {
	var found bool
	if err := r.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users)`).Scan(&found); err != nil {
		return false, fmt.Errorf("has users: %w", err)
	}
	return found, nil
}

// GetByID fetches a user by id.
func (r *Repository) GetByID(ctx context.Context, id string) (User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE id = $1`
	u, err := scanUser(r.db.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("get user by id: %w", err)
	}
	return u, nil
}

// List returns all people (admin view). Service accounts have their own list.
func (r *Repository) List(ctx context.Context) ([]User, error) {
	const q = `SELECT ` + userColumns + ` FROM users WHERE kind = 'user' ORDER BY created_at`
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()
	users := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

// CountAdmins returns the number of admin users.
func (r *Repository) CountAdmins(ctx context.Context) (int, error) {
	var n int
	if err := r.db.QueryRow(ctx, `SELECT count(*) FROM users WHERE is_admin`).Scan(&n); err != nil {
		return 0, fmt.Errorf("count admins: %w", err)
	}
	return n, nil
}

// SetAdmin promotes or demotes a user.
//
// The owner cannot be demoted — by anyone, including themselves. The guard is the
// `AND NOT is_owner` in the statement, not a check in the handler: an admin
// endpoint is not the only thing that will ever call this, and a rule that only
// exists in one caller is a rule that will eventually be bypassed.
func (r *Repository) SetAdmin(ctx context.Context, id string, admin bool) (User, error) {
	// A person's decision: the flag is theirs now, and SSO group sync leaves it alone.
	const q = `UPDATE users SET is_admin = $2, admin_source = 'manual', updated_at = now()
		WHERE id = $1 AND NOT is_owner AND kind = 'user' RETURNING ` + userColumns
	u, err := scanUser(r.db.QueryRow(ctx, q, id, admin))
	if errors.Is(err, pgx.ErrNoRows) {
		// Either the user doesn't exist, or they're the owner. Tell them apart so
		// the caller can return the right status.
		var owner bool
		if err := r.db.QueryRow(ctx, `SELECT is_owner FROM users WHERE id = $1`, id).Scan(&owner); err != nil {
			return User{}, ErrNotFound
		}
		if owner {
			return User{}, ErrOwnerProtected
		}
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("set admin: %w", err)
	}
	return u, nil
}

// TransferOwnership hands the instance owner role to another user, who becomes an
// admin in the process. Only the current owner may do this, and it is atomic:
// there is never a moment with no owner, or with two.
func (r *Repository) TransferOwnership(ctx context.Context, fromID, toID string) (User, error) {
	if fromID == toID {
		return User{}, ErrNotOwner // nothing to do, and silently succeeding would be a lie
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return User{}, fmt.Errorf("begin transfer: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	// Only the owner can give ownership away.
	var isOwner bool
	if err := tx.QueryRow(ctx, `SELECT is_owner FROM users WHERE id = $1`, fromID).Scan(&isOwner); err != nil {
		return User{}, ErrNotFound
	}
	if !isOwner {
		return User{}, ErrNotOwner
	}

	// Clear the old owner first: the single-owner unique index would otherwise
	// reject the second row.
	if _, err := tx.Exec(ctx, `UPDATE users SET is_owner = false, updated_at = now() WHERE id = $1`, fromID); err != nil {
		return User{}, fmt.Errorf("clear owner: %w", err)
	}
	u, err := scanUser(tx.QueryRow(ctx,
		`UPDATE users SET is_owner = true, is_admin = true, admin_source = 'manual', updated_at = now()
		 WHERE id = $1 AND disabled_at IS NULL AND kind = 'user' RETURNING `+userColumns, toID))
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if tx.QueryRow(ctx, `SELECT true FROM users WHERE id = $1`, toID).Scan(&exists) == nil {
			return User{}, ErrDisabled // the owner is the break-glass account; it must be able to sign in
		}
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("set owner: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("commit transfer: %w", err)
	}
	return u, nil
}

// SessionValid reports whether a JWT minted at tokenVersion for userID is still
// good: the account exists, isn't deactivated, and no password change, "sign
// out everywhere" or deactivation has bumped its version since. Runs on every
// JWT-authenticated request (one primary-key read).
func (r *Repository) SessionValid(ctx context.Context, userID string, tokenVersion int) (bool, error) {
	var current int
	var disabled bool
	err := r.db.QueryRow(ctx, `SELECT token_version, disabled_at IS NOT NULL FROM users WHERE id = $1`, userID).
		Scan(&current, &disabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // deleted
	}
	if err != nil {
		return false, fmt.Errorf("session check: %w", err)
	}
	return !disabled && current == tokenVersion, nil
}

// SetPassword stores a new bcrypt hash, revokes every session (token_version)
// and burns any outstanding reset tokens.
func (r *Repository) SetPassword(ctx context.Context, id, passwordHash string) (User, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return User{}, fmt.Errorf("begin set password: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	u, err := scanUser(tx.QueryRow(ctx, `
		UPDATE users SET password_hash = $2, password_changed_at = now(), token_version = token_version + 1, updated_at = now()
		WHERE id = $1 RETURNING `+userColumns, id, passwordHash))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("set password: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM password_reset_tokens WHERE user_id = $1`, id); err != nil {
		return User{}, fmt.Errorf("burn reset tokens: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("commit set password: %w", err)
	}
	return u, nil
}

// RevokeSessions bumps the token version: every JWT issued so far stops working.
func (r *Repository) RevokeSessions(ctx context.Context, id string) (User, error) {
	u, err := scanUser(r.db.QueryRow(ctx, `
		UPDATE users SET token_version = token_version + 1, updated_at = now()
		WHERE id = $1 RETURNING `+userColumns, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("revoke sessions: %w", err)
	}
	return u, nil
}

// SetDisabled deactivates or reactivates an account. Deactivating revokes every
// session and pending reset; the account's API tokens stop validating while it
// is deactivated. The owner can't be deactivated (also a schema constraint).
func (r *Repository) SetDisabled(ctx context.Context, id string, disabled bool) (User, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return User{}, fmt.Errorf("begin set disabled: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	u, err := scanUser(tx.QueryRow(ctx, `
		UPDATE users SET
			disabled_at   = CASE WHEN $2 THEN COALESCE(disabled_at, now()) END,
			token_version = token_version + CASE WHEN $2 AND disabled_at IS NULL THEN 1 ELSE 0 END,
			updated_at    = now()
		WHERE id = $1 AND NOT is_owner RETURNING `+userColumns, id, disabled))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, r.ownerOrMissing(ctx, id)
	}
	if err != nil {
		return User{}, fmt.Errorf("set disabled: %w", err)
	}
	if disabled {
		if _, err := tx.Exec(ctx, `DELETE FROM password_reset_tokens WHERE user_id = $1`, id); err != nil {
			return User{}, fmt.Errorf("burn reset tokens: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("commit set disabled: %w", err)
	}
	return u, nil
}

// Delete removes an account. Memberships, identities and API tokens cascade;
// authored records (comments, rules, policies) keep their content with the
// author cleared. The owner can't be deleted.
func (r *Repository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM users WHERE id = $1 AND NOT is_owner`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return r.ownerOrMissing(ctx, id)
	}
	return nil
}

func (r *Repository) ownerOrMissing(ctx context.Context, id string) error {
	var owner bool
	if err := r.db.QueryRow(ctx, `SELECT is_owner FROM users WHERE id = $1`, id).Scan(&owner); err != nil {
		return ErrNotFound
	}
	if owner {
		return ErrOwnerProtected
	}
	return ErrNotFound
}

// ErrResetInvalid is returned for an unknown, used or expired reset token.
var ErrResetInvalid = errors.New("reset link is invalid or has expired")

// CreateResetToken stores a reset token's hash, replacing any earlier one for
// the user (only the newest link works).
func (r *Repository) CreateResetToken(ctx context.Context, userID, tokenHash string, expiresAt time.Time) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin reset token: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if _, err := tx.Exec(ctx, `DELETE FROM password_reset_tokens WHERE user_id = $1 OR expires_at < now()`, userID); err != nil {
		return fmt.Errorf("clear reset tokens: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
		tokenHash, userID, expiresAt); err != nil {
		return fmt.Errorf("insert reset token: %w", err)
	}
	return tx.Commit(ctx)
}

// ConsumeResetToken redeems a reset token once, returning its (active) user.
// The token is deleted whether or not it was still valid.
func (r *Repository) ConsumeResetToken(ctx context.Context, tokenHash string) (User, error) {
	var userID string
	var valid bool
	err := r.db.QueryRow(ctx, `
		DELETE FROM password_reset_tokens t USING users u
		WHERE t.token_hash = $1 AND u.id = t.user_id
		RETURNING t.user_id, t.expires_at > now() AND u.disabled_at IS NULL`, tokenHash).Scan(&userID, &valid)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !valid) {
		return User{}, ErrResetInvalid
	}
	if err != nil {
		return User{}, fmt.Errorf("consume reset token: %w", err)
	}
	return r.GetByID(ctx, userID)
}

// MFAState is a user's stored TOTP secret (sealed) and whether it's active.
type MFAState struct {
	SealedSecret []byte
	Enabled      bool
}

// GetMFA returns the user's MFA state.
func (r *Repository) GetMFA(ctx context.Context, id string) (MFAState, error) {
	var st MFAState
	err := r.db.QueryRow(ctx, `SELECT mfa_secret_enc, mfa_enabled_at IS NOT NULL FROM users WHERE id = $1`, id).
		Scan(&st.SealedSecret, &st.Enabled)
	if errors.Is(err, pgx.ErrNoRows) {
		return st, ErrNotFound
	}
	return st, err
}

// SetPendingMFA stores a new, not yet confirmed secret (enrollment step 1).
// Refused while MFA is enabled: disable it first.
func (r *Repository) SetPendingMFA(ctx context.Context, id string, sealed []byte) error {
	tag, err := r.db.Exec(ctx, `UPDATE users SET mfa_secret_enc = $2, mfa_last_step = NULL
		WHERE id = $1 AND mfa_enabled_at IS NULL`, id, sealed)
	if err != nil {
		return fmt.Errorf("set pending mfa: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrMFAEnabled
	}
	return nil
}

// EnableMFA activates the pending secret with fresh recovery codes (hashes).
func (r *Repository) EnableMFA(ctx context.Context, id string, step int64, codeHashes []string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	tag, err := tx.Exec(ctx, `UPDATE users SET mfa_enabled_at = now(), mfa_last_step = $2
		WHERE id = $1 AND mfa_enabled_at IS NULL AND mfa_secret_enc IS NOT NULL`, id, step)
	if err != nil {
		return fmt.Errorf("enable mfa: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrMFAEnabled
	}
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO mfa_recovery_codes (user_id, code_hash) SELECT $1, unnest($2::text[])`, id, codeHashes); err != nil {
		return fmt.Errorf("store recovery codes: %w", err)
	}
	return tx.Commit(ctx)
}

// DisableMFA removes the secret and recovery codes.
func (r *Repository) DisableMFA(ctx context.Context, id string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	tag, err := tx.Exec(ctx, `UPDATE users SET mfa_secret_enc = NULL, mfa_enabled_at = NULL, mfa_last_step = NULL WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("disable mfa: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_recovery_codes WHERE user_id = $1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// UseTOTPStep records that the code for time step `step` was used, refusing a
// step at or before the last one used: a code works once.
func (r *Repository) UseTOTPStep(ctx context.Context, id string, step int64) (bool, error) {
	tag, err := r.db.Exec(ctx, `UPDATE users SET mfa_last_step = $2
		WHERE id = $1 AND (mfa_last_step IS NULL OR mfa_last_step < $2)`, id, step)
	if err != nil {
		return false, fmt.Errorf("use totp step: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// UseRecoveryCode consumes an unused recovery code (by hash).
func (r *Repository) UseRecoveryCode(ctx context.Context, id, codeHash string) (bool, error) {
	tag, err := r.db.Exec(ctx, `UPDATE mfa_recovery_codes SET used_at = now()
		WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`, id, codeHash)
	if err != nil {
		return false, fmt.Errorf("use recovery code: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// RecoveryCodesLeft counts unused recovery codes.
func (r *Repository) RecoveryCodesLeft(ctx context.Context, id string) (int, error) {
	var n int
	err := r.db.QueryRow(ctx, `SELECT count(*) FROM mfa_recovery_codes WHERE user_id = $1 AND used_at IS NULL`, id).Scan(&n)
	return n, err
}
