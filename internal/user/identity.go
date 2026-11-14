package user

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Identity is a person as an external identity provider names them. The
// (Provider, Issuer, Subject) triple is the stable key: OIDC `sub` / SAML
// NameID under the OIDC issuer / SAML IdP entity id. Email is only the
// address the IdP asserted on this login.
type Identity struct {
	Provider      string // "oidc" | "saml"
	Issuer        string
	Subject       string
	SubjectFormat string // SAML NameID Format; empty for OIDC
	Email         string // normalized (lower-case, trimmed)
	// ProviderID is the admin-managed provider this login came through
	// (recorded for display; nil for an environment-configured one). It is
	// not part of the key: the same issuer through another provider is the
	// same identity.
	ProviderID *string
	// ClaimLegacy lets this login claim an OIDC link carried over from the
	// single-provider schema (empty issuer) — only the environment-configured
	// OIDC provider, which those links were made against.
	ClaimLegacy bool
}

// LinkPolicy says how far a login may be trusted beyond its subject.
type LinkPolicy struct {
	// EmailVerified: the IdP vouches that Email belongs to this person. Only
	// then may the identity attach to an existing account with that email, or
	// move a linked account to a new email.
	EmailVerified bool
	// AllowCreate: an identity with no account may get a new passwordless one
	// (just-in-time provisioning).
	AllowCreate bool
}

// LinkOutcome reports how LinkIdentity resolved the user.
type LinkOutcome string

const (
	LinkedExisting LinkOutcome = "existing" // the identity was already linked
	LinkedByEmail  LinkOutcome = "email"    // attached to the account with the same email
	LinkedCreated  LinkOutcome = "created"  // a new account was provisioned
)

// Linking errors. Each is a distinct, explainable reason to refuse a login.
var (
	// ErrNoAccount: nobody has this identity or email, and provisioning is off.
	ErrNoAccount = errors.New("no account exists for this identity and automatic provisioning is off")
	// ErrEmailUnverified: an account with this email exists, but the IdP did not
	// vouch for the email, so attaching would let anyone who can set an
	// unverified address at the IdP take the account over. Also returned when an
	// unknown identity's email is explicitly unverified and so cannot found a
	// new account.
	ErrEmailUnverified = errors.New("the identity provider did not verify this email address")
	// ErrIdentityConflict: the account with this email is already linked to a
	// *different* subject at the same IdP — typically a recycled address. The
	// existing link wins; an admin must resolve it.
	ErrIdentityConflict = errors.New("the account with this email is already linked to another identity at this provider")
)

// LinkIdentity resolves an SSO login to a user:
//
//  1. an existing (provider, issuer, subject) link → that user. A verified email
//     that differs from the account's is adopted unless another account already
//     uses it (then the account keeps its email);
//  2. else an account with the same email → linked, only if policy.EmailVerified
//     and the account has no other subject at this IdP;
//  3. else a new passwordless account, if policy.AllowCreate. The first user of
//     an empty instance becomes the owner + admin, exactly as with Create.
//
// OIDC links carried over from the single-provider schema have an empty issuer;
// the first login of that subject through the environment-configured OIDC
// provider (Identity.ClaimLegacy) claims them for its issuer.
//
// Concurrent first logins of the same identity race on unique keys; the loser
// retries and lands on the winner's link.
func (r *Repository) LinkIdentity(ctx context.Context, id Identity, policy LinkPolicy) (User, LinkOutcome, error) {
	for attempt := 0; ; attempt++ {
		u, outcome, err := r.linkOnce(ctx, id, policy)
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && attempt < 2 {
			continue
		}
		if err != nil {
			return User{}, "", err
		}
		if outcome == LinkedExisting && policy.EmailVerified && id.Email != "" && u.Email != id.Email {
			u = r.adoptEmail(ctx, u, id.Email)
		}
		return u, outcome, nil
	}
}

func (r *Repository) linkOnce(ctx context.Context, id Identity, policy LinkPolicy) (User, LinkOutcome, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return User{}, "", fmt.Errorf("begin link: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	var userID string
	err = tx.QueryRow(ctx, `UPDATE user_identities SET last_login_at = now(), provider_id = $4
		WHERE provider = $1 AND issuer = $2 AND subject = $3 RETURNING user_id`,
		id.Provider, id.Issuer, id.Subject, id.ProviderID).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) && id.Provider == "oidc" && id.ClaimLegacy {
		err = tx.QueryRow(ctx, `UPDATE user_identities SET issuer = $1, last_login_at = now()
			WHERE provider = 'oidc' AND issuer = '' AND subject = $2 RETURNING user_id`,
			id.Issuer, id.Subject).Scan(&userID)
	}
	switch {
	case err == nil:
		u, err := scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE id = $1`, userID))
		if err != nil {
			return User{}, "", fmt.Errorf("load linked user: %w", err)
		}
		return u, LinkedExisting, tx.Commit(ctx)
	case !errors.Is(err, pgx.ErrNoRows):
		return User{}, "", fmt.Errorf("find identity: %w", err)
	}

	u, err := scanUser(tx.QueryRow(ctx, `SELECT `+userColumns+` FROM users WHERE email = $1 FOR UPDATE`, id.Email))
	outcome := LinkedByEmail
	switch {
	case err == nil:
		if u.IsService() {
			// A service account never signs in as a person, whatever an IdP asserts.
			return User{}, "", ErrIdentityConflict
		}
		if !policy.EmailVerified {
			return User{}, "", ErrEmailUnverified
		}
		var conflict bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_identities
			WHERE user_id = $1 AND provider = $2 AND (issuer = $3 OR (provider = 'oidc' AND issuer = '')))`,
			u.ID, id.Provider, id.Issuer).Scan(&conflict); err != nil {
			return User{}, "", fmt.Errorf("check identity conflict: %w", err)
		}
		if conflict {
			return User{}, "", ErrIdentityConflict
		}
	case errors.Is(err, pgx.ErrNoRows):
		if !policy.AllowCreate {
			return User{}, "", ErrNoAccount
		}
		u, err = scanUser(tx.QueryRow(ctx, `
			INSERT INTO users (email, is_admin, is_owner)
			VALUES ($1, NOT EXISTS (SELECT 1 FROM users), NOT EXISTS (SELECT 1 FROM users))
			RETURNING `+userColumns, id.Email))
		if err != nil {
			return User{}, "", fmt.Errorf("create sso user: %w", err)
		}
		outcome = LinkedCreated
	default:
		return User{}, "", fmt.Errorf("find user by email: %w", err)
	}

	if _, err := tx.Exec(ctx, `INSERT INTO user_identities (user_id, provider, issuer, subject, subject_format, email_at_link, provider_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		u.ID, id.Provider, id.Issuer, id.Subject, id.SubjectFormat, id.Email, id.ProviderID); err != nil {
		return User{}, "", fmt.Errorf("link identity: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, "", fmt.Errorf("commit link: %w", err)
	}
	return u, outcome, nil
}

// adoptEmail moves a linked account to the email its IdP now asserts, unless
// another account already holds it — then the account keeps its old email (the
// link, not the email, identifies the person). Best-effort: login proceeds
// either way.
func (r *Repository) adoptEmail(ctx context.Context, u User, email string) User {
	updated, err := scanUser(r.db.QueryRow(ctx, `UPDATE users SET email = $2, updated_at = now()
		WHERE id = $1 AND NOT EXISTS (SELECT 1 FROM users WHERE email = $2)
		RETURNING `+userColumns, u.ID, email))
	if err != nil {
		return u // taken (or raced): keep the current email
	}
	return updated
}
