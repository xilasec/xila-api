package saml

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/sso"
	"github.com/xilasec/xila-api/internal/user"
)

// Revoker ends every session of a user — bumping token_version, the only
// granularity Xila's sessions have. Satisfied by user.Repository; used to end
// a user's Xila session(s) when an IdP's LogoutRequest names them.
type Revoker interface {
	RevokeSessions(ctx context.Context, userID string) (user.User, error)
}

// SessionStore persists the NameID (+ SessionIndex) a SAML login was made
// under, for Single Logout: it implements sso.SAMLSessionStore (so
// sso.Service can find a user's latest session to start an SP-initiated
// logout) and additionally resolves an IdP-initiated LogoutRequest's
// (provider, NameID, SessionIndex) to the Xila user(s) to sign out.
type SessionStore struct {
	db      *pgxpool.Pool
	revoker Revoker
}

// NewSessionStore constructs a SessionStore.
func NewSessionStore(db *pgxpool.Pool, revoker Revoker) *SessionStore {
	return &SessionStore{db: db, revoker: revoker}
}

// prune drops rows that have expired — by then the JWT they exist for has
// expired too. Run on every write/lookup, like saml.ReplayStore does.
func (s *SessionStore) prune(ctx context.Context) {
	if _, err := s.db.Exec(ctx, `DELETE FROM saml_sessions WHERE expires_at < now()`); err != nil {
		// Non-fatal: an unpruned row only means a login that would have been
		// missed anyway (its JWT already expired) stays matchable a bit longer.
		_ = err
	}
}

// providerColumns derives (provider_id, env_provider) from p the same way
// user_identities/sso_group_mappings do: a database provider's own uuid, or
// NULL + env_provider for the (at most one) provider configured by
// environment. sso.Provider keeps that logic private, so it is redone here
// from its public Env()/ID.
func providerColumns(p sso.Provider) (providerID *string, envProvider bool) {
	if p.Env() {
		return nil, true
	}
	if p.ID == "" {
		return nil, false
	}
	id := p.ID
	return &id, false
}

// Record remembers a SAML login (sso.SAMLSessionStore).
func (s *SessionStore) Record(ctx context.Context, userID string, p sso.Provider, nameID, nameIDFormat, sessionIndex string, expires time.Time) error {
	s.prune(ctx)
	providerID, envProvider := providerColumns(p)
	_, err := s.db.Exec(ctx, `INSERT INTO saml_sessions
		(user_id, provider_id, env_provider, name_id, name_id_format, session_index, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		userID, providerID, envProvider, nameID, nameIDFormat, sessionIndex, expires)
	if err != nil {
		return fmt.Errorf("record saml session: %w", err)
	}
	return nil
}

const sessionSelect = `
	SELECT ss.id, CASE WHEN ss.env_provider THEN 'saml' ELSE sp.slug END,
	       ss.name_id, ss.name_id_format, ss.session_index
	FROM saml_sessions ss
	LEFT JOIN sso_providers sp ON sp.id = ss.provider_id`

func scanSession(row pgx.Row) (sso.SAMLSession, error) {
	var sess sso.SAMLSession
	err := row.Scan(&sess.ID, &sess.ProviderSlug, &sess.NameID, &sess.NameIDFormat, &sess.SessionIndex)
	return sess, err
}

// Latest returns the most recently recorded, unexpired SAML session for
// userID (sso.SAMLSessionStore).
func (s *SessionStore) Latest(ctx context.Context, userID string) (sso.SAMLSession, bool, error) {
	s.prune(ctx)
	sess, err := scanSession(s.db.QueryRow(ctx, sessionSelect+`
		WHERE ss.user_id = $1 AND ss.expires_at > now() ORDER BY ss.created_at DESC LIMIT 1`, userID))
	if errors.Is(err, pgx.ErrNoRows) {
		return sso.SAMLSession{}, false, nil
	}
	if err != nil {
		return sso.SAMLSession{}, false, fmt.Errorf("find latest saml session: %w", err)
	}
	return sess, true, nil
}

// End removes a recorded session (sso.SAMLSessionStore).
func (s *SessionStore) End(ctx context.Context, id string) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM saml_sessions WHERE id = $1`, id); err != nil {
		return fmt.Errorf("end saml session: %w", err)
	}
	return nil
}

// EndByIdentity ends every Xila session whose SAML login at provider p
// matches nameID (and sessionIndex, when the IdP's LogoutRequest carried
// one — omitted, per the SAML spec, means every session for that principal at
// that IdP). Each matched user is signed out at most once; the matched rows
// are then removed. Returns how many users were signed out, for logging.
func (s *SessionStore) EndByIdentity(ctx context.Context, p sso.Provider, nameID, sessionIndex string) (int, error) {
	s.prune(ctx)
	providerID, envProvider := providerColumns(p)
	query := `SELECT ss.id, ss.user_id FROM saml_sessions ss
		WHERE ss.env_provider = $1 AND ss.provider_id IS NOT DISTINCT FROM $2 AND ss.name_id = $3`
	args := []any{envProvider, providerID, nameID}
	if sessionIndex != "" {
		query += ` AND ss.session_index = $4`
		args = append(args, sessionIndex)
	}
	rows, err := s.db.Query(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("find saml sessions by identity: %w", err)
	}
	type match struct{ id, userID string }
	var matches []match
	for rows.Next() {
		var m match
		if err := rows.Scan(&m.id, &m.userID); err != nil {
			rows.Close()
			return 0, fmt.Errorf("scan saml session: %w", err)
		}
		matches = append(matches, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	seen := map[string]bool{}
	var ids []string
	for _, m := range matches {
		ids = append(ids, m.id)
		if seen[m.userID] {
			continue
		}
		seen[m.userID] = true
		if _, err := s.revoker.RevokeSessions(ctx, m.userID); err != nil {
			return len(seen) - 1, fmt.Errorf("revoke sessions for %s: %w", m.userID, err)
		}
	}
	if len(ids) > 0 {
		if _, err := s.db.Exec(ctx, `DELETE FROM saml_sessions WHERE id = ANY($1::uuid[])`, ids); err != nil {
			return len(seen), fmt.Errorf("remove ended saml sessions: %w", err)
		}
	}
	return len(seen), nil
}
