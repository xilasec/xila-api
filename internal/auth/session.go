package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SessionStore tracks one row per browser session (password, SSO and LDAP
// logins alike) for the idle timeout and absolute session lifetime
// (SESSION_IDLE_TIMEOUT / SESSION_MAX_AGE). API tokens and service-account /
// federated sessions never get a row — they mint their claims with
// signClaims directly, bypassing newSession.
type SessionStore struct{ db *pgxpool.Pool }

// NewSessionStore constructs a SessionStore.
func NewSessionStore(db *pgxpool.Pool) *SessionStore { return &SessionStore{db: db} }

// TrackingActive reports whether per-session idle/absolute tracking does
// anything beyond what the JWT's own "exp" claim already enforces: an idle
// timeout is configured, or the max age is set shorter than the token's own
// TTL (the default, MaxAge == TTL, is exactly what "exp" already checks).
// When false, newSession mints no session id and no row is written or read —
// an untouched install pays nothing extra per request.
func TrackingActive(idleTimeout, maxAge, ttl time.Duration) bool {
	return idleTimeout > 0 || (maxAge > 0 && maxAge < ttl)
}

// Create records a new session. createdAt is when the user last proved who
// they are (the session's auth_time), so the absolute lifetime runs from the
// sign-in even across a reissue ("sign out everywhere" mints a new session
// without new credentials and must not extend it).
func (s *SessionStore) Create(ctx context.Context, id, userID string, createdAt time.Time) error {
	if _, err := s.db.Exec(ctx, `INSERT INTO user_sessions (id, user_id, created_at) VALUES ($1, $2, $3)`,
		id, userID, createdAt); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// Session-liveness errors. ErrSessionNotFound covers a purged row and a
// session id from before tracking existed: both are treated as expired, the
// safe default.
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionIdle     = errors.New("session idle timeout")
	ErrSessionExpired  = errors.New("session expired")
)

// Touch reports whether session id is still within its idle and absolute
// limits. With active set, a live session's last_seen_at is bumped, but only
// when it is more than a minute stale, so a busy tab costs one write per minute rather than
// one per request. An expired session is deleted, never bumped: a refused
// request must not reset the clock, or simply retrying would revive an idle
// session. The verdict is computed by the database (one clock for every
// replica) in the same statement as the write. A background request (the
// UI's polling) passes active=false: it is checked but is not activity, or an
// open tab would keep its session alive forever.
func (s *SessionStore) Touch(ctx context.Context, id string, idleTimeout, maxAge time.Duration, active bool) error {
	var idle, aged bool
	err := s.db.QueryRow(ctx, `
		WITH s AS (
			SELECT ($2 > 0 AND last_seen_at < now() - make_interval(secs => $2)) AS idle,
			       ($3 > 0 AND created_at < now() - make_interval(secs => $3)) AS aged,
			       last_seen_at
			FROM user_sessions WHERE id = $1
		), gone AS (
			DELETE FROM user_sessions WHERE id = $1 AND EXISTS (SELECT 1 FROM s WHERE idle OR aged)
			RETURNING 1
		), seen AS (
			UPDATE user_sessions SET last_seen_at = now()
			WHERE id = $1 AND $4 AND EXISTS (SELECT 1 FROM s WHERE NOT idle AND NOT aged AND last_seen_at < now() - interval '1 minute')
			RETURNING 1
		)
		SELECT idle, aged FROM s`, id, idleTimeout.Seconds(), maxAge.Seconds(), active).Scan(&idle, &aged)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return ErrSessionNotFound
	case err != nil:
		return fmt.Errorf("touch session: %w", err)
	case idle:
		return ErrSessionIdle
	case aged:
		return ErrSessionExpired
	}
	return nil
}

// Purge deletes the sessions that can no longer be used: idle past
// idleTimeout or older than maxAge (a request for one would find it expired).
func (s *SessionStore) Purge(ctx context.Context, idleTimeout, maxAge time.Duration) (int64, error) {
	tag, err := s.db.Exec(ctx, `DELETE FROM user_sessions
		WHERE ($1 > 0 AND last_seen_at < now() - make_interval(secs => $1))
		   OR ($2 > 0 AND created_at < now() - make_interval(secs => $2))`, idleTimeout.Seconds(), maxAge.Seconds())
	if err != nil {
		return 0, fmt.Errorf("purge sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}
