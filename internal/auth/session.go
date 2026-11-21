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

// Create records a new session's start, called once at sign-in.
func (s *SessionStore) Create(ctx context.Context, id, userID string) error {
	if _, err := s.db.Exec(ctx, `INSERT INTO user_sessions (id, user_id) VALUES ($1, $2)`, id, userID); err != nil {
		return fmt.Errorf("create session: %w", err)
	}
	return nil
}

// Session-liveness errors. ErrSessionNotFound covers a purged row and a
// session id from before tracking existed — both are treated as expired, the
// safe default.
var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionIdle     = errors.New("session idle timeout")
	ErrSessionExpired  = errors.New("session expired")
)

// Touch reports whether session id is still within its idle and absolute
// limits, bumping last_seen_at — but only when it is already stale by more
// than a minute, so a busy tab costs one write per session per minute, not
// one per request. The read and the conditional write are a single round
// trip: the "s" CTE sees the row as of the start of the statement, so the
// idle check always compares against the activity recorded before this
// request, never against the bump this same call might make.
func (s *SessionStore) Touch(ctx context.Context, id string, idleTimeout, maxAge time.Duration) error {
	var createdAt, lastSeenAt time.Time
	err := s.db.QueryRow(ctx, `
		WITH s AS (
			SELECT created_at, last_seen_at FROM user_sessions WHERE id = $1
		), upd AS (
			UPDATE user_sessions SET last_seen_at = now()
			WHERE id = $1 AND (SELECT last_seen_at FROM s) < now() - interval '1 minute'
			RETURNING 1
		)
		SELECT created_at, last_seen_at FROM s`, id).Scan(&createdAt, &lastSeenAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrSessionNotFound
	}
	if err != nil {
		return fmt.Errorf("touch session: %w", err)
	}
	now := time.Now()
	if idleTimeout > 0 && now.Sub(lastSeenAt) > idleTimeout {
		return ErrSessionIdle
	}
	if maxAge > 0 && now.Sub(createdAt) > maxAge {
		return ErrSessionExpired
	}
	return nil
}
