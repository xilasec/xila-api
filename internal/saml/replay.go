package saml

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrReplay is returned when an assertion id has already been consumed.
var ErrReplay = errors.New("saml assertion already used")

// ReplayStore remembers consumed assertion ids in Postgres until the assertion
// would have expired anyway, so a captured SAMLResponse cannot be replayed —
// against this replica or any other.
type ReplayStore struct {
	db *pgxpool.Pool
}

// NewReplayStore constructs a ReplayStore.
func NewReplayStore(db *pgxpool.Pool) *ReplayStore {
	return &ReplayStore{db: db}
}

// Consume records the assertion id as used until `until`, or returns ErrReplay
// if it was already used. Expired ids are pruned on the way (indexed; cheap).
func (s *ReplayStore) Consume(ctx context.Context, assertionID string, until time.Time) error {
	if _, err := s.db.Exec(ctx, `DELETE FROM saml_seen_assertions WHERE expires_at < now()`); err != nil {
		return fmt.Errorf("prune seen assertions: %w", err)
	}
	tag, err := s.db.Exec(ctx, `INSERT INTO saml_seen_assertions (assertion_id, expires_at) VALUES ($1, $2)
		ON CONFLICT (assertion_id) DO NOTHING`, assertionID, until)
	if err != nil {
		return fmt.Errorf("record assertion: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrReplay
	}
	return nil
}
