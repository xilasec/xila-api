package apitoken_test

import (
	"context"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/apitoken"
	"github.com/xilasec/xila-api/internal/pgtest"
)

func TestGenerateValidateRevoke(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()

	var userID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash) VALUES ('t@x.co', 'x') RETURNING id`).Scan(&userID); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	svc := apitoken.NewService(apitoken.NewRepository(pool))

	tok, secret, err := svc.Generate(ctx, userID, "ci", nil, 0)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(secret) < 20 || tok.Prefix != secret[:12] {
		t.Errorf("secret/prefix wrong: %q / %q", secret, tok.Prefix)
	}

	// Valid token resolves to the owner.
	actor, err := svc.ValidateToken(ctx, secret)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if actor.UserID != userID || !actor.IsToken {
		t.Errorf("actor = %+v, want user %s token", actor, userID)
	}

	// Garbage token is rejected.
	if _, err := svc.ValidateToken(ctx, "xila_notarealtoken"); err == nil {
		t.Error("expected error for unknown token")
	}

	// Expired token is rejected.
	repo := apitoken.NewRepository(pool)
	_, expiredSecret, err := svc.Generate(ctx, userID, "old", nil, time.Millisecond)
	if err != nil {
		t.Fatalf("generate expired: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	if _, err := svc.ValidateToken(ctx, expiredSecret); err == nil {
		t.Error("expected expired token to be rejected")
	}

	// Revocation removes it.
	if err := repo.Delete(ctx, tok.ID, userID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.ValidateToken(ctx, secret); err == nil {
		t.Error("expected revoked token to be rejected")
	}
}
