package apitoken

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/xilasec/xila-api/internal/auth"
)

// ErrExpired is returned when a valid token has passed its expiry.
var ErrExpired = errors.New("api token expired")

// Service issues and validates API tokens. It satisfies auth.TokenValidator.
type Service struct {
	repo *Repository
}

// NewService constructs a Service.
func NewService(repo *Repository) *Service {
	return &Service{repo: repo}
}

// Generate mints a new token and returns the one-time plaintext secret alongside
// the stored record. projectID may be nil (account-wide); ttl <= 0 means no expiry.
func (s *Service) Generate(ctx context.Context, userID, name string, projectID *string, ttl time.Duration) (Token, string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return Token{}, "", fmt.Errorf("generate token: %w", err)
	}
	secret := auth.TokenPrefix + base64.RawURLEncoding.EncodeToString(buf)

	var expires *time.Time
	if ttl > 0 {
		t := time.Now().Add(ttl)
		expires = &t
	}

	tok, err := s.repo.Create(ctx, Token{
		CreatedBy: userID,
		ProjectID: projectID,
		Name:      name,
		Prefix:    secret[:12], // "xila_" + 7 chars, enough to identify
		ExpiresAt: expires,
	}, hashToken(secret))
	if err != nil {
		return Token{}, "", err
	}
	return tok, secret, nil
}

// ValidateToken implements auth.TokenValidator: it resolves a presented token to
// an Actor, rejecting unknown or expired tokens.
func (s *Service) ValidateToken(ctx context.Context, raw string) (auth.Actor, error) {
	tok, err := s.repo.GetByHash(ctx, hashToken(raw))
	if err != nil {
		return auth.Actor{}, err
	}
	if tok.ExpiresAt != nil && tok.ExpiresAt.Before(time.Now()) {
		return auth.Actor{}, ErrExpired
	}
	_ = s.repo.TouchLastUsed(ctx, tok.ID) // best effort

	actor := auth.Actor{UserID: tok.CreatedBy, IsToken: true, TokenID: tok.ID, IsServiceAccount: tok.OwnerIsService}
	if tok.ProjectID != nil {
		actor.ProjectID = *tok.ProjectID
	}
	return actor, nil
}

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
