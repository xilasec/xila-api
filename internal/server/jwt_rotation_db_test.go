package server

import (
	"net/http"
	"testing"

	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// A session signed with JWT_SECRET before a rotation keeps authenticating
// once the new secret becomes current and the old one moves to
// JWT_PREVIOUS_SECRETS, and stops as soon as the old secret is dropped —
// exactly the sequence an operator follows to rotate JWT_SECRET without
// ending every session.
func TestJWTRotationKeepsSessionsUntilPreviousRemoved(t *testing.T) {
	pool := pgtest.Pool(t)

	before := newTestAppOn(t, pool, func(c *config.Config) { c.JWT.Secret = "secret-a" })
	token := rbacUser(t, before, "alice@xila.io")

	rotated := newTestAppOn(t, pool, func(c *config.Config) {
		c.JWT.Secret = "secret-b"
		c.JWT.Previous = []string{"secret-a"}
	})
	if resp, body := req(t, rotated, http.MethodGet, "/api/v1/me", token, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-rotation session rejected right after rotating JWT_SECRET: %d %v", resp.StatusCode, body)
	}

	removed := newTestAppOn(t, pool, func(c *config.Config) { c.JWT.Secret = "secret-b" })
	if resp, body := req(t, removed, http.MethodGet, "/api/v1/me", token, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("pre-rotation session still accepted once its secret was dropped from JWT_PREVIOUS_SECRETS: %d %v", resp.StatusCode, body)
	}

	// A fresh sign-in against the rotated app signs with the new secret and
	// keeps working with the old secret gone entirely.
	fresh := rbacUser(t, rotated, "bob@xila.io")
	if resp, body := req(t, removed, http.MethodGet, "/api/v1/me", fresh, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("session signed with the new secret rejected: %d %v", resp.StatusCode, body)
	}
}
