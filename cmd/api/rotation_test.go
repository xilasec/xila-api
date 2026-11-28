package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/secretbox"
	"github.com/xilasec/xila-api/internal/sso"
)

// Rotating JWT_SECRET and INTEGRATION_SECRET_KEY through their mounted files
// re-keys the running process: sessions and sealed values from before stay
// valid through the _PREVIOUS lists, new ones use the new keys, and a
// rotation that fails boot's checks is refused without touching the keys.
func TestKeyRotationFromRefreshedFiles(t *testing.T) {
	dir := t.TempDir()
	file := func(name, content string) string {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	keyA := base64.StdEncoding.EncodeToString(make([]byte, 32))
	keyB := base64.StdEncoding.EncodeToString([]byte("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
	const secretA, secretB = "jwt-secret-a-0123456789abcdef", "jwt-secret-b-0123456789abcdef" // gitleaks:allow -- fake secrets for an in-process rotation test

	t.Setenv("APP_ENV", "development")
	for _, k := range []string{"JWT_SECRET", "JWT_PREVIOUS_SECRETS", "INTEGRATION_SECRET_KEY", "INTEGRATION_SECRET_KEY_PREVIOUS"} {
		t.Setenv(k, "")
		os.Unsetenv(k)
	}
	t.Setenv("JWT_SECRET_FILE", file("jwt", secretA))
	t.Setenv("JWT_PREVIOUS_SECRETS_FILE", file("jwt-prev", ""))
	t.Setenv("INTEGRATION_SECRET_KEY_FILE", file("key", keyA))
	t.Setenv("INTEGRATION_SECRET_KEY_PREVIOUS_FILE", file("key-prev", ""))
	t.Setenv("SECRETS_REFRESH_INTERVAL", "20ms")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	primary, _ := cfg.IntegrationKey()
	ring, err := secretbox.NewKeyring(primary, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := auth.NewKeys(cfg.JWT.Secret, cfg.JWT.Previous)
	wireKeyRotation(cfg, keys, ring, sso.NewRegistry(nil, sso.EnvProviders(cfg), nil))
	ctx := t.Context()
	go cfg.Secrets.Run(ctx)

	sealed, err := ring.Seal("token", "aad")
	if err != nil {
		t.Fatal(err)
	}
	sign := func(secret string) string {
		s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, auth.Claims{
			Subject: "u", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		}).SignedString([]byte(secret))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	verifies := func(token string) bool { _, err := auth.ParseToken(keys, token); return err == nil }
	tokenA, tokenB := sign(secretA), sign(secretB)
	if !verifies(tokenA) || verifies(tokenB) {
		t.Fatal("before rotation: want A valid, B not")
	}

	// Rotate: previous lists first, then the new primaries.
	file("jwt-prev", secretA)
	file("key-prev", keyA)
	file("jwt", secretB)
	file("key", keyB)
	eventually(t, "rotation applied", func() bool {
		_, tier, err := ring.OpenTier(sealed, "aad")
		return err == nil && tier != "" && tier != tierOf(t, ring) && verifies(tokenA) && verifies(tokenB)
	})

	// A refused rotation (JWT_PREVIOUS_SECRETS repeating the current secret)
	// leaves both rings exactly as they were.
	file("jwt-prev", secretB)
	time.Sleep(200 * time.Millisecond) // several refresh ticks
	if !verifies(tokenA) || !verifies(tokenB) {
		t.Error("a refused rotation changed the JWT keys")
	}
	if got, err := ring.Open(sealed, "aad"); err != nil || got != "token" {
		t.Errorf("a refused rotation changed the integration keys: %q, %v", got, err)
	}
}

// tierOf is the tier a value sealed now opens with (the primary's).
func tierOf(t *testing.T, ring *secretbox.Keyring) string {
	t.Helper()
	fresh, err := ring.Seal("probe", "aad")
	if err != nil {
		t.Fatal(err)
	}
	_, tier, err := ring.OpenTier(fresh, "aad")
	if err != nil {
		t.Fatal(err)
	}
	return tier
}

func eventually(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
