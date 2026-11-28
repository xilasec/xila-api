package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateAndParseToken(t *testing.T) {
	keys := NewKeys("test-secret", nil)
	token, err := generateToken(keys, "user-123", false, 0, time.Hour, time.Now(), "")
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}

	claims, err := ParseToken(keys, token)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Errorf("subject = %q, want user-123", claims.Subject)
	}
}

func TestParseTokenRejectsWrongSecret(t *testing.T) {
	token, err := generateToken(NewKeys("right-secret", nil), "user-123", false, 0, time.Hour, time.Now(), "")
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}
	if _, err := ParseToken(NewKeys("wrong-secret", nil), token); err == nil {
		t.Error("expected error for token signed with a different secret")
	}
}

func TestParseTokenRejectsExpired(t *testing.T) {
	keys := NewKeys("test-secret", nil)
	token, err := generateToken(keys, "user-123", false, 0, -time.Minute, time.Now(), "")
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}
	if _, err := ParseToken(keys, token); err == nil {
		t.Error("expected error for expired token")
	}
}

func TestParseTokenRejectsWrongSigningMethod(t *testing.T) {
	// A token signed with "none" must be rejected: our parser pins HMAC.
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, Claims{
		Subject: "attacker",
	})
	raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if _, err := ParseToken(NewKeys("test-secret", nil), raw); err == nil {
		t.Error("expected error for 'none' signing method")
	}
}

// A token signed with the current secret carries that secret's kid, and a
// legacy token with no kid header (as every JWT was before key rings
// existed) is still accepted against the current secret.
func TestParseTokenByKid(t *testing.T) {
	keys := NewKeys("current-secret", []string{"old-secret-1", "old-secret-2"})
	token, err := generateToken(keys, "user-123", false, 0, time.Hour, time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	parsed, _, _ := jwt.NewParser().ParseUnverified(token, &Claims{})
	if kid, _ := parsed.Header["kid"].(string); kid == "" {
		t.Error("signed token carries no kid header")
	}

	legacy, err := jwt.NewWithClaims(jwt.SigningMethodHS256, Claims{
		Subject: "user-456", ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	}).SignedString([]byte("current-secret"))
	if err != nil {
		t.Fatal(err)
	}
	if claims, err := ParseToken(keys, legacy); err != nil || claims.Subject != "user-456" {
		t.Errorf("legacy kid-less token (current secret) = %v, %v", claims, err)
	}
}

// A session signed with a secret since rotated out of JWT_SECRET into
// JWT_PREVIOUS_SECRETS still authenticates (verify-only), and stops once that
// secret is removed from the ring entirely.
func TestParseTokenVerifiesWithPreviousSecret(t *testing.T) {
	old := NewKeys("secret-a", nil)
	token, err := generateToken(old, "user-123", false, 0, time.Hour, time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}

	rotated := NewKeys("secret-b", []string{"secret-a"})
	claims, err := ParseToken(rotated, token)
	if err != nil || claims.Subject != "user-123" {
		t.Fatalf("verify with previous secret = %v, %v", claims, err)
	}

	removed := NewKeys("secret-b", nil)
	if _, err := ParseToken(removed, token); err == nil {
		t.Error("token signed with a secret no longer in the ring (current or previous) was accepted")
	}
}

// A token whose kid names a secret the ring doesn't have (neither current
// nor previous) is refused outright, never tried against every key.
func TestParseTokenRejectsUnknownKid(t *testing.T) {
	signed := NewKeys("secret-a", nil)
	token, err := generateToken(signed, "user-123", false, 0, time.Hour, time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	other := NewKeys("secret-b", []string{"secret-c"})
	if _, err := ParseToken(other, token); err == nil {
		t.Error("expected error for a kid naming a key outside the ring")
	}
}

// Update swaps the ring atomically: tokens signed before and after the swap
// both keep verifying as long as the old secret stays in Previous.
func TestKeysUpdateSwapsAtomically(t *testing.T) {
	keys := NewKeys("secret-a", nil)
	before, err := generateToken(keys, "user-123", false, 0, time.Hour, time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	keys.Update("secret-b", []string{"secret-a"})
	after, err := generateToken(keys, "user-456", false, 0, time.Hour, time.Now(), "")
	if err != nil {
		t.Fatal(err)
	}
	if claims, err := ParseToken(keys, before); err != nil || claims.Subject != "user-123" {
		t.Errorf("pre-rotation token after Update = %v, %v", claims, err)
	}
	if claims, err := ParseToken(keys, after); err != nil || claims.Subject != "user-456" {
		t.Errorf("post-rotation token = %v, %v", claims, err)
	}
	keys.Update("secret-b", nil) // old secret fully removed
	if _, err := ParseToken(keys, before); err == nil {
		t.Error("token signed with the fully-removed secret was still accepted")
	}
}
