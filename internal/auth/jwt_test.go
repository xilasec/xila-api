package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestGenerateAndParseToken(t *testing.T) {
	const secret = "test-secret"
	token, err := generateToken(secret, "user-123", false, 0, time.Hour, time.Now())
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}

	claims, err := ParseToken(secret, token)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if claims.Subject != "user-123" {
		t.Errorf("subject = %q, want user-123", claims.Subject)
	}
}

func TestParseTokenRejectsWrongSecret(t *testing.T) {
	token, err := generateToken("right-secret", "user-123", false, 0, time.Hour, time.Now())
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}
	if _, err := ParseToken("wrong-secret", token); err == nil {
		t.Error("expected error for token signed with a different secret")
	}
}

func TestParseTokenRejectsExpired(t *testing.T) {
	token, err := generateToken("test-secret", "user-123", false, 0, -time.Minute, time.Now())
	if err != nil {
		t.Fatalf("generateToken: %v", err)
	}
	if _, err := ParseToken("test-secret", token); err == nil {
		t.Error("expected error for expired token")
	}
}

func TestParseTokenRejectsWrongSigningMethod(t *testing.T) {
	// A token signed with "none" must be rejected: our parser pins HMAC.
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, Claims{
		RegisteredClaims: jwt.RegisteredClaims{Subject: "attacker"},
	})
	raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if _, err := ParseToken("test-secret", raw); err == nil {
		t.Error("expected error for 'none' signing method")
	}
}
