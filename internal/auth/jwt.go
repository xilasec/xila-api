package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims are the JWT claims embedded in an access token.
type Claims struct {
	IsAdmin bool `json:"admin,omitempty"`
	// TokenVersion is the user's token_version at signing; the middleware
	// rejects the token once it no longer matches (password change, "sign out
	// everywhere", deactivation).
	TokenVersion int `json:"tv"`
	// Purpose is empty for a session; PurposeMFA marks a sign-in challenge,
	// which the middleware never accepts as a session.
	Purpose string `json:"purpose,omitempty"`
	// ServiceAccount marks a session of a service account (minted by the
	// workload-identity token exchange).
	ServiceAccount bool `json:"svc,omitempty"`
	// ProjectID confines the session to one project, like a project-scoped
	// API token (a federation binding's project).
	ProjectID string `json:"prj,omitempty"`
	jwt.RegisteredClaims
}

// PurposeMFA marks a two-factor sign-in challenge token.
const PurposeMFA = "mfa"

// generateToken signs a short-lived HS256 access token for the given user.
func generateToken(secret, userID string, isAdmin bool, tokenVersion int, ttl time.Duration) (string, error) {
	return signClaims(secret, Claims{IsAdmin: isAdmin, TokenVersion: tokenVersion}, userID, ttl)
}

// signClaims stamps subject, issue and expiry times onto claims and signs them.
func signClaims(secret string, claims Claims, userID string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Subject:   userID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

// ParseToken validates a token's signature and expiry and returns its claims.
// Provided for use by an auth middleware on protected routes.
func ParseToken(secret, tokenString string) (*Claims, error) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	return claims, nil
}
