package auth

import (
	"errors"
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
	// AuthTime is when the user last proved who they are (a sign-in, MFA,
	// SSO, a password change or reset, re-authentication), as Unix seconds.
	// Reissuing a session ("sign out everywhere") carries it over unchanged,
	// so a fresh token never counts as a fresh sign-in by itself.
	AuthTime int64 `json:"auth_time,omitempty"`
	// SessionID names this session's user_sessions row, read by the idle
	// timeout / absolute-lifetime check (SessionStore.Touch). Empty when
	// tracking is off, for a service-account/federated session, or for a
	// token minted before this existed — all treated as "nothing to check".
	SessionID string `json:"sid,omitempty"`
	jwt.RegisteredClaims
}

// PurposeMFA marks a two-factor sign-in challenge token.
const PurposeMFA = "mfa"

// generateToken signs a short-lived HS256 access token for the given user,
// who last authenticated at authTime. sessionID is empty unless per-session
// idle/absolute tracking is active (SessionStore.TrackingActive).
func generateToken(keys *Keys, userID string, isAdmin bool, tokenVersion int, ttl time.Duration, authTime time.Time, sessionID string) (string, error) {
	return signClaims(keys, Claims{IsAdmin: isAdmin, TokenVersion: tokenVersion, AuthTime: authTime.Unix(), SessionID: sessionID}, userID, ttl)
}

// signClaims stamps subject, issue and expiry times onto claims and signs
// them with the ring's current secret (a `kid` header names it).
func signClaims(keys *Keys, claims Claims, userID string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims.RegisteredClaims = jwt.RegisteredClaims{
		Subject:   userID,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	}
	current, currentID, _, _ := keys.snapshot()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = currentID
	signed, err := token.SignedString([]byte(current))
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return signed, nil
}

// ParseToken validates a token's signature and expiry and returns its
// claims. The secret is picked from keys by the token's `kid` header; a
// token with no kid (issued before key rings existed) is tried against the
// current secret, then every previous one, oldest first. Provided for use by
// an auth middleware on protected routes.
func ParseToken(keys *Keys, tokenString string) (*Claims, error) {
	peeked, _, err := jwt.NewParser().ParseUnverified(tokenString, &Claims{})
	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	current, currentID, previous, legacy := keys.snapshot()
	kid, _ := peeked.Header["kid"].(string)
	var candidates []string
	switch {
	case kid == "":
		candidates = append([]string{current}, legacy...)
	case kid == currentID:
		candidates = []string{current}
	default:
		secret, ok := previous[kid]
		if !ok {
			return nil, errors.New("parse token: unknown signing key")
		}
		candidates = []string{secret}
	}
	var lastErr error
	for _, secret := range candidates {
		claims := &Claims{}
		_, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return []byte(secret), nil
		})
		if err == nil {
			return claims, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("parse token: %w", lastErr)
}
