package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/xilasec/xila-api/internal/user"
)

// Reset link lifetimes: a self-service email link is short-lived; one an admin
// hands over (chat, ticket) gets a day.
const (
	ResetMailTTL  = time.Hour
	ResetAdminTTL = 24 * time.Hour
)

// ChangePassword sets a new password for an authenticated user. Accounts that
// have a password must prove it; SSO-only accounts may add one (only usable when
// password sign-in is enabled). Every other session is revoked; the returned
// token keeps the caller signed in.
func (s *Service) ChangePassword(ctx context.Context, userID, current, next string) (string, user.User, error) {
	if len(next) < minPasswordLen {
		return "", user.User{}, ErrValidation
	}
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return "", user.User{}, err
	}
	if u.HasPassword && bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(current)) != nil {
		return "", user.User{}, ErrWrongPassword
	}
	return s.setPassword(ctx, u.ID, next)
}

// RevokeSessions signs the user out everywhere (every JWT issued so far) and
// returns a fresh token for the caller. It proves nothing about who is
// asking, so the new session keeps the caller's authTime.
func (s *Service) RevokeSessions(ctx context.Context, userID string, authTime time.Time) (string, user.User, error) {
	u, err := s.users.RevokeSessions(ctx, userID)
	if err != nil {
		return "", user.User{}, err
	}
	token, err := s.reissue(ctx, u, authTime)
	return token, u, err
}

// ErrNoLocalPassword: re-authentication by password for an account that
// signs in through an identity provider.
var ErrNoLocalPassword = errors.New("this account signs in through an identity provider; sign in again there")

// ErrCodeRequired: re-authentication of an account with two-factor on
// needs its current code too.
var ErrCodeRequired = errors.New("enter your two-factor code too")

// Reauthenticate proves the signed-in user is still at the keyboard (the
// password, and the TOTP or recovery code when two-factor is on) and returns
// a session whose auth_time is now. Sensitive actions (creating an API
// token) require a recent one.
func (s *Service) Reauthenticate(ctx context.Context, userID, password, code string) (string, user.User, error) {
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return "", user.User{}, err
	}
	if !u.HasPassword {
		return "", user.User{}, ErrNoLocalPassword
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return "", user.User{}, ErrWrongPassword
	}
	if s.mfaRequired(ctx, u) {
		if strings.TrimSpace(code) == "" {
			return "", user.User{}, ErrCodeRequired
		}
		if err := s.checkCode(ctx, u.ID, code); err != nil {
			return "", user.User{}, err
		}
	}
	token, err := s.TokenFor(ctx, u)
	return token, u, err
}

// RequestReset emails a reset link if the address belongs to an active account
// with a password (an SSO-only account resets at its IdP). It never says
// whether that was the case — the response is the same for every address — and
// is a no-op when email isn't configured.
func (s *Service) RequestReset(ctx context.Context, email string) {
	if s.mailer == nil || !s.mailer.SMTPConfigured() || s.publicURL == "" {
		slog.InfoContext(ctx, "password reset requested but email reset is unavailable (SMTP_* or PUBLIC_URL unset)")
		return
	}
	u, err := s.users.GetByEmail(ctx, normalizeEmail(email))
	if err != nil || u.Disabled() || !u.HasPassword || (!s.passwordLogin && !u.IsOwner) {
		return
	}
	link, _, err := s.resetLink(ctx, u.ID, ResetMailTTL)
	if err != nil {
		slog.ErrorContext(ctx, "password reset: create token", "error", err)
		return
	}
	body := fmt.Sprintf("Someone (hopefully you) asked to reset the password for %s on Xila.\n\n"+
		"Open this link within an hour to choose a new one:\n\n%s\n\n"+
		"If you didn't ask, ignore this email — your password stays as it is.\n", u.Email, link)
	// Mail delivery is slow; don't make the response time reveal that the
	// address exists.
	go func() {
		ctx := context.WithoutCancel(ctx)
		if err := s.mailer.SendText(ctx, u.Email, "Reset your Xila password", body); err != nil {
			slog.ErrorContext(ctx, "password reset: send mail", "user_id", u.ID, "error", err)
		}
	}()
}

// ResetLink mints a reset link for a user on an admin's behalf, for handing
// over out of band. It is the way to (re)gain a password without SMTP.
func (s *Service) ResetLink(ctx context.Context, userID string) (string, time.Time, error) {
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return "", time.Time{}, err
	}
	if u.IsService() {
		return "", time.Time{}, user.ErrNotFound // a service account has no password to reset
	}
	if u.Disabled() {
		return "", time.Time{}, user.ErrDisabled
	}
	return s.resetLink(ctx, u.ID, ResetAdminTTL)
}

// ConfirmReset redeems a reset token: sets the password, revokes every session
// and signs the user in.
func (s *Service) ConfirmReset(ctx context.Context, token, next string) (string, user.User, error) {
	if len(next) < minPasswordLen {
		return "", user.User{}, ErrValidation
	}
	u, err := s.users.ConsumeResetToken(ctx, hashResetToken(token))
	if err != nil {
		return "", user.User{}, err
	}
	tok, u, err := s.setPassword(ctx, u.ID, next)
	if err != nil {
		return "", user.User{}, err
	}
	// A reset link proves the mailbox, not the second factor.
	if s.mfaRequired(ctx, u) {
		return "", u, s.challenge(u)
	}
	return tok, u, nil
}

func (s *Service) setPassword(ctx context.Context, userID, password string) (string, user.User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", user.User{}, fmt.Errorf("hash password: %w", err)
	}
	u, err := s.users.SetPassword(ctx, userID, string(hash))
	if err != nil {
		return "", user.User{}, err
	}
	token, err := s.TokenFor(ctx, u)
	return token, u, err
}

// resetLink stores a new token (replacing earlier ones) and returns the link.
// Without PUBLIC_URL the link is relative; the UI prefixes its own origin.
func (s *Service) resetLink(ctx context.Context, userID string, ttl time.Duration) (string, time.Time, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	expires := time.Now().Add(ttl)
	if err := s.users.CreateResetToken(ctx, userID, hashResetToken(token), expires); err != nil {
		return "", time.Time{}, err
	}
	return s.publicURL + "/reset-password#token=" + token, expires, nil
}

func hashResetToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
