package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // RFC 6238 TOTP is HMAC-SHA1 for every authenticator app
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/user"
)

// MFA errors.
var (
	// ErrMFAUnavailable: two-factor needs INTEGRATION_SECRET_KEY to seal secrets.
	ErrMFAUnavailable = errors.New("two-factor authentication needs INTEGRATION_SECRET_KEY on the server")
	// ErrInvalidCode: a wrong, expired or already-used code.
	ErrInvalidCode = errors.New("that code is not valid")
	// ErrChallengeExpired: the sign-in challenge is invalid or older than MFATTL.
	ErrChallengeExpired = errors.New("the sign-in attempt expired — sign in again")
	// ErrTooManyAttempts: too many wrong codes for this account.
	ErrTooManyAttempts = errors.New("too many attempts — wait a few minutes and sign in again")
)

// TOTP parameters (RFC 6238 defaults every authenticator app uses).
const (
	totpStep    = 30 * time.Second
	totpDigits  = 6
	totpSkew    = 1 // steps accepted either side of now (clock drift)
	MFATTL      = 5 * time.Minute
	mfaAttempts = 5
	mfaWindow   = 15 * time.Minute
	issuerName  = "Xila"
	recoveryN   = 10
)

// MFARequiredError is returned by a sign-in that passed the first factor:
// the second step posts Token with a code to /auth/mfa.
type MFARequiredError struct{ Token string }

func (e *MFARequiredError) Error() string { return "two-factor code required" }

// Sealer encrypts the TOTP secret at rest (secretbox.Cipher).
type Sealer interface {
	Seal(plaintext, aad string) ([]byte, error)
	Open(sealed []byte, aad string) (string, error)
}

// AttemptLimiter counts code attempts per account (ratelimit.Limiter).
type AttemptLimiter interface {
	Hit(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error)
}

// EnableMFA turns on two-factor support. limiter may be nil (no attempt cap).
// A sealer that can't seal — nil, or an unconfigured *secretbox.Keyring (no
// INTEGRATION_SECRET_KEY), which is a non-nil interface — leaves two-factor
// unavailable (ErrMFAUnavailable) instead of failing every setup.
func (s *Service) EnableMFA(sealer Sealer, limiter AttemptLimiter) {
	if sealer != nil {
		if _, err := sealer.Seal("probe", mfaAAD("probe")); err != nil {
			sealer = nil
		}
	}
	s.sealer, s.limiter = sealer, limiter
}

// MFAAvailable reports whether accounts can turn two-factor on.
func (s *Service) MFAAvailable() bool { return s.sealer != nil }

func mfaAAD(userID string) string { return "mfa:" + userID }

// --- TOTP ---

func totpAt(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step)) //nolint:gosec // G115: the RFC 6238 counter is the uint64 bit pattern of a non-negative Unix time step
	mac := hmac.New(sha1.New, secret)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	code := (binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff) % 1_000_000
	return fmt.Sprintf("%0*d", totpDigits, code)
}

// matchTOTP returns the time step code is valid for (within the skew), or -1.
func matchTOTP(secret []byte, code string, now time.Time) int64 {
	cur := now.Unix() / int64(totpStep.Seconds())
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		if hmac.Equal([]byte(totpAt(secret, cur+d)), []byte(code)) {
			return cur + d
		}
	}
	return -1
}

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func (s *Service) secretOf(ctx context.Context, userID string) ([]byte, user.MFAState, error) {
	st, err := s.users.GetMFA(ctx, userID)
	if err != nil {
		return nil, st, err
	}
	if st.SealedSecret == nil {
		return nil, st, nil
	}
	if s.sealer == nil {
		return nil, st, ErrMFAUnavailable
	}
	enc, err := s.sealer.Open(st.SealedSecret, mfaAAD(userID))
	if err != nil {
		return nil, st, fmt.Errorf("open mfa secret: %w", err)
	}
	secret, err := b32.DecodeString(enc)
	return secret, st, err
}

// --- enrollment ---

// MFASetup is enrollment step 1: the secret to add to an authenticator app.
type MFASetup struct {
	Secret     string `json:"secret"`      // base32, for typing in
	OTPAuthURL string `json:"otpauth_url"` // for a QR code
}

// SetupMFA generates a new (pending) secret. It only takes effect once a code
// from it is confirmed with ConfirmMFA.
func (s *Service) SetupMFA(ctx context.Context, userID string) (MFASetup, error) {
	if s.sealer == nil {
		return MFASetup{}, ErrMFAUnavailable
	}
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return MFASetup{}, err
	}
	raw := make([]byte, 20)
	if _, err := rand.Read(raw); err != nil {
		return MFASetup{}, err
	}
	enc := b32.EncodeToString(raw)
	sealed, err := s.sealer.Seal(enc, mfaAAD(userID))
	if err != nil {
		return MFASetup{}, err
	}
	if err := s.users.SetPendingMFA(ctx, userID, sealed); err != nil {
		return MFASetup{}, err
	}
	label := url.PathEscape(issuerName + ":" + u.Email)
	q := url.Values{"secret": {enc}, "issuer": {issuerName}, "digits": {"6"}, "period": {"30"}, "algorithm": {"SHA1"}}
	return MFASetup{Secret: enc, OTPAuthURL: "otpauth://totp/" + label + "?" + q.Encode()}, nil
}

// ConfirmMFA activates the pending secret if code matches it, returning the
// recovery codes (shown once).
func (s *Service) ConfirmMFA(ctx context.Context, userID, code string) ([]string, error) {
	secret, st, err := s.secretOf(ctx, userID)
	if err != nil {
		return nil, err
	}
	if st.Enabled {
		return nil, user.ErrMFAEnabled
	}
	if secret == nil {
		return nil, ErrInvalidCode
	}
	step := matchTOTP(secret, normalizeCode(code), time.Now())
	if step < 0 {
		return nil, ErrInvalidCode
	}
	codes := make([]string, recoveryN)
	hashes := make([]string, recoveryN)
	for i := range codes {
		raw := make([]byte, 5)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		c := strings.ToLower(b32.EncodeToString(raw)) // 8 chars
		codes[i] = c[:4] + "-" + c[4:]
		hashes[i] = hashCode(codes[i])
	}
	if err := s.users.EnableMFA(ctx, userID, step, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// DisableMFA turns two-factor off for a user who proves it with a current
// code or a recovery code.
func (s *Service) DisableMFA(ctx context.Context, userID, code string) error {
	if err := s.checkCode(ctx, userID, code); err != nil {
		return err
	}
	return s.users.DisableMFA(ctx, userID)
}

// ResetMFA turns two-factor off on an admin's behalf (lost device) and signs
// the user out everywhere.
func (s *Service) ResetMFA(ctx context.Context, userID string) error {
	if err := s.users.DisableMFA(ctx, userID); err != nil {
		return err
	}
	_, err := s.users.RevokeSessions(ctx, userID)
	return err
}

// RecoveryCodesLeft reports how many unused recovery codes the user has.
func (s *Service) RecoveryCodesLeft(ctx context.Context, userID string) (int, error) {
	return s.users.RecoveryCodesLeft(ctx, userID)
}

func normalizeCode(c string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(c), " ", ""))
}

func hashCode(c string) string {
	sum := sha256.Sum256([]byte(normalizeCode(c)))
	return hex.EncodeToString(sum[:])
}

// checkCode accepts a current TOTP code (once) or an unused recovery code,
// counting attempts per account.
func (s *Service) checkCode(ctx context.Context, userID, code string) error {
	if s.limiter != nil {
		ok, _, err := s.limiter.Hit(ctx, "mfa:"+userID, mfaAttempts, mfaWindow)
		if err == nil && !ok {
			return ErrTooManyAttempts
		}
	}
	secret, st, err := s.secretOf(ctx, userID)
	if err != nil {
		return err
	}
	if !st.Enabled || secret == nil {
		return ErrInvalidCode
	}
	code = normalizeCode(code)
	if len(code) == totpDigits {
		if step := matchTOTP(secret, code, time.Now()); step >= 0 {
			if ok, err := s.users.UseTOTPStep(ctx, userID, step); err != nil {
				return err
			} else if ok {
				return nil
			}
		}
		return ErrInvalidCode
	}
	if ok, err := s.users.UseRecoveryCode(ctx, userID, hashCode(code)); err != nil {
		return err
	} else if !ok {
		return ErrInvalidCode
	}
	return nil
}

// --- sign-in ---

// challenge returns the second-step token for a user who passed the first
// factor: short-lived, bound to the session version, and refused by the auth
// middleware as a session (Purpose "mfa").
func (s *Service) challenge(u user.User) error {
	tok, err := signClaims(s.keys, Claims{TokenVersion: u.TokenVersion, Purpose: PurposeMFA}, u.ID, MFATTL)
	if err != nil {
		return err
	}
	return &MFARequiredError{Token: tok}
}

// VerifyMFA completes a sign-in: a valid challenge plus a TOTP or recovery
// code yields the session token.
func (s *Service) VerifyMFA(ctx context.Context, challenge, code string) (string, user.User, error) {
	claims, err := ParseToken(s.keys, challenge)
	if err != nil || claims.Purpose != PurposeMFA {
		return "", user.User{}, ErrChallengeExpired
	}
	u, err := s.users.GetByID(ctx, claims.Subject)
	if errors.Is(err, user.ErrNotFound) {
		return "", user.User{}, ErrChallengeExpired
	}
	if err != nil {
		return "", user.User{}, err
	}
	if u.Disabled() || u.TokenVersion != claims.TokenVersion {
		return "", user.User{}, ErrChallengeExpired
	}
	if err := s.checkCode(ctx, u.ID, code); err != nil {
		return "", user.User{}, err
	}
	token, err := s.TokenFor(ctx, u)
	return token, u, err
}

// signedIn finishes a first-factor success: a session token, or the MFA
// challenge when the user has two-factor on.
func (s *Service) signedIn(ctx context.Context, u user.User) (string, user.User, error) {
	if s.mfaRequired(ctx, u) {
		return "", u, s.challenge(u)
	}
	token, err := s.TokenFor(ctx, u)
	if err != nil {
		return "", user.User{}, err
	}
	return token, u, nil
}
