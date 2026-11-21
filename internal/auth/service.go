// Package auth implements user registration and login.
package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/user"
)

// Service-level errors, mapped to HTTP status codes by the handler.
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrEmailTaken         = errors.New("email already registered")
	ErrValidation         = errors.New("invalid input")
	// ErrPasswordLoginDisabled: PASSWORD_LOGIN_ENABLED=false and this is not the
	// instance owner's (correct) credentials.
	ErrPasswordLoginDisabled = errors.New("password sign-in is disabled")
	// ErrRegistrationClosed: PASSWORD_LOGIN_ENABLED=false and the instance is
	// past bootstrap.
	ErrRegistrationClosed = errors.New("registration is disabled")
	// ErrAccountDisabled: right credentials, deactivated account.
	ErrAccountDisabled = errors.New("account is deactivated")
	// ErrWrongPassword: the current password given to a password change is wrong.
	ErrWrongPassword = errors.New("current password is incorrect")
	// ErrDirectoryRefused: the directory accepted the password, but Xila won't
	// admit the account (no account and auto-create off, an identity conflict,
	// no email in the directory).
	ErrDirectoryRefused = errors.New("signed in to the directory, but it has no Xila account you can use")
)

// Directory authenticates people who have no local password against an LDAP /
// Active Directory directory (internal/ldap), returning the linked user. A
// wrong login or password is ErrInvalidCredentials.
type Directory interface {
	Authenticate(ctx context.Context, login, password string) (user.User, error)
}

const minPasswordLen = 8

// Service contains the registration and login use cases.
type Service struct {
	users         *user.Repository
	jwt           config.JWT
	keys          *Keys // signs/verifies JWTs; built from jwt.Secret/jwt.Previous
	passwordLogin bool
	mailer        Mailer
	publicURL     string
	directory     Directory
	sealer        Sealer         // MFA secrets; nil = MFA unavailable
	limiter       AttemptLimiter // MFA code attempts; nil = uncapped
	features      Features       // runtime switches; nil = every feature on
	sessions      *SessionStore  // idle/absolute session tracking; nil = off
}

// Features reports runtime feature switches (feature.Store); two-factor
// sign-in is the "mfa" feature.
type Features interface {
	Enabled(ctx context.Context, key string) bool
}

// WithFeatures lets the instance owner switch two-factor off: while "mfa" is
// off, sign-in asks no one for a second factor. Enrollments are kept, so
// turning it back on asks the same people again.
func (s *Service) WithFeatures(f Features) { s.features = f }

// mfaRequired reports whether u must pass the second factor to sign in.
func (s *Service) mfaRequired(ctx context.Context, u user.User) bool {
	return u.MFAEnabled && (s.features == nil || s.features.Enabled(ctx, "mfa"))
}

// EnableDirectory turns on LDAP sign-in through the password form.
func (s *Service) EnableDirectory(d Directory) { s.directory = d }

// DirectoryEnabled reports whether LDAP sign-in is on.
func (s *Service) DirectoryEnabled() bool { return s.directory != nil }

// Mailer sends the password-reset email (notify.Service).
type Mailer interface {
	SMTPConfigured() bool
	SendText(ctx context.Context, to, subject, body string) error
}

// EnableResetMail turns on self-service password reset by email. Without it a
// reset link comes only from an admin (ResetLink).
func (s *Service) EnableResetMail(m Mailer, publicURL string) {
	s.mailer, s.publicURL = m, strings.TrimRight(publicURL, "/")
}

// EnableSessionTracking turns on the idle timeout / absolute session
// lifetime (SESSION_IDLE_TIMEOUT / SESSION_MAX_AGE): every session minted
// after this call gets a session id tracked in store, read by
// auth.Middleware. Config with nothing to enforce (SessionStore.TrackingActive
// false) still accepts store but mints no session id, so nothing extra is
// written or read per request.
func (s *Service) EnableSessionTracking(store *SessionStore) { s.sessions = store }

// NewService constructs an auth Service. passwordLogin is PASSWORD_LOGIN_ENABLED:
// false closes registration (after the first user) and password sign-in for
// everyone but the instance owner.
func NewService(users *user.Repository, jwt config.JWT, passwordLogin bool) *Service {
	return &Service{users: users, jwt: jwt, keys: NewKeys(jwt.Secret, jwt.Previous), passwordLogin: passwordLogin}
}

// Keys returns the service's JWT signing/verification ring, shared with the
// auth middleware and the audit recorder so a rotation (Keys.Update) applies
// to every signer and verifier at once.
func (s *Service) Keys() *Keys { return s.keys }

// PasswordLoginEnabled reports whether email + password sign-in is offered.
func (s *Service) PasswordLoginEnabled() bool { return s.passwordLogin }

// newSession mints a signed session JWT for userID, tracking it in
// s.sessions when session tracking is active: in that case the token
// carries a session id and a user_sessions row starts its clock, both read
// back by auth.Middleware on every later request.
func (s *Service) newSession(ctx context.Context, userID string, isAdmin bool, tokenVersion int, authTime time.Time) (string, error) {
	sessionID := ""
	if s.sessions != nil && TrackingActive(s.jwt.IdleTimeout, s.jwt.MaxAge, s.jwt.TTL) {
		sessionID = uuid.NewString()
		if err := s.sessions.Create(ctx, sessionID, userID); err != nil {
			return "", err
		}
	}
	return generateToken(s.keys, userID, isAdmin, tokenVersion, s.jwt.TTL, authTime, sessionID)
}

// TokenFor mints a signed JWT for a user who has just authenticated (its
// auth_time is now). Used by SSO, which establishes identity out-of-band and
// then issues our own access token, and by every local sign-in path.
func (s *Service) TokenFor(ctx context.Context, u user.User) (string, error) {
	return s.newSession(ctx, u.ID, u.IsAdmin, u.TokenVersion, time.Now())
}

// reissue mints a new session for a user who did not just authenticate,
// keeping the authentication time of the session it replaces.
func (s *Service) reissue(ctx context.Context, u user.User, authTime time.Time) (string, error) {
	return s.newSession(ctx, u.ID, u.IsAdmin, u.TokenVersion, authTime)
}

// ServiceAccountToken mints a short-lived session for a service account (the
// workload-identity token exchange), optionally confined to one project. Like
// every JWT it carries the account's token_version, so suspending the account
// ends it at once.
func (s *Service) ServiceAccountToken(u user.User, projectID string, ttl time.Duration) (string, error) {
	if !u.IsService() {
		return "", fmt.Errorf("not a service account: %s", u.ID)
	}
	return signClaims(s.keys, Claims{TokenVersion: u.TokenVersion, ServiceAccount: true, ProjectID: projectID}, u.ID, ttl)
}

// Register creates a new account with a bcrypt-hashed password.
func (s *Service) Register(ctx context.Context, email, password string) (user.User, error) {
	email = normalizeEmail(email)
	if email == "" || len(password) < minPasswordLen {
		return user.User{}, ErrValidation
	}
	if !s.passwordLogin {
		// The very first user may still register (someone has to own the
		// instance); after that, accounts come from SSO.
		exists, err := s.users.HasUsers(ctx)
		if err != nil {
			return user.User{}, err
		}
		if exists {
			return user.User{}, ErrRegistrationClosed
		}
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return user.User{}, fmt.Errorf("hash password: %w", err)
	}

	u, err := s.users.Create(ctx, email, string(hash))
	if errors.Is(err, user.ErrDuplicate) {
		return user.User{}, ErrEmailTaken
	}
	if err != nil {
		return user.User{}, err
	}
	return u, nil
}

// Login verifies credentials and returns a signed access token.
//
// With password sign-in disabled only the instance owner gets in — the
// break-glass for a broken IdP — and every other attempt, right password or
// not, gets the same ErrPasswordLoginDisabled, so the response reveals neither
// which accounts exist nor which one is the owner.
func (s *Service) Login(ctx context.Context, email, password string) (string, user.User, error) {
	refused := ErrInvalidCredentials
	if !s.passwordLogin {
		refused = ErrPasswordLoginDisabled
	}
	login := strings.TrimSpace(email)
	email = normalizeEmail(email)

	u, err := s.users.GetByEmail(ctx, email)
	if err != nil && !errors.Is(err, user.ErrNotFound) {
		return "", user.User{}, err
	}
	// Accounts with a local password sign in locally; everyone else — unknown
	// logins and SSO-provisioned accounts — against the directory, when there
	// is one. (The directory is SSO: PASSWORD_LOGIN_ENABLED doesn't apply.)
	if (err != nil || !u.HasPassword) && s.directory != nil {
		return s.directoryLogin(ctx, login, password)
	}
	if errors.Is(err, user.ErrNotFound) {
		return "", user.User{}, refused
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return "", user.User{}, refused
	}
	if !s.passwordLogin {
		if !u.IsOwner {
			return "", user.User{}, refused
		}
		slog.WarnContext(ctx, "break-glass: instance owner signed in with a password while PASSWORD_LOGIN_ENABLED=false",
			"user_id", u.ID)
	}

	// Only after the password matched: a wrong guess learns nothing new.
	if u.Disabled() {
		return "", user.User{}, ErrAccountDisabled
	}
	return s.signedIn(ctx, u)
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func (s *Service) directoryLogin(ctx context.Context, login, password string) (string, user.User, error) {
	u, err := s.directory.Authenticate(ctx, login, password)
	switch {
	case errors.Is(err, ErrInvalidCredentials):
		return "", user.User{}, ErrInvalidCredentials
	case errors.Is(err, user.ErrDisabled):
		return "", user.User{}, ErrAccountDisabled
	case errors.Is(err, ErrDirectoryRefused), errors.Is(err, user.ErrNoAccount), errors.Is(err, user.ErrIdentityConflict), errors.Is(err, user.ErrEmailUnverified):
		slog.WarnContext(ctx, "directory sign-in refused", "error", err)
		return "", user.User{}, ErrDirectoryRefused
	case err != nil:
		return "", user.User{}, err
	}
	return s.signedIn(ctx, u)
}
