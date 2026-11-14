package sso

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/user"
)

// EmailTrust is how far the IdP vouched for the asserted email.
type EmailTrust int

const (
	// EmailUnknown: the IdP said nothing either way (e.g. no OIDC email_verified
	// claim). Enough to provision a new account, not to attach to an existing one.
	EmailUnknown EmailTrust = iota
	// EmailVerified: the IdP vouches the address belongs to this person.
	EmailVerified
	// EmailUnverified: the IdP explicitly says it has not verified the address.
	EmailUnverified
)

// Assertion is a verified login handed over by a protocol package: who the IdP
// says this is, and which groups it says they are in. Everything in it has
// already been cryptographically verified (ID token signature, SAML signature,
// audience, expiry…). Which provider it came through travels next to it.
type Assertion struct {
	Issuer        string // OIDC issuer / SAML IdP entity id
	Subject       string // OIDC sub / SAML NameID
	SubjectFormat string // SAML NameID Format
	Email         string
	EmailTrust    EmailTrust
	Groups        []string
	// SessionIndex is the SAML AuthnStatement's SessionIndex, when the IdP
	// sent one (SAML only; empty for OIDC). Single Logout addresses a session
	// by NameID + SessionIndex.
	SessionIndex string
}

// Failure codes, sent to the login page as /login?error=<code>. They name the
// reason without echoing anything the IdP asserted.
const (
	FailureGeneric          = "sso_failed"
	FailureNoAccount        = "sso_no_account"
	FailureEmailUnverified  = "sso_email_unverified"
	FailureIdentityConflict = "sso_identity_conflict"
	FailureNoEmail          = "sso_no_email"
	FailureDisabled         = "sso_account_disabled"
)

var errNoEmail = errors.New("the identity provider sent no email address")

// Linker resolves an identity to a user and ends every session of one
// (user.Repository).
type Linker interface {
	LinkIdentity(ctx context.Context, id user.Identity, policy user.LinkPolicy) (user.User, user.LinkOutcome, error)
	GetByID(ctx context.Context, id string) (user.User, error)
}

// GrantSyncer re-applies the group mappings in scope for a provider to a user
// (Repository).
type GrantSyncer interface {
	SyncGrants(ctx context.Context, userID string, p Provider, groups []string) error
}

// TokenIssuer mints our access token (auth.Service).
type TokenIssuer interface {
	TokenFor(u user.User) (string, error)
}

// Service completes SSO logins for every protocol and provider.
type Service struct {
	users      Linker
	grants     GrantSyncer
	tokens     TokenIssuer
	autoCreate bool

	// SAML Single Logout, enabled by WithSAMLSingleLogout. Nil samlSessions
	// means SAML logins work as before and Logout always answers "" (plain
	// local sign-out, as before this existed).
	samlSessions SAMLSessionStore
	registry     *Registry
	sessionTTL   time.Duration
}

// NewService constructs the Service. autoCreate (SSO_AUTO_CREATE_USERS) lets an
// identity with no account get one on first login, unless the provider
// overrides it.
func NewService(users Linker, grants GrantSyncer, tokens TokenIssuer, autoCreate bool) *Service {
	return &Service{users: users, grants: grants, tokens: tokens, autoCreate: autoCreate}
}

// Login links (or provisions) the user behind a verified assertion made
// through provider p, under p's policy, and syncs the group-mapped grants in
// scope for p. A failed sync fails the login: letting someone in with grants
// the IdP may have just revoked is the wrong way to fail.
func (s *Service) Login(ctx context.Context, p Provider, a Assertion) (user.User, error) {
	email := strings.ToLower(strings.TrimSpace(a.Email))
	if email == "" {
		return user.User{}, errNoEmail
	}
	if a.Subject == "" {
		return user.User{}, errors.New("the identity provider sent no subject")
	}
	trust := a.EmailTrust
	if trust == EmailVerified && !p.LinkByEmail {
		// Not linked to an existing account by email; still enough to found one.
		trust = EmailUnknown
	}
	autoCreate := s.autoCreate
	if p.AutoCreateUsers != nil {
		autoCreate = *p.AutoCreateUsers
	}
	id := user.Identity{
		Provider: p.Kind, Issuer: a.Issuer, Subject: a.Subject, SubjectFormat: a.SubjectFormat, Email: email,
		ProviderID: p.databaseID(),
		// Pre-multi-provider OIDC links (empty issuer) were made against the
		// environment-configured issuer: only that provider may claim them.
		ClaimLegacy: p.Env() && p.Kind == ProviderOIDC,
	}
	policy := user.LinkPolicy{
		EmailVerified: trust == EmailVerified,
		// An address the IdP disowns may not found an account: that account would
		// later attract links from other IdPs that do verify the address.
		AllowCreate: autoCreate && trust != EmailUnverified,
	}
	u, outcome, err := s.users.LinkIdentity(ctx, id, policy)
	if errors.Is(err, user.ErrNoAccount) && trust == EmailUnverified && autoCreate {
		err = user.ErrEmailUnverified
	}
	if err != nil {
		return user.User{}, err
	}
	// A deactivated account stays out whatever the IdP says (and its groups
	// aren't synced: an admin's deactivation must not be undone by a login).
	if u.Disabled() {
		return user.User{}, user.ErrDisabled
	}
	if err := s.grants.SyncGrants(ctx, u.ID, p, a.Groups); err != nil {
		return user.User{}, err
	}
	// Re-read: the sync may have changed is_admin, which the token carries for the UI.
	if u, err = s.users.GetByID(ctx, u.ID); err != nil {
		return user.User{}, err
	}
	slog.InfoContext(ctx, "sso login", "provider", p.Slug, "kind", p.Kind, "user_id", u.ID, "link", string(outcome),
		"groups", len(a.Groups), "is_admin", u.IsAdmin)
	// SAML Single Logout: remember the NameID (+ SessionIndex, when the IdP
	// sent one) this login was made under, until the JWT it backs would have
	// expired anyway. Best-effort — a failure here only means Logout falls
	// back to a plain local sign-out for this session, not that the login fails.
	if s.samlSessions != nil && p.Kind == ProviderSAML {
		if err := s.samlSessions.Record(ctx, u.ID, p, a.Subject, a.SubjectFormat, a.SessionIndex, time.Now().Add(s.sessionTTL)); err != nil {
			slog.WarnContext(ctx, "sso: record saml session for single logout", "provider", p.Slug, "error", err)
		}
	}
	return u, nil
}

// WithSAMLSingleLogout turns on SAML Single Logout. sessionTTL is how long a
// recorded session is trusted to still matter — the lifetime of the JWT it
// backs (JWT_TTL); past that the session is moot regardless. Call once, like
// the other optional Service features (auth.Service.EnableResetMail, …).
func (s *Service) WithSAMLSingleLogout(sessions SAMLSessionStore, registry *Registry, sessionTTL time.Duration) *Service {
	s.samlSessions, s.registry, s.sessionTTL = sessions, registry, sessionTTL
	return s
}

// SAMLSession is one recorded SAML login, kept for Single Logout: the NameID
// (and SessionIndex, when the IdP sent one) it was made under, and which
// provider (by slug — "saml" for the environment-configured one) to address.
type SAMLSession struct {
	ID           string
	ProviderSlug string
	NameID       string
	NameIDFormat string
	SessionIndex string
}

// SAMLSessionStore records and ends SAML sessions for Single Logout
// (saml.SessionStore; this package cannot import internal/saml).
type SAMLSessionStore interface {
	// Record remembers a SAML login until expires — an IdP-initiated
	// LogoutRequest matches sessions by (provider, NameID, SessionIndex); a
	// later Logout call finds a user's latest one to start an SP-initiated one.
	Record(ctx context.Context, userID string, p Provider, nameID, nameIDFormat, sessionIndex string, expires time.Time) error
	// Latest returns the most recently recorded, unexpired SAML session for
	// userID, across every SAML provider (a user signs in through at most one
	// at a time in practice, but Logout only needs the newest).
	Latest(ctx context.Context, userID string) (SAMLSession, bool, error)
	// End removes a recorded session — it no longer matches anything, from
	// either side.
	End(ctx context.Context, id string) error
}

// SAMLLogoutClient is implemented by a SAML provider's built client
// (saml.Service) that can start a Single Logout at its IdP. Checked with a
// type assertion, like the protocol handlers do for their own client type —
// this package has no notion of SAML specifics beyond this one capability.
type SAMLLogoutClient interface {
	// LogoutRedirect builds a signed LogoutRequest (HTTP-Redirect binding) for
	// this NameID/SessionIndex and returns the URL to send the browser to and
	// ok=true, or ok=false if the IdP's metadata advertises no
	// SingleLogoutService (nothing to redirect to: fall back to local sign-out).
	LogoutRedirect(nameID, nameIDFormat, sessionIndex, relayState string) (redirectURL string, ok bool, err error)
}

// LogoutResult is what Logout found. Redirect, when non-empty, is the URL to
// send the browser to next (the IdP's Single Logout endpoint); empty means a
// plain local sign-out, which has already happened either way.
type LogoutResult struct {
	Redirect string
}

// Logout starts SP-initiated Single Logout for userID's sign-out: if
// WithSAMLSingleLogout is configured and their most recent login was through
// a SAML provider whose IdP advertises a SingleLogoutService, it returns the
// signed LogoutRequest URL to send the browser to, so the IdP ends its own
// session. It does not revoke Xila sessions — sign-out stays local to the
// browser, as before (only an IdP-initiated LogoutRequest, or "sign out
// everywhere", bumps token_version). Best-effort: any failure means a plain
// local sign-out.
func (s *Service) Logout(ctx context.Context, userID string) (LogoutResult, error) {
	if s.samlSessions == nil {
		return LogoutResult{}, nil
	}
	sess, ok, err := s.samlSessions.Latest(ctx, userID)
	if err != nil {
		slog.WarnContext(ctx, "sso: find saml session for logout", "error", err)
		return LogoutResult{}, nil
	}
	if !ok {
		return LogoutResult{}, nil
	}
	if err := s.samlSessions.End(ctx, sess.ID); err != nil {
		slog.WarnContext(ctx, "sso: end saml session", "error", err)
	}
	res, err := s.registry.Resolve(ctx, ProviderSAML, sess.ProviderSlug)
	if err != nil {
		slog.WarnContext(ctx, "sso: resolve saml provider for logout", "provider", sess.ProviderSlug, "error", err)
		return LogoutResult{}, nil
	}
	logout, ok := res.Client.(SAMLLogoutClient)
	if !ok {
		return LogoutResult{}, nil
	}
	redirectURL, ok, err := logout.LogoutRedirect(sess.NameID, sess.NameIDFormat, sess.SessionIndex, "")
	if err != nil {
		slog.WarnContext(ctx, "sso: build saml logout request", "provider", sess.ProviderSlug, "error", err)
		return LogoutResult{}, nil
	}
	if !ok {
		return LogoutResult{}, nil // the IdP advertises no SLO endpoint
	}
	return LogoutResult{Redirect: redirectURL}, nil
}

// Complete finishes a login through p and returns where to send the browser:
// the SPA with our JWT in the URL fragment (never sent to a server, stripped
// by the SPA on load), or the login page with a failure code.
func (s *Service) Complete(ctx context.Context, p Provider, a Assertion) string {
	u, err := s.Login(ctx, p, a)
	if err != nil {
		code := FailureCode(err)
		slog.WarnContext(ctx, "sso login refused", "provider", p.Slug, "reason", code, "error", err)
		return FailureURL(code)
	}
	token, err := s.tokens.TokenFor(u)
	if err != nil {
		slog.ErrorContext(ctx, "sso: mint token", "error", err)
		return FailureURL(FailureGeneric)
	}
	return "/#sso_token=" + token
}

// FailureCode maps a login error to the code the login page explains.
func FailureCode(err error) string {
	switch {
	case errors.Is(err, user.ErrNoAccount):
		return FailureNoAccount
	case errors.Is(err, user.ErrDisabled):
		return FailureDisabled
	case errors.Is(err, user.ErrEmailUnverified):
		return FailureEmailUnverified
	case errors.Is(err, user.ErrIdentityConflict):
		return FailureIdentityConflict
	case errors.Is(err, errNoEmail):
		return FailureNoEmail
	default:
		return FailureGeneric
	}
}

// FailureURL is the login page showing the given failure code.
func FailureURL(code string) string {
	return "/login?error=" + url.QueryEscape(code)
}
