package saml

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	crewjam "github.com/crewjam/saml"
	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/sso"
)

// Resolver finds an enabled provider and its built client (sso.Registry).
type Resolver interface {
	Resolve(ctx context.Context, kind, slug string) (sso.Resolved, error)
}

// Completer finishes a verified login — link, group sync, session — and says
// where to send the browser (sso.Service).
type Completer interface {
	Complete(ctx context.Context, p sso.Provider, a sso.Assertion) string
}

// ReplayGuard consumes assertion ids once (ReplayStore). One store serves every
// provider: assertion ids are unique.
type ReplayGuard interface {
	Consume(ctx context.Context, assertionID string, until time.Time) error
}

// SessionEnder ends every Xila session matching an IdP-initiated
// LogoutRequest's (provider, NameID, SessionIndex) — saml.SessionStore.
// sessionIndex empty means every session for that NameID at that provider
// (the IdP omitted it, per the SAML spec that means "all of them").
type SessionEnder interface {
	EndByIdentity(ctx context.Context, p sso.Provider, nameID, sessionIndex string) (int, error)
}

// requestTTL bounds how long a started login may take at the IdP.
const requestTTL = 10 * time.Minute

// cookiePrefix names the environment provider's request-tracking cookies; a
// database provider's carry its slug (cookieName).
const cookiePrefix = "saml_req_"

// Handler serves the SP endpoints of every SAML provider: the environment one
// at /saml/{metadata,login,acs,slo}, database ones at /saml/{slug}/….
type Handler struct {
	providers    Resolver
	replay       ReplayGuard
	logins       Completer
	sessions     SessionEnder
	cookieSecure bool
}

// NewHandler constructs the SAML Handler. secure sets the Secure flag on the
// request-tracking cookie — and SameSite=None, which the IdP's cross-site POST
// to the ACS needs to carry it (browsers only allow None on Secure cookies).
func NewHandler(providers Resolver, replay ReplayGuard, logins Completer, sessions SessionEnder, secure bool) *Handler {
	return &Handler{providers: providers, replay: replay, logins: logins, sessions: sessions, cookieSecure: secure}
}

// Register mounts the SP routes on the public auth group (/api/v1/auth). They
// are always mounted; an unknown or disabled provider is a 404.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/saml/metadata", h.Metadata)
	r.Get("/saml/login", h.Login)
	r.Post("/saml/acs", h.ACS)
	r.Get("/saml/slo", h.SLO)
	r.Post("/saml/slo", h.SLO)
	r.Get("/saml/:slug/metadata", h.Metadata)
	r.Get("/saml/:slug/login", h.Login)
	r.Post("/saml/:slug/acs", h.ACS)
	r.Get("/saml/:slug/slo", h.SLO)
	r.Post("/saml/:slug/slo", h.SLO)
}

var errFailed = errors.New("provider unavailable")

// resolve finds the route's provider: the environment one on the bare routes,
// a database one by slug.
func (h *Handler) resolve(c *fiber.Ctx) (sso.Provider, *Service, error) {
	slug := c.Params("slug")
	if slug == "" {
		slug = sso.ProviderSAML
	} else if sso.ReservedSlug(slug) {
		return sso.Provider{}, nil, fiber.ErrNotFound
	}
	res, err := h.providers.Resolve(c.UserContext(), sso.ProviderSAML, slug)
	switch {
	case errors.Is(err, sso.ErrProviderNotFound):
		return sso.Provider{}, nil, fiber.NewError(fiber.StatusNotFound, "no such SAML provider")
	case err != nil:
		slog.WarnContext(c.UserContext(), "saml: provider unavailable", "provider", slug, "error", err)
		return sso.Provider{}, nil, errFailed
	}
	svc, ok := res.Client.(*Service)
	if !ok {
		return sso.Provider{}, nil, errors.New("saml: provider client of the wrong kind")
	}
	return res.Provider, svc, nil
}

// Metadata serves the provider's SP metadata XML for the IdP.
func (h *Handler) Metadata(c *fiber.Ctx) error {
	_, svc, err := h.resolve(c)
	if errors.Is(err, errFailed) {
		return fiber.NewError(fiber.StatusServiceUnavailable, "this SAML provider is not working (see the admin SSO page)")
	}
	if err != nil {
		return err
	}
	md, err := svc.Metadata()
	if err != nil {
		return err
	}
	c.Set(fiber.HeaderContentType, "application/samlmetadata+xml")
	return c.Send(md)
}

// Login starts an SP-initiated login: it redirects to the IdP with an
// AuthnRequest and remembers the request id in a signed, HttpOnly cookie keyed
// by the RelayState, so the response can be matched to this browser's request.
func (h *Handler) Login(c *fiber.Ctx) error {
	p, svc, err := h.resolve(c)
	if errors.Is(err, errFailed) {
		return c.Redirect(sso.FailureURL(sso.FailureGeneric), fiber.StatusFound)
	}
	if err != nil {
		return err
	}
	relayState := randHex(16)
	redirect, requestID, err := svc.authnRequest(relayState)
	if err != nil {
		slog.ErrorContext(c.UserContext(), "saml: build AuthnRequest", "provider", p.Slug, "error", err)
		return c.Redirect(sso.FailureURL(sso.FailureGeneric), fiber.StatusFound)
	}
	expires := time.Now().Add(requestTTL)
	h.setCookie(c, p, cookieName(p, relayState), svc.trackValue(relayState, requestID, expires), expires)
	return c.Redirect(redirect.String(), fiber.StatusFound)
}

// ACS consumes the IdP's HTTP-POST response. Every failure sends the browser to
// the login page with a code; nothing the IdP asserted is echoed or logged.
// Only this provider's tracking cookie counts.
func (h *Handler) ACS(c *fiber.Ctx) error {
	ctx := c.UserContext()
	p, svc, err := h.resolve(c)
	if errors.Is(err, errFailed) {
		return c.Redirect(sso.FailureURL(sso.FailureGeneric), fiber.StatusFound)
	}
	if err != nil {
		return err
	}
	fail := func(reason string, err error) error {
		slog.WarnContext(ctx, "saml login rejected", "provider", p.Slug, "reason", reason, "error", err)
		return c.Redirect(sso.FailureURL(sso.FailureGeneric), fiber.StatusFound)
	}

	relayState := c.FormValue("RelayState")
	requestID := ""
	if isHex(relayState, 32) {
		name := cookieName(p, relayState)
		if v := c.Cookies(name); v != "" {
			h.clearCookie(c, p, name)
			id, ok := svc.checkTrack(relayState, v)
			if !ok {
				return fail("request cookie invalid or expired", nil)
			}
			requestID = id
		}
	}
	assertion, err := svc.parse(c.FormValue("SAMLResponse"), requestID)
	if err != nil {
		return fail("invalid response", err)
	}
	if err := h.replay.Consume(ctx, assertion.ID, replayUntil(assertion)); err != nil {
		return fail("replay check", err)
	}
	return c.Redirect(h.logins.Complete(ctx, p, svc.toSSO(assertion)), fiber.StatusFound)
}

// cookieName is the request-tracking cookie for one login. The environment
// provider's cookie path (/api/v1/auth/saml) also covers the database
// providers' paths, so theirs carry the slug.
func cookieName(p sso.Provider, relayState string) string {
	if p.Env() {
		return cookiePrefix + relayState
	}
	return "saml_" + p.Slug + "_req_" + relayState
}

// trackValue is "<requestID>.<expiry>.<mac>", the MAC binding both to the relay
// state (the cookie name) under a key derived from the SP key and the provider —
// so it holds across replicas and cannot be forged or moved to another login
// or provider.
func (s *Service) trackValue(relayState, requestID string, expires time.Time) string {
	exp := strconv.FormatInt(expires.Unix(), 10)
	return requestID + "." + exp + "." + s.mac(relayState, requestID, exp)
}

func (s *Service) checkTrack(relayState, v string) (string, bool) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return "", false
	}
	requestID, exp, sig := parts[0], parts[1], parts[2]
	if !hmac.Equal([]byte(sig), []byte(s.mac(relayState, requestID, exp))) {
		return "", false
	}
	unix, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || time.Now().After(time.Unix(unix, 0)) {
		return "", false
	}
	return requestID, true
}

func (s *Service) mac(relayState, requestID, exp string) string {
	m := hmac.New(sha256.New, s.cookieKey)
	m.Write([]byte(relayState + "\x00" + requestID + "\x00" + exp))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (h *Handler) setCookie(c *fiber.Ctx, p sso.Provider, name, value string, expires time.Time) {
	c.Cookie(&fiber.Cookie{
		Name: name, Value: value, Path: p.BasePath(), Expires: expires,
		HTTPOnly: true, Secure: h.cookieSecure, SameSite: h.sameSite(),
	})
}

func (h *Handler) clearCookie(c *fiber.Ctx, p sso.Provider, name string) {
	c.Cookie(&fiber.Cookie{
		Name: name, Value: "", Path: p.BasePath(), Expires: time.Now().Add(-time.Hour),
		HTTPOnly: true, Secure: h.cookieSecure, SameSite: h.sameSite(),
	})
}

// sameSite: the ACS is a cross-site POST from the IdP, which only carries
// SameSite=None cookies (Secure only). Without TLS (local development, IdP on
// the same host) Lax is the best available and works same-site.
func (h *Handler) sameSite() string {
	if h.cookieSecure {
		return fiber.CookieSameSiteNoneMode
	}
	return fiber.CookieSameSiteLaxMode
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// SLO serves this provider's one Single Logout endpoint, for both directions:
// an IdP-initiated LogoutRequest (dispatched by EndByIdentity, answered with a
// LogoutResponse) and the LogoutResponse completing a browser's SP-initiated
// logout (sso.Service.Logout already ended the Xila session before
// redirecting here — this only decides where the browser lands next). Accepts
// the HTTP-Redirect binding (GET, deflate+base64 query params) and HTTP-POST
// (form fields), matching whichever the message arrived in.
func (h *Handler) SLO(c *fiber.Ctx) error {
	ctx := c.UserContext()
	p, svc, err := h.resolve(c)
	if errors.Is(err, errFailed) {
		return c.Redirect(sso.FailureURL(sso.FailureGeneric), fiber.StatusFound)
	}
	if err != nil {
		return err
	}
	redirectBinding := c.Method() == fiber.MethodGet
	relayState := c.FormValue("RelayState")
	if redirectBinding {
		relayState = c.Query("RelayState")
	}

	switch {
	case redirectBinding && c.Query("SAMLRequest") != "":
		req, err := svc.parseLogoutRequestRedirect(string(c.Request().URI().QueryString()))
		return h.handleLogoutRequest(ctx, c, p, svc, req, err, relayState, true)
	case !redirectBinding && c.FormValue("SAMLRequest") != "":
		req, err := svc.parseLogoutRequestPost(c.FormValue("SAMLRequest"))
		return h.handleLogoutRequest(ctx, c, p, svc, req, err, relayState, false)
	case redirectBinding && c.Query("SAMLResponse") != "":
		return h.handleLogoutResponse(ctx, c, p, svc.parseLogoutResponseRedirect(c.Query("SAMLResponse")))
	case !redirectBinding && c.FormValue("SAMLResponse") != "":
		return h.handleLogoutResponse(ctx, c, p, svc.parseLogoutResponsePost(c.FormValue("SAMLResponse")))
	default:
		return fiber.NewError(fiber.StatusBadRequest, "missing SAMLRequest or SAMLResponse")
	}
}

// handleLogoutRequest answers an IdP-initiated LogoutRequest: ends every
// matching Xila session and replies with a LogoutResponse in the same binding
// the request arrived in. If the sessions could not be ended it answers with
// an error instead: a Success response would tell the IdP the user is signed
// out when they are not.
func (h *Handler) handleLogoutRequest(ctx context.Context, c *fiber.Ctx, p sso.Provider, svc *Service,
	req *crewjam.LogoutRequest, parseErr error, relayState string, redirectBinding bool) error {
	if parseErr != nil {
		slog.WarnContext(ctx, "saml idp-initiated logout rejected", "provider", p.Slug, "error", parseErr)
		return fiber.NewError(fiber.StatusBadRequest, "invalid LogoutRequest")
	}
	sessionIndex := ""
	if req.SessionIndex != nil {
		sessionIndex = req.SessionIndex.Value
	}
	if _, err := h.sessions.EndByIdentity(ctx, p, req.NameID.Value, sessionIndex); err != nil {
		slog.ErrorContext(ctx, "saml idp-initiated logout: ending sessions", "provider", p.Slug, "error", err)
		return fiber.NewError(fiber.StatusInternalServerError, "could not end the session")
	}
	redirect, form, err := svc.logoutResponse(req.ID, relayState, !redirectBinding)
	if err != nil {
		slog.ErrorContext(ctx, "saml: build logout response", "provider", p.Slug, "error", err)
		return fiber.NewError(fiber.StatusInternalServerError, "could not build the logout response")
	}
	if redirect != "" {
		return c.Redirect(redirect, fiber.StatusFound)
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	return c.Send(form)
}

// handleLogoutResponse completes an SP-initiated logout (sso.Service.Logout
// already ended the Xila session beforehand): a valid, successful response
// just lands on the login page; a rejected one still does — the local
// sign-out already happened — but is logged as a warning.
func (h *Handler) handleLogoutResponse(ctx context.Context, c *fiber.Ctx, p sso.Provider, err error) error {
	if err != nil {
		slog.WarnContext(ctx, "saml logout response rejected", "provider", p.Slug, "error", err)
	}
	return c.Redirect("/login", fiber.StatusFound)
}
