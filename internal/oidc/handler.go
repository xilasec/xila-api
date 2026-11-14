package oidc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"golang.org/x/oauth2"

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

// Handler drives the OIDC login + callback flow for every OIDC provider: the
// environment one at /oidc/login + /oidc/callback, database ones at
// /oidc/{slug}/login + /oidc/{slug}/callback.
type Handler struct {
	providers    Resolver
	logins       Completer
	cookieSecure bool // Secure flag on the state/nonce/PKCE cookies (production)
}

// NewHandler constructs the OIDC Handler. secure sets the Secure flag on the
// short-lived state/nonce/PKCE cookies (enable behind TLS).
func NewHandler(providers Resolver, logins Completer, secure bool) *Handler {
	return &Handler{providers: providers, logins: logins, cookieSecure: secure}
}

// Register mounts the routes on the public auth group (/api/v1/auth). They are
// always mounted; an unknown or disabled provider is a 404.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/oidc/login", h.Login)
	r.Get("/oidc/callback", h.Callback)
	r.Get("/oidc/:slug/login", h.Login)
	r.Get("/oidc/:slug/callback", h.Callback)
}

// resolve finds the route's provider: the environment one on the bare routes,
// a database one by slug. errFailed means the provider exists but cannot be
// used right now (its discovery failed).
func (h *Handler) resolve(c *fiber.Ctx) (sso.Provider, *Client, error) {
	slug := c.Params("slug")
	if slug == "" {
		slug = sso.ProviderOIDC
	} else if sso.ReservedSlug(slug) {
		return sso.Provider{}, nil, fiber.ErrNotFound
	}
	res, err := h.providers.Resolve(c.UserContext(), sso.ProviderOIDC, slug)
	switch {
	case errors.Is(err, sso.ErrProviderNotFound):
		return sso.Provider{}, nil, fiber.NewError(fiber.StatusNotFound, "no such OIDC provider")
	case err != nil:
		slog.WarnContext(c.UserContext(), "oidc: provider unavailable", "provider", slug, "error", err)
		return sso.Provider{}, nil, errFailed
	}
	client, ok := res.Client.(*Client)
	if !ok {
		return sso.Provider{}, nil, errors.New("oidc: provider client of the wrong kind")
	}
	return res.Provider, client, nil
}

var errFailed = errors.New("provider unavailable")

func (h *Handler) fail(c *fiber.Ctx, err error) error {
	if errors.Is(err, errFailed) {
		return c.Redirect(sso.FailureURL(sso.FailureGeneric), fiber.StatusFound)
	}
	return err
}

// Login starts the flow: it stores a CSRF state, a nonce and a PKCE verifier in
// cookies scoped to this provider and redirects to the provider.
func (h *Handler) Login(c *fiber.Ctx) error {
	p, client, err := h.resolve(c)
	if err != nil {
		return h.fail(c, err)
	}
	state, nonce, verifier := randToken(), randToken(), oauth2.GenerateVerifier()
	names := cookieNames(p)
	h.setCookie(c, p, names.state, state)
	h.setCookie(c, p, names.nonce, nonce)
	h.setCookie(c, p, names.pkce, verifier)
	return c.Redirect(client.authCodeURL(state, nonce, verifier), fiber.StatusFound)
}

// Callback verifies the state, exchanges the code, and hands the verified
// assertion to the shared SSO layer, which redirects back to the SPA with our JWT
// in the URL fragment — or to the login page with a failure code. Only this
// provider's cookies count: another provider's in-flight login cannot complete
// here.
func (h *Handler) Callback(c *fiber.Ctx) error {
	p, client, err := h.resolve(c)
	if err != nil {
		return h.fail(c, err)
	}
	names := cookieNames(p)
	code, state := c.Query("code"), c.Query("state")
	nonce, verifier, wantState := c.Cookies(names.nonce), c.Cookies(names.pkce), c.Cookies(names.state)
	for _, name := range []string{names.state, names.nonce, names.pkce} {
		h.clearCookie(c, p, name)
	}
	switch {
	case c.Query("error") != "":
		// The IdP refused (user cancelled, not assigned to the app…).
		slog.WarnContext(c.UserContext(), "oidc: provider returned an error", "provider", p.Slug, "error", c.Query("error"))
		return c.Redirect(sso.FailureURL(sso.FailureGeneric), fiber.StatusFound)
	case code == "" || state == "" || state != wantState:
		slog.WarnContext(c.UserContext(), "oidc: missing code or state mismatch", "provider", p.Slug)
		return c.Redirect(sso.FailureURL(sso.FailureGeneric), fiber.StatusFound)
	}

	assertion, err := client.exchange(c.UserContext(), code, nonce, verifier)
	if err != nil {
		slog.WarnContext(c.UserContext(), "oidc callback failed", "provider", p.Slug, "error", err)
		return c.Redirect(sso.FailureURL(sso.FailureGeneric), fiber.StatusFound)
	}
	return c.Redirect(h.logins.Complete(c.UserContext(), p, assertion), fiber.StatusFound)
}

// Cookies carrying the in-flight login (HttpOnly, 10 minutes, cleared on
// callback), path-scoped to the provider's routes. The environment provider
// keeps the original names; a database provider's carry its slug, since the
// environment provider's path (/api/v1/auth/oidc) also covers theirs.
type cookieSet struct{ state, nonce, pkce string }

func cookieNames(p sso.Provider) cookieSet {
	prefix := "oidc_"
	if !p.Env() {
		prefix = "oidc_" + p.Slug + "_"
	}
	return cookieSet{state: prefix + "state", nonce: prefix + "nonce", pkce: prefix + "pkce"}
}

func (h *Handler) setCookie(c *fiber.Ctx, p sso.Provider, name, value string) {
	c.Cookie(&fiber.Cookie{
		Name: name, Value: value, Path: p.BasePath(),
		HTTPOnly: true, SameSite: "Lax", Secure: h.cookieSecure,
		Expires: time.Now().Add(10 * time.Minute),
	})
}

func (h *Handler) clearCookie(c *fiber.Ctx, p sso.Provider, name string) {
	c.Cookie(&fiber.Cookie{
		Name: name, Value: "", Path: p.BasePath(),
		HTTPOnly: true, SameSite: "Lax", Secure: h.cookieSecure,
		Expires: time.Now().Add(-time.Hour),
	})
}

func randToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
