package sso

import (
	"context"
	"errors"
	"log/slog"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
)

// Settings are the instance-wide facts the admin SSO API needs.
type Settings struct {
	AutoCreateUsers      bool   // SSO_AUTO_CREATE_USERS (the default a provider may override)
	PasswordLoginEnabled bool   // PASSWORD_LOGIN_ENABLED
	PublicURL            string // PUBLIC_URL, which every provider URL is built from
	Production           bool   // APP_ENV=production: issuer and metadata URLs must be https
	CookieSecure         bool   // COOKIE_SECURE: SAML's cross-site POST needs it
}

// Handler serves the admin SSO API: providers (environment ones read-only,
// database ones managed here) and the group → role mappings. /sso is
// instance-admin only (authz).
type Handler struct {
	mappings  *Repository
	providers *ProviderRepository
	registry  *Registry
	settings  Settings
}

// NewHandler constructs the Handler.
func NewHandler(mappings *Repository, providers *ProviderRepository, registry *Registry, settings Settings) *Handler {
	return &Handler{mappings: mappings, providers: providers, registry: registry, settings: settings}
}

// Register mounts the routes on the secured group.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/sso/providers", h.ListProviders)
	r.Post("/sso/providers", h.CreateProvider)
	r.Post("/sso/providers/test", h.TestDraft)
	r.Get("/sso/providers/:providerID", h.GetProvider)
	r.Put("/sso/providers/:providerID", h.UpdateProvider)
	r.Delete("/sso/providers/:providerID", h.DeleteProvider)
	r.Post("/sso/providers/:providerID/test", h.TestProvider)
	r.Get("/sso/group-mappings", h.ListMappings)
	r.Post("/sso/group-mappings", h.CreateMapping)
	r.Delete("/sso/group-mappings/:mappingID", h.DeleteMapping)
}

// LoginOptions are the login page's SSO buttons (GET /auth/config): enabled
// providers whose client works. If the database cannot be read, the
// environment providers are still offered.
func (h *Handler) LoginOptions(ctx context.Context) []LoginOption {
	opts, err := h.registry.LoginOptions(ctx)
	if err != nil {
		slog.ErrorContext(ctx, "sso: list providers for the login page", "error", err)
	}
	return opts
}

func (h *Handler) rules() Rules {
	return Rules{PublicURL: h.settings.PublicURL, AllowHTTP: !h.settings.Production, CanSeal: h.providers.CanSeal()}
}

// ProviderView is a provider as the admin page shows it: configuration (no
// secrets), health, and the values to enter at the IdP (Endpoints).
type ProviderView struct {
	Provider
	Status
	// LinkedIdentities counts the identities that last signed in through it.
	LinkedIdentities int `json:"linked_identities"`
}

func (h *Handler) views(ctx context.Context, providers []Provider) ([]ProviderView, error) {
	linked, err := h.providers.LinkedIdentities(ctx)
	if err != nil {
		return nil, err
	}
	statuses := h.registry.Statuses(ctx, providers, adminWait)
	out := make([]ProviderView, len(providers))
	for i, p := range providers {
		out[i] = ProviderView{Provider: p, Status: statuses[i], LinkedIdentities: linked[p.ID]}
	}
	return out, nil
}

func (h *Handler) view(ctx context.Context, p Provider) (ProviderView, error) {
	v, err := h.views(ctx, []Provider{p})
	if err != nil {
		return ProviderView{}, err
	}
	return v[0], nil
}

func providerError(err error) error {
	switch {
	case errors.Is(err, ErrProviderNotFound):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	case errors.Is(err, ErrInvalidProvider):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, ErrSlugTaken), errors.Is(err, ErrReadOnly):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	return err
}

// ListProviders lists every provider — environment and database — with its
// health and what to enter at the IdP.
func (h *Handler) ListProviders(c *fiber.Ctx) error {
	all, err := h.registry.All(c.UserContext())
	if err != nil {
		return err
	}
	views, err := h.views(c.UserContext(), all)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{
		"providers":              views,
		"auto_create_users":      h.settings.AutoCreateUsers,
		"password_login_enabled": h.settings.PasswordLoginEnabled,
		"public_url":             h.settings.PublicURL,
		"secrets_configured":     h.providers.CanSeal(),
		"cookie_secure":          h.settings.CookieSecure,
	})
}

// GetProvider returns one provider: a uuid, or oidc/saml for an environment one.
func (h *Handler) GetProvider(c *fiber.Ctx) error {
	p, err := h.registry.Get(c.UserContext(), c.Params("providerID"))
	if err != nil {
		return providerError(err)
	}
	v, err := h.view(c.UserContext(), p)
	if err != nil {
		return err
	}
	return c.JSON(v)
}

// CreateProvider adds a provider. It is live at once, on every replica.
func (h *Handler) CreateProvider(c *fiber.Ctx) error {
	var in ProviderInput
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	p, err := in.Apply(nil, h.rules())
	if err != nil {
		return providerError(err)
	}
	created, err := h.providers.Create(c.UserContext(), p, auth.UserID(c))
	if err != nil {
		return providerError(err)
	}
	v, err := h.view(c.UserContext(), created)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(v)
}

// stored loads a database provider for a write; environment ones are read-only.
func (h *Handler) stored(ctx context.Context, id string) (Provider, error) {
	for _, p := range h.registry.Environment() {
		if p.ID == id {
			return Provider{}, ErrReadOnly
		}
	}
	return h.providers.Get(ctx, id)
}

// UpdateProvider replaces a provider's settings (slug and kind are fixed;
// omitted secrets are kept). Every replica rebuilds its client on next use.
func (h *Handler) UpdateProvider(c *fiber.Ctx) error {
	existing, err := h.stored(c.UserContext(), c.Params("providerID"))
	if err != nil {
		return providerError(err)
	}
	var in ProviderInput
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	p, err := in.Apply(&existing, h.rules())
	if err != nil {
		return providerError(err)
	}
	updated, err := h.providers.Update(c.UserContext(), p)
	if err != nil {
		return providerError(err)
	}
	h.registry.Invalidate(updated.ID)
	v, err := h.view(c.UserContext(), updated)
	if err != nil {
		return err
	}
	return c.JSON(v)
}

// DeleteProvider removes a provider and the mappings scoped to it. Its users
// keep their accounts and identities.
func (h *Handler) DeleteProvider(c *fiber.Ctx) error {
	p, err := h.stored(c.UserContext(), c.Params("providerID"))
	if err != nil {
		return providerError(err)
	}
	if err := h.providers.Delete(c.UserContext(), p.ID); err != nil {
		return providerError(err)
	}
	h.registry.Invalidate(p.ID)
	return c.SendStatus(fiber.StatusNoContent)
}

// TestDraft dry-runs a provider that is not saved (or an edit of one, when the
// draft carries its id): discovery / metadata fetch, nothing stored.
func (h *Handler) TestDraft(c *fiber.Ctx) error {
	var in ProviderInput
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	var existing *Provider
	if in.ID != "" {
		p, err := h.stored(c.UserContext(), in.ID)
		if err != nil {
			return providerError(err)
		}
		existing = &p
	} else if in.Slug == "" {
		in.Slug = "draft" // the slug only shapes the URLs; not checked for uniqueness
	}
	rules := h.rules()
	rules.CanSeal = true // nothing is stored
	p, err := in.Apply(existing, rules)
	if err != nil {
		return providerError(err)
	}
	return c.JSON(h.registry.Test(c.UserContext(), p))
}

// TestProvider dry-runs a saved provider (environment or database) from
// scratch, and drops its cached client so its status is re-evaluated.
func (h *Handler) TestProvider(c *fiber.Ctx) error {
	p, err := h.registry.Get(c.UserContext(), c.Params("providerID"))
	if err != nil {
		return providerError(err)
	}
	result := h.registry.Test(c.UserContext(), p)
	h.registry.Invalidate(p.ID)
	return c.JSON(result)
}

// ListMappings returns every group mapping.
func (h *Handler) ListMappings(c *fiber.Ctx) error {
	mappings, err := h.mappings.List(c.UserContext())
	if err != nil {
		return err
	}
	env := h.registry.Environment()
	for i, m := range mappings {
		for _, p := range env {
			if m.ProviderID == p.ID {
				mappings[i].ProviderName = p.Name
			}
		}
	}
	return c.JSON(fiber.Map{"mappings": mappings})
}

// CreateMapping adds a group mapping. It applies at each member's next SSO login.
func (h *Handler) CreateMapping(c *fiber.Ctx) error {
	var m GroupMapping
	if err := httpx.Parse(c, &m); err != nil {
		return err
	}
	m.ID, m.TargetName, m.ProviderName = "", "", ""
	if m.ProviderID != "" {
		p, err := h.registry.Get(c.UserContext(), m.ProviderID)
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "unknown provider_id")
		}
		if m.Provider != "" && m.Provider != ProviderAny && m.Provider != p.Kind {
			return fiber.NewError(fiber.StatusBadRequest, "provider and provider_id disagree on the kind")
		}
		m.Provider = p.Kind
	}
	if err := m.Validate(); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	created, err := h.mappings.Create(c.UserContext(), m)
	switch {
	case errors.Is(err, ErrDuplicate):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	case errors.Is(err, ErrTargetNotFound):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, ErrProviderNotFound):
		return fiber.NewError(fiber.StatusBadRequest, "unknown provider_id")
	case err != nil:
		return err
	}
	for _, p := range h.registry.Environment() {
		if created.ProviderID == p.ID {
			created.ProviderName = p.Name
		}
	}
	return c.Status(fiber.StatusCreated).JSON(created)
}

// DeleteMapping removes a group mapping; the grants it made are revoked at each
// member's next SSO login.
func (h *Handler) DeleteMapping(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "mappingID")
	if err != nil {
		return err
	}
	if err := h.mappings.Delete(c.UserContext(), id); errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	} else if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
