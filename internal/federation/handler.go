package federation

import (
	"errors"
	"log/slog"
	"net/url"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/netguard"
)

// RFC 8693 identifiers.
const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeIDToken       = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
)

// Handler serves the public token exchange and the admin routes for issuers
// and bindings (instance-admin only: authz adminOnly on /federation).
type Handler struct {
	repo *Repository
	svc  *Service
	// allowHTTP permits http:// issuer URLs (development / test only).
	allowHTTP bool
}

// NewHandler constructs a Handler. allowHTTP permits plain-http issuers
// (never in production).
func NewHandler(repo *Repository, svc *Service, allowHTTP bool) *Handler {
	return &Handler{repo: repo, svc: svc, allowHTTP: allowHTTP}
}

// Register mounts the admin routes.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/federation/issuers", h.ListIssuers)
	r.Post("/federation/issuers", h.CreateIssuer)
	r.Get("/federation/issuers/:issuerID", h.GetIssuer)
	r.Put("/federation/issuers/:issuerID", h.UpdateIssuer)
	r.Delete("/federation/issuers/:issuerID", h.DeleteIssuer)
	r.Post("/federation/issuers/:issuerID/test", h.TestIssuer)
	r.Get("/federation/bindings", h.ListBindings)
	r.Post("/federation/bindings", h.CreateBinding)
	r.Get("/federation/bindings/:bindingID", h.GetBinding)
	r.Put("/federation/bindings/:bindingID", h.UpdateBinding)
	r.Delete("/federation/bindings/:bindingID", h.DeleteBinding)
}

type exchangeRequest struct {
	GrantType        string `json:"grant_type" form:"grant_type"`
	SubjectToken     string `json:"subject_token" form:"subject_token"`
	SubjectTokenType string `json:"subject_token_type" form:"subject_token_type"`
}

// oauthError writes an RFC 6749 §5.2 error body.
func oauthError(c *fiber.Ctx, status int, code, description string) error {
	return c.Status(status).JSON(fiber.Map{"error": code, "error_description": description})
}

// Exchange handles POST /auth/token (public, rate-limited): RFC 8693 token
// exchange of a workload's OIDC identity token for a Xila access token.
func (h *Handler) Exchange(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	var body exchangeRequest
	if err := c.BodyParser(&body); err != nil {
		return oauthError(c, fiber.StatusBadRequest, "invalid_request", "send an application/x-www-form-urlencoded or JSON body")
	}
	if body.GrantType != GrantTypeTokenExchange {
		return oauthError(c, fiber.StatusBadRequest, "unsupported_grant_type", "grant_type must be "+GrantTypeTokenExchange)
	}
	if body.SubjectToken == "" {
		return oauthError(c, fiber.StatusBadRequest, "invalid_request", "subject_token is required")
	}
	if body.SubjectTokenType != TokenTypeJWT && body.SubjectTokenType != TokenTypeIDToken {
		return oauthError(c, fiber.StatusBadRequest, "invalid_request", "subject_token_type must be "+TokenTypeJWT)
	}

	sess, err := h.svc.Exchange(c.UserContext(), body.SubjectToken)
	switch {
	case errors.Is(err, ErrIssuerUnavailable):
		slog.WarnContext(c.UserContext(), "token exchange: issuer unavailable", "error", err)
		return oauthError(c, fiber.StatusServiceUnavailable, "temporarily_unavailable", ErrIssuerUnavailable.Error())
	case errors.Is(err, ErrUnknownIssuer), errors.Is(err, ErrInvalidToken), errors.Is(err, ErrNoBinding),
		errors.Is(err, ErrAmbiguousBinding), errors.Is(err, ErrSuspended):
		slog.InfoContext(c.UserContext(), "token exchange refused", "error", err)
		return oauthError(c, fiber.StatusUnauthorized, "invalid_grant", rootMessage(err))
	case err != nil:
		return err
	}
	slog.InfoContext(c.UserContext(), "token exchange", "service_account_id", sess.ServiceAccountID, "binding_id", sess.BindingID)
	return c.JSON(fiber.Map{
		"access_token":      sess.AccessToken,
		"issued_token_type": TokenTypeAccessToken,
		"token_type":        "Bearer",
		"expires_in":        int(sess.ExpiresIn.Seconds()),
	})
}

// rootMessage drops verifier detail (logged above) from the client message.
func rootMessage(err error) string {
	for _, e := range []error{ErrUnknownIssuer, ErrInvalidToken, ErrNoBinding, ErrAmbiguousBinding, ErrSuspended} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	return "invalid token"
}

type issuerRequest struct {
	Name      string `json:"name"`
	IssuerURL string `json:"issuer_url"`
	Audience  string `json:"audience"`
	Enabled   *bool  `json:"enabled"`
}

func (h *Handler) parseIssuer(c *fiber.Ctx) (Issuer, error) {
	var body issuerRequest
	if err := httpx.Parse(c, &body); err != nil {
		return Issuer{}, err
	}
	i := Issuer{
		Name:      strings.TrimSpace(body.Name),
		IssuerURL: strings.TrimSpace(body.IssuerURL),
		Audience:  strings.TrimSpace(body.Audience),
		Enabled:   body.Enabled == nil || *body.Enabled,
	}
	if i.Name == "" || i.Audience == "" {
		return Issuer{}, fiber.NewError(fiber.StatusBadRequest, "name and audience are required")
	}
	u, err := url.Parse(i.IssuerURL)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil ||
		(u.Scheme != "https" && (u.Scheme != "http" || !h.allowHTTP)) {
		return Issuer{}, fiber.NewError(fiber.StatusBadRequest, "issuer_url must be an https:// URL without query or fragment, exactly as the tokens' iss claim")
	}
	if err := netguard.CheckURL(i.IssuerURL); err != nil {
		return Issuer{}, fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return i, nil
}

// ListIssuers handles GET /federation/issuers.
func (h *Handler) ListIssuers(c *fiber.Ctx) error {
	issuers, err := h.repo.ListIssuers(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"issuers": issuers})
}

// CreateIssuer handles POST /federation/issuers.
func (h *Handler) CreateIssuer(c *fiber.Ctx) error {
	i, err := h.parseIssuer(c)
	if err != nil {
		return err
	}
	out, err := h.repo.CreateIssuer(c.UserContext(), i, auth.UserID(c))
	if err != nil {
		return repoErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

// GetIssuer handles GET /federation/issuers/{id}.
func (h *Handler) GetIssuer(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "issuerID")
	if err != nil {
		return err
	}
	i, err := h.repo.GetIssuer(c.UserContext(), id)
	if err != nil {
		return repoErr(err)
	}
	return c.JSON(i)
}

// UpdateIssuer handles PUT /federation/issuers/{id}.
func (h *Handler) UpdateIssuer(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "issuerID")
	if err != nil {
		return err
	}
	i, err := h.parseIssuer(c)
	if err != nil {
		return err
	}
	i.ID = id
	out, err := h.repo.UpdateIssuer(c.UserContext(), i)
	if err != nil {
		return repoErr(err)
	}
	return c.JSON(out)
}

// DeleteIssuer handles DELETE /federation/issuers/{id}; its bindings go too.
func (h *Handler) DeleteIssuer(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "issuerID")
	if err != nil {
		return err
	}
	if err := h.repo.DeleteIssuer(c.UserContext(), id); err != nil {
		return repoErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// TestIssuer handles POST /federation/issuers/{id}/test: runs discovery now.
func (h *Handler) TestIssuer(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "issuerID")
	if err != nil {
		return err
	}
	i, err := h.repo.GetIssuer(c.UserContext(), id)
	if err != nil {
		return repoErr(err)
	}
	if err := h.svc.Test(c.UserContext(), i); err != nil {
		return c.JSON(fiber.Map{"ok": false, "error": err.Error()})
	}
	return c.JSON(fiber.Map{"ok": true})
}

type bindingRequest struct {
	IssuerID         string            `json:"issuer_id"`
	ServiceAccountID string            `json:"service_account_id"`
	ProjectID        *string           `json:"project_id"`
	Name             string            `json:"name"`
	Conditions       map[string]string `json:"conditions"`
	Enabled          *bool             `json:"enabled"`
}

func parseBinding(c *fiber.Ctx) (Binding, error) {
	var body bindingRequest
	if err := httpx.Parse(c, &body); err != nil {
		return Binding{}, err
	}
	b := Binding{
		IssuerID:         body.IssuerID,
		ServiceAccountID: body.ServiceAccountID,
		ProjectID:        body.ProjectID,
		Name:             strings.TrimSpace(body.Name),
		Conditions:       map[string]string{},
		Enabled:          body.Enabled == nil || *body.Enabled,
	}
	if b.ProjectID != nil && *b.ProjectID == "" {
		b.ProjectID = nil
	}
	if b.Name == "" {
		return Binding{}, fiber.NewError(fiber.StatusBadRequest, "name is required")
	}
	if uuid.Validate(b.IssuerID) != nil || uuid.Validate(b.ServiceAccountID) != nil ||
		(b.ProjectID != nil && uuid.Validate(*b.ProjectID) != nil) {
		return Binding{}, fiber.NewError(fiber.StatusBadRequest, "issuer_id, service_account_id and project_id must be ids")
	}
	for k, v := range body.Conditions {
		b.Conditions[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	if err := validateConditions(b.Conditions); err != nil {
		return Binding{}, fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return b, nil
}

// ListBindings handles GET /federation/bindings.
func (h *Handler) ListBindings(c *fiber.Ctx) error {
	bindings, err := h.repo.ListBindings(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"bindings": bindings})
}

// CreateBinding handles POST /federation/bindings.
func (h *Handler) CreateBinding(c *fiber.Ctx) error {
	b, err := parseBinding(c)
	if err != nil {
		return err
	}
	out, err := h.repo.CreateBinding(c.UserContext(), b, auth.UserID(c))
	if err != nil {
		return repoErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

// GetBinding handles GET /federation/bindings/{id}.
func (h *Handler) GetBinding(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "bindingID")
	if err != nil {
		return err
	}
	b, err := h.repo.GetBinding(c.UserContext(), id)
	if err != nil {
		return repoErr(err)
	}
	return c.JSON(b)
}

// UpdateBinding handles PUT /federation/bindings/{id}.
func (h *Handler) UpdateBinding(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "bindingID")
	if err != nil {
		return err
	}
	b, err := parseBinding(c)
	if err != nil {
		return err
	}
	b.ID = id
	out, err := h.repo.UpdateBinding(c.UserContext(), b)
	if err != nil {
		return repoErr(err)
	}
	return c.JSON(out)
}

// DeleteBinding handles DELETE /federation/bindings/{id}.
func (h *Handler) DeleteBinding(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "bindingID")
	if err != nil {
		return err
	}
	if err := h.repo.DeleteBinding(c.UserContext(), id); err != nil {
		return repoErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func repoErr(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "not found")
	case errors.Is(err, ErrDuplicateIssuer):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	case errors.Is(err, ErrUnknownReference):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return err
}
