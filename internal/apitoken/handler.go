package apitoken

import (
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
)

// Handler exposes API-token management over HTTP.
type Handler struct {
	repo *Repository
	svc  *Service
	// reauthWindow is how recently the session must have authenticated to
	// create a token (0 = no check).
	reauthWindow time.Duration
}

// NewHandler constructs an API-token Handler.
func NewHandler(repo *Repository, svc *Service) *Handler {
	return &Handler{repo: repo, svc: svc}
}

// WithReauthWindow makes creating a token require a session that
// authenticated within d (REAUTH_WINDOW): a stolen or forgotten session
// can't quietly mint a long-lived credential.
func (h *Handler) WithReauthWindow(d time.Duration) *Handler {
	h.reauthWindow = d
	return h
}

// ReauthRequired is the error message (and X-Reauth-Required header) of a
// token request whose session last authenticated too long ago; the client
// re-authenticates (POST /me/reauth) and retries.
const ReauthRequired = "re-authentication required: confirm your password (POST /me/reauth) and retry"

// Register mounts token routes.
func (h *Handler) Register(r fiber.Router) {
	r.Post("/tokens", h.Create)
	r.Get("/tokens", h.List)
	r.Delete("/tokens/:tokenID", h.Delete)
}

type createRequest struct {
	Name          string  `json:"name"`
	ProjectID     *string `json:"project_id"`
	ExpiresInDays int     `json:"expires_in_days"`
}

type createResponse struct {
	Token  Token  `json:"token"`
	Secret string `json:"secret"` // shown once
}

// Create handles POST /tokens.
func (h *Handler) Create(c *fiber.Ctx) error {
	actor := auth.CurrentActor(c)
	if actor.IsServiceAccount {
		// Its keys are an admin's to issue, with a capped expiry; minting its
		// own would sidestep both.
		return fiber.NewError(fiber.StatusForbidden, "a service account's keys are managed by an admin")
	}
	if actor.IsToken {
		// A token minting tokens would let a leaked one outlive its revocation.
		return fiber.NewError(fiber.StatusForbidden, "API tokens can't create API tokens; sign in")
	}
	if h.reauthWindow > 0 && time.Since(actor.AuthTime) > h.reauthWindow {
		c.Set("X-Reauth-Required", "true")
		return fiber.NewError(fiber.StatusForbidden, ReauthRequired)
	}
	var body createRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}

	var ttl time.Duration
	if body.ExpiresInDays > 0 {
		ttl = time.Duration(body.ExpiresInDays) * 24 * time.Hour
	}

	tok, secret, err := h.svc.Generate(c.UserContext(), auth.UserID(c), body.Name, body.ProjectID, ttl)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(createResponse{Token: tok, Secret: secret})
}

// List handles GET /tokens (secrets are never returned).
func (h *Handler) List(c *fiber.Ctx) error {
	tokens, err := h.repo.ListByUser(c.UserContext(), auth.UserID(c))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"tokens": tokens})
}

// Delete handles DELETE /tokens/{id} (revocation).
func (h *Handler) Delete(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "tokenID")
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.UserContext(), id, auth.UserID(c)); errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "token not found")
	} else if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
