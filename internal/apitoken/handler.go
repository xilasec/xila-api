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
}

// NewHandler constructs an API-token Handler.
func NewHandler(repo *Repository, svc *Service) *Handler {
	return &Handler{repo: repo, svc: svc}
}

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
	if auth.CurrentActor(c).IsServiceAccount {
		// Its keys are an admin's to issue, with a capped expiry; minting its
		// own would sidestep both.
		return fiber.NewError(fiber.StatusForbidden, "a service account's keys are managed by an admin")
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
