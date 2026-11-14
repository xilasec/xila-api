package serviceaccount

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/apitoken"
	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
)

// DefaultKeyDays is a key's lifetime when the request names none (capped by
// the configured maximum).
const DefaultKeyDays = 30

// KeyIssuer mints API keys (apitoken.Service: same hashing, same validation
// path as every other API token).
type KeyIssuer interface {
	Generate(ctx context.Context, userID, name string, projectID *string, ttl time.Duration) (apitoken.Token, string, error)
}

// KeyStore lists and revokes them (apitoken.Repository).
type KeyStore interface {
	ListByUser(ctx context.Context, userID string) ([]apitoken.Token, error)
	Delete(ctx context.Context, id, userID string) error
}

// Handler exposes service-account administration. Every route is
// instance-admin only (authz adminOnly on /service-accounts).
type Handler struct {
	repo       *Repository
	issuer     KeyIssuer
	keys       KeyStore
	keyMaxDays int
}

// NewHandler constructs a Handler. keyMaxDays caps a key's lifetime.
func NewHandler(repo *Repository, issuer KeyIssuer, keys KeyStore, keyMaxDays int) *Handler {
	return &Handler{repo: repo, issuer: issuer, keys: keys, keyMaxDays: keyMaxDays}
}

// Register mounts the routes.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/service-accounts", h.List)
	r.Post("/service-accounts", h.Create)
	r.Get("/service-accounts/:accountID", h.Get)
	r.Patch("/service-accounts/:accountID", h.Update)
	r.Delete("/service-accounts/:accountID", h.Delete)
	r.Post("/service-accounts/:accountID/suspend", h.Suspend)
	r.Post("/service-accounts/:accountID/resume", h.Resume)
	r.Get("/service-accounts/:accountID/keys", h.ListKeys)
	r.Post("/service-accounts/:accountID/keys", h.CreateKey)
	r.Delete("/service-accounts/:accountID/keys/:keyID", h.DeleteKey)
}

var nameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

type createRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Create handles POST /service-accounts.
func (h *Handler) Create(c *fiber.Ctx) error {
	var body createRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	name := strings.ToLower(strings.TrimSpace(body.Name))
	if !nameRe.MatchString(name) {
		return fiber.NewError(fiber.StatusBadRequest, "name must be 1–63 lowercase letters, digits or dashes (not at either end)")
	}
	a, err := h.repo.Create(c.UserContext(), name, strings.TrimSpace(body.Description), auth.UserID(c))
	if errors.Is(err, ErrDuplicate) {
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(a)
}

// List handles GET /service-accounts.
func (h *Handler) List(c *fiber.Ctx) error {
	accounts, err := h.repo.List(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"service_accounts": accounts})
}

// Get handles GET /service-accounts/{id}.
func (h *Handler) Get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "accountID")
	if err != nil {
		return err
	}
	a, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		return notFound(err)
	}
	return c.JSON(a)
}

type updateRequest struct {
	Description string `json:"description"`
}

// Update handles PATCH /service-accounts/{id} (the description; the name is
// the account's identity and doesn't change).
func (h *Handler) Update(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "accountID")
	if err != nil {
		return err
	}
	var body updateRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	a, err := h.repo.SetDescription(c.UserContext(), id, strings.TrimSpace(body.Description))
	if err != nil {
		return notFound(err)
	}
	return c.JSON(a)
}

// Delete handles DELETE /service-accounts/{id}.
func (h *Handler) Delete(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "accountID")
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.UserContext(), id); err != nil {
		return notFound(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Suspend handles POST /service-accounts/{id}/suspend: its sessions end and
// its keys are revoked immediately.
func (h *Handler) Suspend(c *fiber.Ctx) error { return h.setSuspended(c, true) }

// Resume handles POST /service-accounts/{id}/resume.
func (h *Handler) Resume(c *fiber.Ctx) error { return h.setSuspended(c, false) }

func (h *Handler) setSuspended(c *fiber.Ctx, suspended bool) error {
	id, err := httpx.ID(c, "accountID")
	if err != nil {
		return err
	}
	a, err := h.repo.SetSuspended(c.UserContext(), id, suspended)
	if err != nil {
		return notFound(err)
	}
	return c.JSON(a)
}

// ListKeys handles GET /service-accounts/{id}/keys (never the secrets).
func (h *Handler) ListKeys(c *fiber.Ctx) error {
	a, err := h.account(c)
	if err != nil {
		return err
	}
	keys, err := h.keys.ListByUser(c.UserContext(), a.ID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"keys": keys})
}

type createKeyRequest struct {
	Name          string  `json:"name"`
	ProjectID     *string `json:"project_id"`
	ExpiresInDays int     `json:"expires_in_days"`
}

// CreateKey handles POST /service-accounts/{id}/keys. A key always expires:
// DefaultKeyDays unless asked otherwise, never beyond the configured maximum.
func (h *Handler) CreateKey(c *fiber.Ctx) error {
	a, err := h.account(c)
	if err != nil {
		return err
	}
	if a.SuspendedAt != nil {
		return fiber.NewError(fiber.StatusConflict, "the service account is suspended; resume it first")
	}
	var body createKeyRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}
	if body.ProjectID != nil && uuid.Validate(*body.ProjectID) != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid project_id")
	}
	days := body.ExpiresInDays
	switch {
	case days == 0:
		days = min(DefaultKeyDays, h.keyMaxDays)
	case days < 0 || days > h.keyMaxDays:
		return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("expires_in_days must be between 1 and %d", h.keyMaxDays))
	}
	tok, secret, err := h.issuer.Generate(c.UserContext(), a.ID, body.Name, body.ProjectID, time.Duration(days)*24*time.Hour)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"key": tok, "secret": secret})
}

// DeleteKey handles DELETE /service-accounts/{id}/keys/{keyID}.
func (h *Handler) DeleteKey(c *fiber.Ctx) error {
	a, err := h.account(c)
	if err != nil {
		return err
	}
	keyID, err := httpx.ID(c, "keyID")
	if err != nil {
		return err
	}
	if err := h.keys.Delete(c.UserContext(), keyID, a.ID); errors.Is(err, apitoken.ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "key not found")
	} else if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) account(c *fiber.Ctx) (Account, error) {
	id, err := httpx.ID(c, "accountID")
	if err != nil {
		return Account{}, err
	}
	a, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		return Account{}, notFound(err)
	}
	return a, nil
}

func notFound(err error) error {
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	return err
}
