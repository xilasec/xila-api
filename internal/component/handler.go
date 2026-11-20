package component

import (
	"errors"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
)

// Handler exposes internal-component patterns (instance-admin; authz).
type Handler struct {
	svc *Service
}

// NewHandler constructs the Handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// Register mounts the routes.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/component-patterns", h.List)
	r.Post("/component-patterns", h.Create)
	r.Put("/component-patterns/:id", h.Update)
	r.Delete("/component-patterns/:id", h.Delete)
}

func mapErr(err error) error {
	var verr *ValidationError
	switch {
	case errors.As(err, &verr):
		return fiber.NewError(fiber.StatusBadRequest, verr.Error())
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "component pattern not found")
	default:
		return err
	}
}

func actorID(c *fiber.Ctx) *string {
	if a := auth.CurrentActor(c); a.UserID != "" {
		return &a.UserID
	}
	return nil
}

// List returns every pattern.
func (h *Handler) List(c *fiber.Ctx) error {
	patterns, err := h.svc.List(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"patterns": patterns})
}

// Create handles POST /component-patterns.
func (h *Handler) Create(c *fiber.Ctx) error {
	var p Pattern
	if err := c.BodyParser(&p); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	created, err := h.svc.Create(c.UserContext(), p, actorID(c))
	if err != nil {
		return mapErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(created)
}

// Update handles PUT /component-patterns/{id}.
func (h *Handler) Update(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "id")
	if err != nil {
		return err
	}
	var p Pattern
	if err := c.BodyParser(&p); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	p.ID = id
	updated, err := h.svc.Update(c.UserContext(), p)
	if err != nil {
		return mapErr(err)
	}
	return c.JSON(updated)
}

// Delete handles DELETE /component-patterns/{id}.
func (h *Handler) Delete(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "id")
	if err != nil {
		return err
	}
	if err := h.svc.Delete(c.UserContext(), id); err != nil {
		return mapErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}
