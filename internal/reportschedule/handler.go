package reportschedule

import (
	"context"
	"errors"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
)

// admins answers whether an actor is an instance admin (membership.Repository).
type admins interface {
	AdminStatus(ctx context.Context, userID string) (isAdmin, isOwner bool, err error)
}

// Handler serves /report-schedules: each user manages their own; instance
// admins see and manage every schedule.
type Handler struct {
	svc   *Service
	admin admins
}

// NewHandler constructs a Handler.
func NewHandler(svc *Service, admin admins) *Handler {
	return &Handler{svc: svc, admin: admin}
}

// Register mounts the routes.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/report-schedules", h.list)
	r.Post("/report-schedules", h.create)
	r.Get("/report-schedules/:scheduleID", h.get)
	r.Put("/report-schedules/:scheduleID", h.update)
	r.Delete("/report-schedules/:scheduleID", h.delete)
	r.Get("/report-schedules/:scheduleID/runs", h.runs)
	r.Post("/report-schedules/:scheduleID/send-now", h.sendNow)
}

func (h *Handler) isAdmin(c *fiber.Ctx) bool {
	ok, _, err := h.admin.AdminStatus(c.UserContext(), auth.UserID(c))
	return err == nil && ok
}

func scheduleErr(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "report schedule not found")
	case errors.Is(err, ErrOwnerUnavailable):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	var verr ValidationError
	if errors.As(err, &verr) {
		return fiber.NewError(fiber.StatusBadRequest, verr.Error())
	}
	return err
}

// owned loads id, 404ing unless the caller owns it or is an instance admin
// (so an unauthorized id reads exactly like a missing one).
func (h *Handler) owned(c *fiber.Ctx, id string) (Schedule, error) {
	sch, err := h.svc.Get(c.UserContext(), id)
	if err != nil {
		return Schedule{}, scheduleErr(err)
	}
	if sch.OwnerID != auth.UserID(c) && !h.isAdmin(c) {
		return Schedule{}, fiber.NewError(fiber.StatusNotFound, "report schedule not found")
	}
	return sch, nil
}

func (h *Handler) list(c *fiber.Ctx) error {
	schedules, err := h.svc.List(c.UserContext(), auth.UserID(c), h.isAdmin(c))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"report_schedules": schedules})
}

func (h *Handler) get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "scheduleID")
	if err != nil {
		return err
	}
	sch, err := h.owned(c, id)
	if err != nil {
		return err
	}
	return c.JSON(sch)
}

func (h *Handler) create(c *fiber.Ctx) error {
	var in Input
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	sch, err := h.svc.Create(c.UserContext(), auth.UserID(c), in)
	if err != nil {
		return scheduleErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(sch)
}

func (h *Handler) update(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "scheduleID")
	if err != nil {
		return err
	}
	existing, err := h.owned(c, id)
	if err != nil {
		return err
	}
	var in Input
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	sch, err := h.svc.Update(c.UserContext(), id, existing.OwnerID, in)
	if err != nil {
		return scheduleErr(err)
	}
	return c.JSON(sch)
}

func (h *Handler) delete(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "scheduleID")
	if err != nil {
		return err
	}
	if _, err := h.owned(c, id); err != nil {
		return err
	}
	if err := h.svc.Delete(c.UserContext(), id); err != nil {
		return scheduleErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func (h *Handler) runs(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "scheduleID")
	if err != nil {
		return err
	}
	if _, err := h.owned(c, id); err != nil {
		return err
	}
	runs, err := h.svc.Runs(c.UserContext(), id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"runs": runs})
}

// sendNow handles POST /report-schedules/{id}/send-now: renders and delivers
// immediately, synchronously (a report takes well under a request timeout).
func (h *Handler) sendNow(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "scheduleID")
	if err != nil {
		return err
	}
	if _, err := h.owned(c, id); err != nil {
		return err
	}
	if err := h.svc.SendNow(c.UserContext(), id); err != nil {
		return scheduleErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}
