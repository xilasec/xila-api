package issuetracker

import (
	"errors"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/secretbox"
)

// Handler exposes tracker config, finding↔issue links and the on-demand sync.
type Handler struct {
	svc *Service
}

// NewHandler constructs a Handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// Register mounts the routes. authz gates them: reading the config needs project
// viewer; changing or testing it needs project owner (it holds a credential and
// decides what gets filed in another system); creating an issue needs editor;
// /issue-trackers/* is instance-admin.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/projects/:projectID/issue-tracker", h.get)
	r.Put("/projects/:projectID/issue-tracker", h.put)
	r.Delete("/projects/:projectID/issue-tracker", h.delete)
	r.Post("/projects/:projectID/issue-tracker/test", h.test)
	r.Get("/findings/:findingID/issue", h.getLink)
	r.Post("/findings/:findingID/issue", h.createIssue)
	r.Post("/issue-trackers/sync", h.sync)
}

func mapErr(err error) error {
	var verr ValidationError
	switch {
	case errors.As(err, &verr), errors.Is(err, secretbox.ErrNoKey), errors.Is(err, ErrNoTracker):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrNoProject), errors.Is(err, ErrNoLink),
		errors.Is(err, finding.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	return err
}

func (h *Handler) get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	t, err := h.svc.Get(c.UserContext(), id)
	if err != nil {
		return mapErr(err)
	}
	return c.JSON(t)
}

func (h *Handler) put(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var in Input
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	t, err := h.svc.Put(c.UserContext(), id, in)
	if err != nil {
		return mapErr(err)
	}
	return c.JSON(t)
}

func (h *Handler) delete(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	if err := h.svc.Delete(c.UserContext(), id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// test reports whether the stored credentials can read the target. A tracker
// that rejects them is a 502 carrying the tracker's message.
func (h *Handler) test(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	if err := h.svc.Test(c.UserContext(), id); err != nil {
		if mapped := mapErr(err); mapped != err { //nolint:errorlint // identity check: did mapErr translate this error
			return mapped
		}
		return fiber.NewError(fiber.StatusBadGateway, "tracker check failed: "+remoteMessage(c, err))
	}
	return c.JSON(fiber.Map{"ok": true})
}

func (h *Handler) getLink(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	l, err := h.svc.Link(c.UserContext(), id)
	if err != nil {
		return mapErr(err)
	}
	return c.JSON(l)
}

// createIssue files the finding's issue now: 201 when created, 200 with the
// existing link when it already has one.
func (h *Handler) createIssue(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	l, created, err := h.svc.CreateIssue(c.UserContext(), id)
	if err != nil {
		if mapped := mapErr(err); mapped != err { //nolint:errorlint // identity check: did mapErr translate this error
			return mapped
		}
		return fiber.NewError(fiber.StatusBadGateway, "create issue failed: "+remoteMessage(c, err))
	}
	if created {
		return c.Status(fiber.StatusCreated).JSON(l)
	}
	return c.JSON(l)
}

func (h *Handler) sync(c *fiber.Ctx) error {
	res, err := h.svc.Sync(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(res)
}

// remoteMessage is err as shown to the caller: instance admins see what the
// tracker answered; anyone else (project owners can set the tracker URL) only
// the request and status, so the Test button can't read internal services.
func remoteMessage(c *fiber.Ctx, err error) string {
	var r RemoteError
	if !authz.VisibleScope(c).AllAccess && errors.As(err, &r) {
		return r.Public()
	}
	return err.Error()
}
