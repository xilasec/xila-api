package connector

import (
	"errors"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/secretbox"
)

// Handler exposes connector config, the connection test and "pull now".
type Handler struct {
	svc *Service
}

// NewHandler constructs a Handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// Register mounts the routes. authz gates them: listing needs project viewer;
// pulling needs editor (it is a scan); creating, changing, deleting or testing a
// connector needs owner (it holds a credential for another system).
func (h *Handler) Register(r fiber.Router) {
	r.Get("/projects/:projectID/connectors", h.list)
	r.Post("/projects/:projectID/connectors", h.create)
	r.Put("/projects/:projectID/connectors/:connectorID", h.update)
	r.Delete("/projects/:projectID/connectors/:connectorID", h.delete)
	r.Post("/projects/:projectID/connectors/:connectorID/test", h.test)
	r.Post("/projects/:projectID/connectors/:connectorID/pull", h.pull)
}

func mapErr(c *fiber.Ctx, err error) error {
	var verr ValidationError
	var rerr RemoteError
	switch {
	case errors.As(err, &verr), errors.Is(err, secretbox.ErrNoKey):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrNoProject):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	case errors.Is(err, ErrDuplicate), errors.Is(err, ErrBusy):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	case errors.As(err, &rerr):
		// Only instance admins see what the remote answered: anyone else who can
		// set a connector URL could use the Test button to read internal services.
		if authz.VisibleScope(c).AllAccess {
			return fiber.NewError(fiber.StatusBadGateway, rerr.Error())
		}
		return fiber.NewError(fiber.StatusBadGateway, rerr.Public())
	}
	return err
}

func ids(c *fiber.Ctx) (projectID, connectorID string, err error) {
	if projectID, err = httpx.ID(c, "projectID"); err != nil {
		return "", "", err
	}
	if connectorID, err = httpx.ID(c, "connectorID"); err != nil {
		return "", "", err
	}
	return projectID, connectorID, nil
}

func (h *Handler) list(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	list, err := h.svc.List(c.UserContext(), id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"connectors": list})
}

func (h *Handler) create(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var in Input
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	out, err := h.svc.Create(c.UserContext(), id, in)
	if err != nil {
		return mapErr(c, err)
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Handler) update(c *fiber.Ctx) error {
	projectID, connectorID, err := ids(c)
	if err != nil {
		return err
	}
	var in Input
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	out, err := h.svc.Update(c.UserContext(), projectID, connectorID, in)
	if err != nil {
		return mapErr(c, err)
	}
	return c.JSON(out)
}

func (h *Handler) delete(c *fiber.Ctx) error {
	projectID, connectorID, err := ids(c)
	if err != nil {
		return err
	}
	if err := h.svc.Delete(c.UserContext(), projectID, connectorID); err != nil {
		return mapErr(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// test reports whether the stored credentials can read the remote project; a
// remote that rejects them is a 502 carrying its message.
func (h *Handler) test(c *fiber.Ctx) error {
	projectID, connectorID, err := ids(c)
	if err != nil {
		return err
	}
	name, err := h.svc.Test(c.UserContext(), projectID, connectorID)
	if err != nil {
		return mapErr(c, err)
	}
	return c.JSON(fiber.Map{"ok": true, "remote_name": name})
}

// pull runs the connector now and returns what it did. A remote failure is a
// 502 (recorded on the connector; no finding is touched); a pull already in
// progress is a 409.
func (h *Handler) pull(c *fiber.Ctx) error {
	projectID, connectorID, err := ids(c)
	if err != nil {
		return err
	}
	res, err := h.svc.Pull(c.UserContext(), projectID, connectorID)
	if err != nil {
		return mapErr(c, err)
	}
	return c.JSON(res)
}
