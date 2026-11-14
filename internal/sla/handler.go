package sla

import (
	"errors"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/httpx"
)

// Handler exposes SLA policy management and the on-demand sweep.
type Handler struct {
	repo  *Repository
	sweep *Service
}

// NewHandler constructs an SLA Handler.
func NewHandler(repo *Repository, sweep *Service) *Handler {
	return &Handler{repo: repo, sweep: sweep}
}

// Register mounts SLA routes. authz gates them: /sla/* is instance-admin;
// org policies need org admin to change; project policies need project owner to
// change, since an SLA is a commitment the team is held to, not one it edits.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/sla/policy", h.get(globalTarget))
	r.Put("/sla/policy", h.put(globalTarget))
	r.Delete("/sla/policy", h.delete(globalTarget))
	r.Post("/sla/sweep", h.Sweep)
	r.Get("/sla/settings", h.GetSettings)
	r.Put("/sla/settings", h.PutSettings)
	r.Get("/orgs/:orgID/sla/policy", h.get(orgTarget))
	r.Put("/orgs/:orgID/sla/policy", h.put(orgTarget))
	r.Delete("/orgs/:orgID/sla/policy", h.delete(orgTarget))
	r.Get("/projects/:projectID/sla/policy", h.get(projectTarget))
	r.Put("/projects/:projectID/sla/policy", h.put(projectTarget))
	r.Delete("/projects/:projectID/sla/policy", h.delete(projectTarget))
}

type targetFn func(c *fiber.Ctx) (Target, string, error)

func globalTarget(*fiber.Ctx) (Target, string, error) { return Global, ScopeGlobal, nil }

func orgTarget(c *fiber.Ctx) (Target, string, error) {
	id, err := httpx.ID(c, "orgID")
	if err != nil {
		return Target{}, "", err
	}
	return Target{OrgID: &id}, ScopeOrg, nil
}

func projectTarget(c *fiber.Ctx) (Target, string, error) {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return Target{}, "", err
	}
	return Target{ProjectID: &id}, ScopeProject, nil
}

// get returns the policy in force for the target and the scope it comes from.
func (h *Handler) get(target targetFn) fiber.Handler {
	return func(c *fiber.Ctx) error {
		t, _, err := target(c)
		if err != nil {
			return err
		}
		eff, err := h.repo.EffectiveFor(c.UserContext(), t)
		if err != nil {
			return err
		}
		return c.JSON(eff)
	}
}

// put stores the target's policy. The body states all five windows; an omitted
// or null one means no SLA for that severity at this scope.
func (h *Handler) put(target targetFn) fiber.Handler {
	return func(c *fiber.Ctx) error {
		t, scope, err := target(c)
		if err != nil {
			return err
		}
		var d Days
		if err := httpx.Parse(c, &d); err != nil {
			return err
		}
		if err := d.Validate(); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
		if _, err := h.repo.Put(c.UserContext(), t, d); errors.Is(err, ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, err.Error())
		} else if err != nil {
			return err
		}
		// What's now in force — for a project that includes the windows after
		// criticality scaling.
		eff, err := h.repo.EffectiveFor(c.UserContext(), t)
		if err != nil {
			return err
		}
		eff.Scope = scope
		return c.JSON(eff)
	}
}

// delete removes the target's own policy; it then inherits the enclosing scope.
func (h *Handler) delete(target targetFn) fiber.Handler {
	return func(c *fiber.Ctx) error {
		t, _, err := target(c)
		if err != nil {
			return err
		}
		if err := h.repo.Delete(c.UserContext(), t); err != nil {
			return err
		}
		return c.SendStatus(fiber.StatusNoContent)
	}
}

type settingsResponse struct {
	Settings
	Matrix Matrix `json:"matrix"`
}

func (h *Handler) respondSettings(c *fiber.Ctx, s Settings) error {
	m, err := h.repo.Matrix(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(settingsResponse{Settings: s, Matrix: m})
}

// GetSettings handles GET /sla/settings (admin): the instance-wide options and
// the resulting windows per project criticality × severity.
func (h *Handler) GetSettings(c *fiber.Ctx) error {
	s, err := h.repo.Settings(c.UserContext())
	if err != nil {
		return err
	}
	return h.respondSettings(c, s)
}

// PutSettings handles PUT /sla/settings (admin). Saving re-applies every
// finding's window, so existing deadlines move with the setting.
func (h *Handler) PutSettings(c *fiber.Ctx) error {
	var s Settings
	if err := httpx.Parse(c, &s); err != nil {
		return err
	}
	if err := s.Factors.Validate(); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	out, err := h.repo.PutSettings(c.UserContext(), s)
	if err != nil {
		return err
	}
	return h.respondSettings(c, out)
}

// Sweep handles POST /sla/sweep: alert on newly breached / due-soon findings
// now (it also runs on SLA_SWEEP_INTERVAL).
func (h *Handler) Sweep(c *fiber.Ctx) error {
	res, err := h.sweep.Sweep(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(res)
}
