package vulnpolicy

import (
	"context"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
)

// registerProject mounts the routes a project owner manages their project's
// own policies with (M13 13.10). authz.Middleware makes the mutations
// owner-level; every route keeps to the path's project, so an admin policy or
// another project's is "not found" here.
func (h *Handler) registerProject(r fiber.Router) {
	r.Get("/projects/:projectID/vuln-policies", h.ListProject)
	r.Post("/projects/:projectID/vuln-policies", h.CreateProject)
	r.Patch("/projects/:projectID/vuln-policies/:policyID", h.UpdateProject)
	r.Delete("/projects/:projectID/vuln-policies/:policyID", h.DeleteProject)
}

// pinToOwner keeps a project-owned policy scoped to its project alone, whoever
// edits it: an owner can't widen it, and an admin edit can't turn it global
// while its project's owners still manage it.
func pinToOwner(p *Policy, projectID string) {
	p.OwnerProjectID = &projectID
	p.Scope, p.ProjectIDs, p.Tag = ScopeProjects, []string{projectID}, ""
}

// ListProject handles GET /projects/{id}/vuln-policies: the project's own.
func (h *Handler) ListProject(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	policies, err := h.repo.ListOwned(c.UserContext(), pid)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"policies": policies})
}

// CreateProject handles POST /projects/{id}/vuln-policies.
func (h *Handler) CreateProject(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	p := Draft()
	if err := httpx.Parse(c, &p); err != nil {
		return err
	}
	pinToOwner(&p, pid)
	if err := h.validate(c.UserContext(), &p); err != nil {
		return err
	}
	out, err := h.repo.Create(c.UserContext(), p, auth.UserID(c))
	if err != nil {
		return writeError(err)
	}
	h.reevaluateProject(pid)
	return c.Status(fiber.StatusCreated).JSON(out)
}

// ownPolicy loads the path's policy, "not found" unless the path's project
// owns it.
func (h *Handler) ownPolicy(c *fiber.Ctx) (string, Policy, error) {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return "", Policy{}, err
	}
	p, err := h.lookup(c)
	if err != nil {
		return "", Policy{}, err
	}
	if p.OwnerProjectID == nil || *p.OwnerProjectID != pid {
		return "", Policy{}, fiber.NewError(fiber.StatusNotFound, "vulnerability policy not found")
	}
	return pid, p, nil
}

// UpdateProject handles PATCH /projects/{id}/vuln-policies/{policyID}.
func (h *Handler) UpdateProject(c *fiber.Ctx) error {
	pid, existing, err := h.ownPolicy(c)
	if err != nil {
		return err
	}
	p := Draft()
	if err := httpx.Parse(c, &p); err != nil {
		return err
	}
	p.ID = existing.ID
	pinToOwner(&p, pid)
	if err := h.validate(c.UserContext(), &p); err != nil {
		return err
	}
	out, err := h.repo.Update(c.UserContext(), p)
	if err != nil {
		return writeError(err)
	}
	h.reevaluateProject(pid)
	return c.JSON(out)
}

// DeleteProject handles DELETE /projects/{id}/vuln-policies/{policyID}.
func (h *Handler) DeleteProject(c *fiber.Ctx) error {
	pid, p, err := h.ownPolicy(c)
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.UserContext(), p.ID); err != nil {
		return writeError(err)
	}
	h.reevaluateProject(pid)
	return c.SendStatus(fiber.StatusNoContent)
}

// reevaluateProject is reevaluate for a project-owned policy: only its
// project can be affected.
func (h *Handler) reevaluateProject(projectID string) {
	go func() {
		_, _ = h.svc.ApplyToProject(context.Background(), projectID)
	}()
}
