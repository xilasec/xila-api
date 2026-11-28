package triage

import (
	"errors"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/httpx"
)

// registerProject mounts the routes a project owner manages their project's
// own rules with (M13 13.10). authz.Middleware makes their mutations
// owner-level; every route keeps to the path's project, so a rule of another
// project, or a global one, is "not found" here.
func (h *Handler) registerProject(r fiber.Router) {
	r.Get("/projects/:projectID/triage-rules", h.ListProject)
	r.Post("/projects/:projectID/triage-rules", h.CreateProject)
	r.Post("/projects/:projectID/triage-rules/apply", h.ApplyProject)
	r.Patch("/projects/:projectID/triage-rules/:ruleID", h.UpdateProject)
	r.Delete("/projects/:projectID/triage-rules/:ruleID", h.DeleteProject)
	r.Get("/projects/:projectID/triage-settings", h.GetProjectSettings)
	r.Put("/projects/:projectID/triage-settings", h.PutProjectSettings)
}

// ListProject handles GET /projects/{id}/triage-rules: the project's own
// rules, in evaluation order and every state.
func (h *Handler) ListProject(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	rules, err := h.repo.ListForProject(c.UserContext(), pid)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"rules": rules})
}

// CreateProject handles POST /projects/{id}/triage-rules: a rule of this
// project only, whatever project_id the body says.
func (h *Handler) CreateProject(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	rule, err := parseRule(c)
	if err != nil {
		return err
	}
	rule.ProjectID = &pid
	return h.create(c, rule)
}

// ownRule loads the path's rule, "not found" unless it belongs to the path's
// project.
func (h *Handler) ownRule(c *fiber.Ctx) (string, Rule, error) {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return "", Rule{}, err
	}
	id, err := httpx.ID(c, "ruleID")
	if err != nil {
		return "", Rule{}, err
	}
	rule, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) || (err == nil && (rule.ProjectID == nil || *rule.ProjectID != pid)) {
		return "", Rule{}, fiber.NewError(fiber.StatusNotFound, "triage rule not found")
	}
	return pid, rule, err
}

// UpdateProject handles PATCH /projects/{id}/triage-rules/{ruleID}.
func (h *Handler) UpdateProject(c *fiber.Ctx) error {
	pid, existing, err := h.ownRule(c)
	if err != nil {
		return err
	}
	rule, err := parseRule(c)
	if err != nil {
		return err
	}
	rule.ID, rule.ProjectID = existing.ID, &pid
	return h.update(c, rule)
}

// DeleteProject handles DELETE /projects/{id}/triage-rules/{ruleID}.
func (h *Handler) DeleteProject(c *fiber.Ctx) error {
	_, rule, err := h.ownRule(c)
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.UserContext(), rule.ID); err != nil {
		return writeError(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ApplyProject handles POST /projects/{id}/triage-rules/apply: the project's
// rules (its own and, unless it opted out, the global ones) over its backlog.
func (h *Handler) ApplyProject(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	changed, err := h.svc.ApplyToProject(c.UserContext(), pid)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"applied": changed})
}

// projectSettings is a project's view of its triage settings.
type projectSettings struct {
	// SkipGlobalRules: the project's findings skip global triage rules and
	// global vulnerability policies.
	SkipGlobalRules bool `json:"skip_global_rules"`
	// AllowSkipGlobalRules is the instance setting that permits it.
	AllowSkipGlobalRules bool `json:"allow_skip_global_rules"`
}

func (h *Handler) projectSettings(c *fiber.Ctx, pid string) error {
	skip, err := h.repo.ProjectSkipsGlobalRules(c.UserContext(), pid)
	if err != nil {
		return writeError(err)
	}
	allow, err := h.repo.AllowSkipGlobalRules(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(projectSettings{SkipGlobalRules: skip, AllowSkipGlobalRules: allow})
}

// GetProjectSettings handles GET /projects/{id}/triage-settings.
func (h *Handler) GetProjectSettings(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	return h.projectSettings(c, pid)
}

// PutProjectSettings handles PUT /projects/{id}/triage-settings. Opting out
// needs the instance setting; opting back in never does.
func (h *Handler) PutProjectSettings(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var body struct {
		SkipGlobalRules bool `json:"skip_global_rules"`
	}
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	if body.SkipGlobalRules {
		allow, err := h.repo.AllowSkipGlobalRules(c.UserContext())
		if err != nil {
			return err
		}
		if !allow {
			return fiber.NewError(fiber.StatusForbidden, "an instance admin hasn't allowed projects to opt out of global rules")
		}
	}
	if err := h.repo.SetProjectSkipsGlobalRules(c.UserContext(), pid, body.SkipGlobalRules); err != nil {
		return writeError(err)
	}
	return h.projectSettings(c, pid)
}

// GetSettings handles GET /triage-rules/settings (admin).
func (h *Handler) GetSettings(c *fiber.Ctx) error {
	s, err := h.repo.GetSettings(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(s)
}

// PutSettings handles PUT /triage-rules/settings (admin). Turning
// allow_skip_global_rules off leaves projects' opt-outs stored but ignored.
func (h *Handler) PutSettings(c *fiber.Ctx) error {
	var body Settings
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	s, err := h.repo.PutSettings(c.UserContext(), body)
	if err != nil {
		return err
	}
	return c.JSON(s)
}
