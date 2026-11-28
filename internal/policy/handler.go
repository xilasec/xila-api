package policy

import (
	"context"
	"errors"
	"slices"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/projecttree"
)

// findingLister lists findings (finding.Repository).
type findingLister interface {
	List(ctx context.Context, f finding.Filter) ([]finding.Finding, error)
}

// Handler exposes policy management (mutations are instance-admin, enforced
// by the authz middleware), previews and violations (scoped to what the caller
// can see).
type Handler struct {
	repo     *Repository
	svc      *Service
	findings findingLister
}

// NewHandler constructs a policy Handler.
func NewHandler(repo *Repository, svc *Service, findings findingLister) *Handler {
	return &Handler{repo: repo, svc: svc, findings: findings}
}

// Register mounts the routes.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/policies", h.List)
	r.Post("/policies", h.Create)
	r.Post("/policies/preview", h.Preview)
	r.Post("/policies/evaluate", h.Evaluate)
	r.Get("/policies/:policyID", h.Get)
	r.Put("/policies/:policyID", h.Update)
	r.Delete("/policies/:policyID", h.Delete)
	r.Get("/policies/:policyID/violations", h.Violations)
	r.Get("/projects/:projectID/policies", h.ProjectPolicies)
}

// visible narrows a policy to what the caller may see: nil when it applies to
// none of the caller's projects; a project-scoped policy lists only the
// caller's projects.
func visible(p Policy, s authz.Scope) *Policy {
	if s.AllAccess || p.Scope == ScopeGlobal {
		return &p
	}
	ids := []string{}
	for _, id := range p.ProjectIDs {
		if slices.Contains(s.ProjectIDs, id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	p.ProjectIDs = ids
	return &p
}

// scopeProjects is the caller's project filter: nil for full access.
func scopeProjects(s authz.Scope) []string {
	if s.AllAccess {
		return nil
	}
	if s.ProjectIDs == nil {
		return []string{}
	}
	return s.ProjectIDs
}

// List handles GET /policies: every policy the caller can see, with its open
// violation count on the caller's projects' default versions.
func (h *Handler) List(c *fiber.Ctx) error {
	ctx := c.UserContext()
	s := authz.VisibleScope(c)
	all, err := h.repo.List(ctx)
	if err != nil {
		return err
	}
	counts, err := h.repo.ViolationCounts(ctx, scopeProjects(s))
	if err != nil {
		return err
	}
	out := []Policy{}
	for _, p := range all {
		if v := visible(p, s); v != nil {
			v.Violations = new(counts[v.ID])
			out = append(out, *v)
		}
	}
	return c.JSON(fiber.Map{"policies": out})
}

// Get handles GET /policies/{id}.
func (h *Handler) Get(c *fiber.Ctx) error {
	p, err := h.lookup(c)
	if err != nil {
		return err
	}
	v := visible(p, authz.VisibleScope(c))
	if v == nil {
		return fiber.NewError(fiber.StatusNotFound, "policy not found")
	}
	return c.JSON(v)
}

// Create handles POST /policies. Omitted fields take Draft's defaults.
func (h *Handler) Create(c *fiber.Ctx) error {
	p := Draft()
	if err := httpx.Parse(c, &p); err != nil {
		return err
	}
	if err := h.validate(c, &p); err != nil {
		return err
	}
	out, err := h.repo.Create(c.UserContext(), p, auth.UserID(c))
	if err != nil {
		return writeError(err)
	}
	h.reevaluate(out)
	return c.Status(fiber.StatusCreated).JSON(out)
}

// Update handles PUT /policies/{id}: a full replacement (omitted fields take
// Draft's defaults).
func (h *Handler) Update(c *fiber.Ctx) error {
	old, err := h.lookup(c)
	if err != nil {
		return err
	}
	p := Draft()
	if err := httpx.Parse(c, &p); err != nil {
		return err
	}
	p.ID = old.ID
	if err := h.validate(c, &p); err != nil {
		return err
	}
	out, err := h.repo.Update(c.UserContext(), p)
	if err != nil {
		return writeError(err)
	}
	h.reevaluate(old, out)
	return c.JSON(out)
}

// Delete handles DELETE /policies/{id}. Its open violations close on the
// re-evaluation that follows.
func (h *Handler) Delete(c *fiber.Ctx) error {
	old, err := h.lookup(c)
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.UserContext(), old.ID); err != nil {
		return writeError(err)
	}
	h.reevaluate(old)
	return c.SendStatus(fiber.StatusNoContent)
}

// reevaluate re-evaluates, in the background, the projects the policy
// versions (before/after a change) were in force on.
func (h *Handler) reevaluate(versions ...Policy) {
	var ids []string
	for _, p := range versions {
		if !p.Enabled {
			continue
		}
		if p.Scope == ScopeGlobal {
			h.svc.Reevaluate(nil, true)
			return
		}
		ids = append(ids, p.ProjectIDs...)
	}
	if len(ids) > 0 {
		h.svc.Reevaluate(ids, false)
	}
}

// Preview handles POST /policies/preview: a draft (create body) evaluated
// against ?project_id= or every project the caller can see. Writes nothing.
func (h *Handler) Preview(c *fiber.Ctx) error {
	p := Draft()
	if err := httpx.Parse(c, &p); err != nil {
		return err
	}
	projects, err := h.projectParam(c)
	if err != nil {
		return err
	}
	out, err := h.svc.Preview(c.UserContext(), p, projects)
	if err != nil {
		return validationError(err)
	}
	return c.JSON(out)
}

// projectParam resolves ?project_id= against the caller's scope: the projects
// to cover (nil = all, for full access).
func (h *Handler) projectParam(c *fiber.Ctx) ([]string, error) {
	s := authz.VisibleScope(c)
	pid := c.Query("project_id")
	if pid == "" {
		return scopeProjects(s), nil
	}
	if _, err := uuid.Parse(pid); err != nil {
		return nil, fiber.NewError(fiber.StatusBadRequest, "invalid project_id")
	}
	if !s.AllAccess && !slices.Contains(s.ProjectIDs, pid) {
		return nil, fiber.NewError(fiber.StatusNotFound, "project not found")
	}
	ok, err := h.repo.ProjectExists(c.UserContext(), pid)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fiber.NewError(fiber.StatusNotFound, "project not found")
	}
	return []string{pid}, nil
}

// Evaluate handles POST /policies/evaluate (admin): re-evaluate ?project_id=,
// or every project, now.
func (h *Handler) Evaluate(c *fiber.Ctx) error {
	projects, err := h.projectParam(c)
	if err != nil {
		return err
	}
	var res Result
	if projects == nil {
		res, err = h.svc.EvaluateAll(c.UserContext())
	} else {
		res, err = h.svc.EvaluateProject(c.UserContext(), projects[0])
	}
	if err != nil {
		return err
	}
	return c.JSON(res)
}

// Violations handles GET /policies/{id}/violations: the policy's open
// violation findings on the caller's projects — default versions unless
// ?all_versions=true; ?project_id= narrows to one project.
func (h *Handler) Violations(c *fiber.Ctx) error {
	p, err := h.lookup(c)
	if err != nil {
		return err
	}
	s := authz.VisibleScope(c)
	if visible(p, s) == nil {
		return fiber.NewError(fiber.StatusNotFound, "policy not found")
	}
	filter := finding.Filter{
		Scanner: Scanner, RuleID: p.ID, OpenOnly: true,
		ProjectIDs: scopeProjects(s), AllVersions: c.QueryBool("all_versions"),
		Sort: "priority",
	}
	if pid := c.Query("project_id"); pid != "" {
		if _, err := uuid.Parse(pid); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid project_id")
		}
		filter.ProjectID = pid
	}
	page := httpx.ParsePage(c)
	filter.Limit, filter.Offset = page.Limit+1, page.Offset
	list, err := h.findings.List(c.UserContext(), filter)
	if err != nil {
		return err
	}
	hasMore := len(list) > page.Limit
	if hasMore {
		list = list[:page.Limit]
	}
	return c.JSON(fiber.Map{"findings": list, "pagination": httpx.Meta(page, len(list), hasMore)})
}

// ProjectPolicies handles GET /projects/{id}/policies: the enabled policies in
// force on a project, each with its open violations on the default version —
// with children included (projecttree.Rollup), over the project and its
// descendants.
func (h *Handler) ProjectPolicies(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	ctx := c.UserContext()
	ids, err := projecttree.Rollup(c, h.repo.db, projectID)
	if err != nil {
		return err
	}
	ps, err := h.repo.InForce(ctx, ids)
	if err != nil {
		return err
	}
	counts, err := h.repo.ViolationCounts(ctx, ids)
	if err != nil {
		return err
	}
	for i := range ps {
		ps[i].Violations = new(counts[ps[i].ID])
		if ps[i].Scope == ScopeProjects {
			// Only the rolled-up projects it covers, not the others.
			ps[i].ProjectIDs = slices.DeleteFunc(ps[i].ProjectIDs, func(id string) bool { return !slices.Contains(ids, id) })
		}
	}
	return c.JSON(fiber.Map{"policies": ps})
}

func (h *Handler) lookup(c *fiber.Ctx) (Policy, error) {
	id, err := httpx.ID(c, "policyID")
	if err != nil {
		return Policy{}, err
	}
	p, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return Policy{}, fiber.NewError(fiber.StatusNotFound, "policy not found")
	}
	return p, err
}

func (h *Handler) validate(c *fiber.Ctx, p *Policy) error {
	return validationError(h.svc.Validate(c.UserContext(), p))
}

// validationError maps a *ValidationError to 400.
func validationError(err error) error {
	if v, ok := errors.AsType[*ValidationError](err); ok {
		return fiber.NewError(fiber.StatusBadRequest, v.Error())
	}
	return err
}

func writeError(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "policy not found")
	case errors.Is(err, ErrDuplicate):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	case errors.Is(err, ErrNoProject):
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	}
	return err
}
