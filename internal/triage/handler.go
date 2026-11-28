package triage

import (
	"context"
	"errors"
	"slices"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/httpx"
)

// Handler exposes triage-rule management + backfill. Admin-gated by the authz
// middleware (rules are instance-wide policy).
type Handler struct {
	repo *Repository
	svc  *Service
	// requireApproval (TRIAGE_RULES_REQUIRE_APPROVAL) puts every created or
	// edited rule into pending review; pending rules never apply.
	requireApproval bool
	// fields lists the custom-field definitions expressions and
	// set_custom_field are checked against (optional: nil = none defined).
	fields customFieldLister
}

// customFieldLister lists custom-field definitions (customfield.Repository).
type customFieldLister interface {
	List(ctx context.Context, entity customfield.Entity) ([]customfield.Definition, error)
}

// NewHandler constructs a triage Handler.
func NewHandler(repo *Repository, svc *Service, requireApproval bool) *Handler {
	return &Handler{repo: repo, svc: svc, requireApproval: requireApproval}
}

// WithCustomFields lets rules read finding.custom / project.custom and use
// set_custom_field.
func (h *Handler) WithCustomFields(fields customFieldLister) *Handler {
	h.fields = fields
	return h
}

// validate checks a rule against the current custom fields: its expression
// dry-runs on a document carrying every defined field, and a set_custom_field
// value must fit its (finding) field's type. The value is normalized in place.
func (h *Handler) validate(ctx context.Context, rule *Rule) error {
	var findingFields, projectFields []customfield.Definition
	if h.fields != nil {
		var err error
		if findingFields, err = h.fields.List(ctx, customfield.EntityFinding); err != nil {
			return err
		}
		if projectFields, err = h.fields.List(ctx, customfield.EntityProject); err != nil {
			return err
		}
	}
	if err := rule.Validate(FindingSchemaFor(findingFields, projectFields)); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	// A project rule's assignee must see its project; a global rule's is
	// checked per project when it fires (applySide skips the others).
	if rule.AssignUserID != nil && rule.ProjectID != nil {
		ok, err := h.repo.CanAssign(ctx, *rule.AssignUserID, *rule.ProjectID)
		if err != nil {
			return err
		}
		if !ok {
			return fiber.NewError(fiber.StatusBadRequest, "assign_user_id: not an active user who can see the project")
		}
	}
	if rule.Action != ActionSetCustomField {
		return nil
	}
	i := slices.IndexFunc(findingFields, func(d customfield.Definition) bool { return d.Key == rule.CustomField })
	if i < 0 {
		return fiber.NewError(fiber.StatusBadRequest, "set_custom_field: unknown finding custom field "+rule.CustomField)
	}
	v, err := findingFields[i].Normalize(rule.CustomValue)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "set_custom_field: "+err.Error())
	}
	if v == nil && findingFields[i].Required {
		return fiber.NewError(fiber.StatusBadRequest, "set_custom_field: a required field can't be cleared")
	}
	rule.CustomValue = v
	return nil
}

// Register mounts the routes.
func (h *Handler) Register(r fiber.Router) {
	r.Post("/triage-rules", h.Create)
	r.Get("/triage-rules", h.List)
	r.Get("/triage-rules/settings", h.GetSettings)
	r.Put("/triage-rules/settings", h.PutSettings)
	r.Post("/triage-rules/apply", h.Apply)
	r.Post("/triage-rules/preview", h.Preview)
	r.Get("/triage-rules/:ruleID", h.Get)
	r.Post("/triage-rules/:ruleID/preview", h.PreviewStored)
	r.Post("/triage-rules/:ruleID/approve", h.Approve)
	r.Post("/triage-rules/:ruleID/reject", h.Reject)
	r.Patch("/triage-rules/:ruleID", h.Update)
	r.Delete("/triage-rules/:ruleID", h.Delete)
	h.registerProject(r)
}

// Create adds a rule.
func (h *Handler) Create(c *fiber.Ctx) error {
	rule, err := parseRule(c)
	if err != nil {
		return err
	}
	return h.create(c, rule)
}

func (h *Handler) create(c *fiber.Ctx, rule Rule) error {
	if err := h.validate(c.UserContext(), &rule); err != nil {
		return err
	}
	out, err := h.repo.Create(c.UserContext(), rule, auth.UserID(c), h.requireApproval)
	if err != nil {
		return writeError(err)
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

// ruleRequest is a rule as the API takes it: only_if_unassigned defaults to
// true when omitted, so a rule never takes over an assignment unless told to.
type ruleRequest struct {
	Rule
	OnlyIfUnassigned *bool `json:"only_if_unassigned"`
}

// parseRule decodes a rule body.
func parseRule(c *fiber.Ctx) (Rule, error) {
	var req ruleRequest
	if err := httpx.Parse(c, &req); err != nil {
		return Rule{}, err
	}
	req.Rule.OnlyIfUnassigned = req.OnlyIfUnassigned == nil || *req.OnlyIfUnassigned
	return req.Rule, nil
}

// writeError maps a rule write's sentinel errors to statuses.
func writeError(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "triage rule not found")
	case errors.Is(err, ErrNoProject):
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	case errors.Is(err, ErrNoAssignee):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return err
}

// List returns all rules in evaluation order.
func (h *Handler) List(c *fiber.Ctx) error {
	rules, err := h.repo.List(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"rules": rules})
}

// Get returns one rule.
func (h *Handler) Get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "ruleID")
	if err != nil {
		return err
	}
	rule, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "triage rule not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(rule)
}

// Update replaces a rule.
func (h *Handler) Update(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "ruleID")
	if err != nil {
		return err
	}
	rule, err := parseRule(c)
	if err != nil {
		return err
	}
	rule.ID = id
	return h.update(c, rule)
}

func (h *Handler) update(c *fiber.Ctx, rule Rule) error {
	if err := h.validate(c.UserContext(), &rule); err != nil {
		return err
	}
	out, err := h.repo.Update(c.UserContext(), rule, auth.UserID(c), h.requireApproval)
	if err != nil {
		return writeError(err)
	}
	return c.JSON(out)
}

// Delete removes a rule.
func (h *Handler) Delete(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "ruleID")
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.UserContext(), id); errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "triage rule not found")
	} else if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Apply backfills rules across the existing backlog: ?project_id= for one
// project, or all projects when omitted. Returns how many findings changed.
func (h *Handler) Apply(c *fiber.Ctx) error {
	var (
		changed int
		err     error
	)
	if pid := c.Query("project_id"); pid != "" {
		changed, err = h.svc.ApplyToProject(c.UserContext(), pid)
	} else {
		changed, err = h.svc.ApplyAll(c.UserContext())
	}
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"applied": changed})
}

// Preview dry-runs an unsaved rule (same body as create): which findings it
// would change, and how. ?project_id= narrows the scope. Mutates nothing.
func (h *Handler) Preview(c *fiber.Ctx) error {
	var rule Rule
	if err := httpx.Parse(c, &rule); err != nil {
		return err
	}
	if rule.Name == "" {
		rule.Name = "preview" // a draft needn't be named yet
	}
	if err := h.validate(c.UserContext(), &rule); err != nil {
		return err
	}
	return h.preview(c, rule)
}

// PreviewStored dry-runs a stored rule — whatever its enabled/approval state.
func (h *Handler) PreviewStored(c *fiber.Ctx) error {
	rule, err := h.lookup(c)
	if err != nil {
		return err
	}
	return h.preview(c, rule)
}

func (h *Handler) preview(c *fiber.Ctx, rule Rule) error {
	out, err := h.svc.Preview(c.UserContext(), rule, c.Query("project_id"))
	if errors.Is(err, ErrNoProject) {
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// Approve approves a pending rule. Four-eyes: its author/last editor can't.
func (h *Handler) Approve(c *fiber.Ctx) error {
	return h.review(c, h.repo.Approve)
}

// Reject rejects a pending rule; the row is kept (never applies) for audit.
func (h *Handler) Reject(c *fiber.Ctx) error {
	return h.review(c, h.repo.Reject)
}

func (h *Handler) review(c *fiber.Ctx, do func(ctx context.Context, id, actor string) (Rule, error)) error {
	id, err := httpx.ID(c, "ruleID")
	if err != nil {
		return err
	}
	actor := auth.UserID(c)
	if actor == "" {
		return fiber.NewError(fiber.StatusUnauthorized, "reviewing a rule requires a user identity")
	}
	out, err := do(c.UserContext(), id, actor)
	switch {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "triage rule not found")
	case errors.Is(err, ErrSelfApproval):
		return fiber.NewError(fiber.StatusForbidden, err.Error())
	case errors.Is(err, ErrNotPending):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	case err != nil:
		return err
	}
	return c.JSON(out)
}

func (h *Handler) lookup(c *fiber.Ctx) (Rule, error) {
	id, err := httpx.ID(c, "ruleID")
	if err != nil {
		return Rule{}, err
	}
	rule, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return Rule{}, fiber.NewError(fiber.StatusNotFound, "triage rule not found")
	}
	return rule, err
}
