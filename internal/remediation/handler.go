package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/fixplan"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/issuetracker"
	"github.com/xilasec/xila-api/internal/secretbox"
)

// access answers whether a user may own a project's action (implemented by
// *membership.Repository).
type access interface {
	AdminStatus(ctx context.Context, userID string) (isAdmin, isOwner bool, err error)
	RoleOnProject(ctx context.Context, userID, projectID string) (domain.TeamRole, bool, error)
}

// lister lists actions (implemented by *Repository).
type lister interface {
	List(ctx context.Context, f Filter, limit, offset int) ([]Action, error)
	Get(ctx context.Context, id string) (Action, error)
	Findings(ctx context.Context, actionID string) ([]ActionFinding, error)
}

// Handler serves remediation actions.
type Handler struct {
	repo   lister
	svc    *Service
	access access
}

// NewHandler constructs the handler.
func NewHandler(repo lister, svc *Service, access access) *Handler {
	return &Handler{repo: repo, svc: svc, access: access}
}

// Register mounts the routes. authz gates them: project routes and
// /remediation/{id}… need project viewer to read and editor to change;
// GET /remediation is the portfolio list, scoped to the caller's visible
// projects; POST /remediation/sweep is instance-admin.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/projects/:projectID/remediation", h.projectList)
	r.Get("/projects/:projectID/remediation/proposals", h.proposals)
	r.Post("/projects/:projectID/remediation", h.accept)
	r.Get("/remediation", h.portfolio)
	r.Post("/remediation/sweep", h.sweep)
	r.Get("/remediation/:actionID", h.get)
	r.Patch("/remediation/:actionID", h.update)
	r.Get("/remediation/:actionID/findings", h.findings)
	r.Post("/remediation/:actionID/issue", h.createIssue)
}

func mapErr(err error) error {
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrNoProposal):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	case errors.Is(err, ErrConflict):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	case errors.Is(err, issuetracker.ErrNoTracker), errors.Is(err, secretbox.ErrNoKey):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return err
}

// filter reads ?status= (comma-separated, or "all"; default open,in_progress)
// and ?kind=.
func filter(c *fiber.Ctx) (Filter, error) {
	var f Filter
	switch st := c.Query("status"); st {
	case "":
		f.Statuses = []Status{StatusOpen, StatusInProgress}
	case "all":
	default:
		for s := range strings.SplitSeq(st, ",") {
			s := Status(strings.TrimSpace(s))
			if !s.Valid() {
				return f, fiber.NewError(fiber.StatusBadRequest, "status must be open, in_progress, done, wont_do or all")
			}
			f.Statuses = append(f.Statuses, s)
		}
	}
	if k := fixplan.Kind(c.Query("kind")); k != "" {
		if !k.Valid() {
			return f, fiber.NewError(fiber.StatusBadRequest, "kind must be package_upgrade, base_image, iac_rule, code_location or config")
		}
		f.Kind = k
	}
	return f, nil
}

func (h *Handler) respondList(c *fiber.Ctx, f Filter) error {
	page := httpx.ParsePage(c)
	items, err := h.repo.List(c.UserContext(), f, page.Limit+1, page.Offset)
	if err != nil {
		return err
	}
	hasMore := len(items) > page.Limit
	if hasMore {
		items = items[:page.Limit]
	}
	return c.JSON(fiber.Map{"actions": items, "pagination": httpx.Meta(page, len(items), hasMore)})
}

func (h *Handler) projectList(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	f, err := filter(c)
	if err != nil {
		return err
	}
	f.ProjectIDs = []string{pid}
	return h.respondList(c, f)
}

func (h *Handler) portfolio(c *fiber.Ctx) error {
	f, err := filter(c)
	if err != nil {
		return err
	}
	if s := authz.VisibleScope(c); !s.AllAccess {
		f.ProjectIDs = s.ProjectIDs
		if f.ProjectIDs == nil {
			f.ProjectIDs = []string{}
		}
	}
	return h.respondList(c, f)
}

func (h *Handler) proposals(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	ps, err := h.svc.Proposals(c.UserContext(), pid)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"proposals": ps})
}

type acceptRequest struct {
	Kind fixplan.Kind `json:"kind"`
	Key  string       `json:"key"`
}

// accept creates the action for a proposal: 201 when created, 200 when the
// change already had a live action (the findings joined it).
func (h *Handler) accept(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var body acceptRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	if !body.Kind.Valid() || body.Key == "" {
		return fiber.NewError(fiber.StatusBadRequest, "kind and key of a proposal are required")
	}
	a, created, err := h.svc.Accept(c.UserContext(), pid, body.Kind, body.Key, auth.UserID(c))
	if err != nil {
		return mapErr(err)
	}
	if created {
		return c.Status(fiber.StatusCreated).JSON(a)
	}
	return c.JSON(a)
}

func (h *Handler) get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "actionID")
	if err != nil {
		return err
	}
	a, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		return mapErr(err)
	}
	return c.JSON(a)
}

func (h *Handler) findings(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "actionID")
	if err != nil {
		return err
	}
	fs, err := h.repo.Findings(c.UserContext(), id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"findings": fs})
}

// updateRequest: owner_id present (a user id, or null for nobody) sets the
// owner by hand; auto_owner hands it back to the findings' assignees.
type updateRequest struct {
	Status    *Status         `json:"status"`
	Title     *string         `json:"title"`
	OwnerID   json.RawMessage `json:"owner_id"`
	AutoOwner bool            `json:"auto_owner"`
}

func (h *Handler) update(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "actionID")
	if err != nil {
		return err
	}
	var body updateRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	cur, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		return mapErr(err)
	}
	p := Patch{Status: body.Status, AutoOwner: body.AutoOwner}
	if body.Status != nil && !body.Status.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "status must be open, in_progress, done or wont_do")
	}
	if body.Title != nil {
		t := strings.TrimSpace(*body.Title)
		if t == "" || len(t) > 500 {
			return fiber.NewError(fiber.StatusBadRequest, "title must be 1-500 characters")
		}
		p.Title = &t
	}
	if len(body.OwnerID) > 0 {
		if body.AutoOwner {
			return fiber.NewError(fiber.StatusBadRequest, "owner_id and auto_owner are exclusive")
		}
		p.SetOwner = true
		if string(body.OwnerID) != "null" {
			var owner string
			if err := json.Unmarshal(body.OwnerID, &owner); err != nil || uuid.Validate(owner) != nil {
				return fiber.NewError(fiber.StatusBadRequest, "owner_id must be a user id or null")
			}
			if err := h.ownable(c, owner, cur.ProjectID); err != nil {
				return err
			}
			p.OwnerID = &owner
		}
	}
	a, err := h.svc.Update(c.UserContext(), id, p, auth.UserID(c))
	if err != nil {
		return mapErr(err)
	}
	return c.JSON(a)
}

// ownable checks the owner can see the project (an instance admin always can).
func (h *Handler) ownable(c *fiber.Ctx, userID, projectID string) error {
	isAdmin, _, err := h.access.AdminStatus(c.UserContext(), userID)
	if err != nil {
		return err
	}
	if isAdmin {
		return nil
	}
	if _, ok, err := h.access.RoleOnProject(c.UserContext(), userID, projectID); err != nil {
		return err
	} else if !ok {
		return fiber.NewError(fiber.StatusBadRequest, "the owner has no access to this project")
	}
	return nil
}

// createIssue files the action's ticket: 201 when created, 200 with the
// existing link when it already has one.
func (h *Handler) createIssue(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "actionID")
	if err != nil {
		return err
	}
	l, created, err := h.svc.CreateIssue(c.UserContext(), id)
	if err != nil {
		if mapped := mapErr(err); mapped != err { //nolint:errorlint // identity check: did mapErr translate this error
			return mapped
		}
		if r, ok := errors.AsType[issuetracker.RemoteError](err); ok {
			msg := err.Error()
			if !authz.VisibleScope(c).AllAccess {
				msg = r.Public()
			}
			return fiber.NewError(fiber.StatusBadGateway, "create issue failed: "+msg)
		}
		return err
	}
	if created {
		return c.Status(fiber.StatusCreated).JSON(l)
	}
	return c.JSON(l)
}

func (h *Handler) sweep(c *fiber.Ctx) error {
	res, err := h.svc.Sweep(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(res)
}
