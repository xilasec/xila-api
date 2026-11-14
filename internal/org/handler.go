package org

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/user"
)

// Handler exposes organization CRUD + membership over HTTP.
type Handler struct {
	repo  *Repository
	users *user.Repository
}

// NewHandler constructs an org Handler.
func NewHandler(repo *Repository, users *user.Repository) *Handler {
	return &Handler{repo: repo, users: users}
}

// Register mounts org routes. Access is enforced by the authz middleware:
// create is open (creator becomes admin); read needs org membership; member
// management + update need org admin.
func (h *Handler) Register(r fiber.Router) {
	r.Post("/orgs", h.Create)
	r.Get("/orgs", h.List)
	r.Get("/orgs/:orgID", h.Get)
	r.Get("/orgs/:orgID/members", h.ListMembers)
	r.Post("/orgs/:orgID/members", h.AddMember)
	r.Delete("/orgs/:orgID/members/:userID", h.RemoveMember)
}

type createRequest struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

// Create makes an organization; the creator becomes its admin.
func (h *Handler) Create(c *fiber.Ctx) error {
	var body createRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	body.Slug = strings.TrimSpace(body.Slug)
	body.Name = strings.TrimSpace(body.Name)
	if body.Slug == "" || body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "slug and name are required")
	}
	o, err := h.repo.Create(c.UserContext(), body.Slug, body.Name)
	if errors.Is(err, ErrDuplicate) {
		return fiber.NewError(fiber.StatusConflict, "organization slug already exists")
	}
	if err != nil {
		return err
	}
	if actor := auth.CurrentActor(c); actor.UserID != "" {
		if err := h.repo.AddMember(c.UserContext(), o.ID, actor.UserID, domain.OrgAdmin); err != nil {
			return err
		}
	}
	return c.Status(fiber.StatusCreated).JSON(o)
}

// List returns the orgs the actor can see.
func (h *Handler) List(c *fiber.Ctx) error {
	scope := authz.VisibleScope(c)
	if scope.AllAccess {
		orgs, err := h.repo.List(c.UserContext())
		if err != nil {
			return err
		}
		return c.JSON(fiber.Map{"organizations": orgs})
	}
	orgs, err := h.repo.ListByIDs(c.UserContext(), scope.OrgIDs)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"organizations": orgs})
}

// Get returns one org.
func (h *Handler) Get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "orgID")
	if err != nil {
		return err
	}
	o, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "organization not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(o)
}

// ListMembers returns an org's members.
func (h *Handler) ListMembers(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "orgID")
	if err != nil {
		return err
	}
	members, err := h.repo.ListMembers(c.UserContext(), id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"members": members})
}

type addMemberRequest struct {
	Email string         `json:"email"`
	Role  domain.OrgRole `json:"role"`
}

// AddMember adds a user (by email) to the org with a role.
func (h *Handler) AddMember(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "orgID")
	if err != nil {
		return err
	}
	var body addMemberRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	body.Email = strings.TrimSpace(strings.ToLower(body.Email))
	if !body.Role.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "invalid role")
	}
	u, err := h.users.GetByEmail(c.UserContext(), body.Email)
	if errors.Is(err, user.ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "no user with that email")
	}
	if err != nil {
		return err
	}
	if err := h.repo.AddMember(c.UserContext(), id, u.ID, body.Role); err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(Member{UserID: u.ID, Email: u.Email, Role: body.Role})
}

// RemoveMember drops a member from the org.
func (h *Handler) RemoveMember(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "orgID")
	if err != nil {
		return err
	}
	userID, err := httpx.ID(c, "userID")
	if err != nil {
		return err
	}
	switch err := h.repo.RemoveMember(c.UserContext(), id, userID); {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "member not found")
	case errors.Is(err, ErrLastAdmin):
		return fiber.NewError(fiber.StatusBadRequest, "cannot remove the last admin")
	case err != nil:
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
