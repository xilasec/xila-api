package team

import (
	"context"
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/httpx"
)

// memberAdder adds the creator of a team as its owner.
type memberAdder interface {
	Add(ctx context.Context, teamID, userID string, role domain.TeamRole, customRoleID string) error
}

// Handler exposes team CRUD over HTTP.
type Handler struct {
	repo    *Repository
	members memberAdder
}

// NewHandler constructs a team Handler.
func NewHandler(repo *Repository, members memberAdder) *Handler {
	return &Handler{repo: repo, members: members}
}

// Register mounts team routes on the given router.
func (h *Handler) Register(r fiber.Router) {
	r.Post("/orgs/:orgID/teams", h.Create)
	r.Get("/teams", h.List)
	r.Get("/teams/:teamID", h.Get)
	r.Patch("/teams/:teamID", h.Update)
	r.Delete("/teams/:teamID", h.Delete)
}

type createRequest struct {
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type updateRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

func (h *Handler) Create(c *fiber.Ctx) error {
	orgID, err := httpx.ID(c, "orgID")
	if err != nil {
		return err
	}
	var body createRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	body.Slug = strings.TrimSpace(body.Slug)
	body.Name = strings.TrimSpace(body.Name)
	if body.Slug == "" || body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "slug and name are required")
	}

	t, err := h.repo.Create(c.UserContext(), orgID, body.Slug, body.Name, body.Description)
	switch {
	case errors.Is(err, ErrDuplicate):
		return fiber.NewError(fiber.StatusConflict, "team slug already exists")
	case errors.Is(err, ErrNoOrg):
		return fiber.NewError(fiber.StatusNotFound, "organization not found")
	case err != nil:
		return err
	}
	// The creator becomes the team's owner.
	if actor := auth.CurrentActor(c); actor.UserID != "" {
		if err := h.members.Add(c.UserContext(), t.ID, actor.UserID, domain.TeamOwner, ""); err != nil {
			return err
		}
	}
	return c.Status(fiber.StatusCreated).JSON(t)
}

func (h *Handler) List(c *fiber.Ctx) error {
	scope := authz.VisibleScope(c)
	if scope.AllAccess {
		teams, err := h.repo.List(c.UserContext())
		if err != nil {
			return err
		}
		return c.JSON(fiber.Map{"teams": teams})
	}
	teams, err := h.repo.ListByIDs(c.UserContext(), scope.TeamIDs)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"teams": teams})
}

func (h *Handler) Get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "teamID")
	if err != nil {
		return err
	}
	t, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "team not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(t)
}

func (h *Handler) Update(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "teamID")
	if err != nil {
		return err
	}
	var body updateRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	t, err := h.repo.Update(c.UserContext(), id, body.Name, body.Description)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "team not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(t)
}

func (h *Handler) Delete(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "teamID")
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.UserContext(), id); errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "team not found")
	} else if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
