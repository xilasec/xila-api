package membership

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/user"
)

// Handler exposes team-member management. All routes are owner-gated by authz.
type Handler struct {
	repo  *Repository
	users *user.Repository
}

// NewHandler constructs a membership Handler.
func NewHandler(repo *Repository, users *user.Repository) *Handler {
	return &Handler{repo: repo, users: users}
}

// Register mounts member routes. Team routes are owner-gated by authz; so are the
// project ones — granting access to a project is an owner-level act.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/teams/:teamID/members", h.List)
	r.Post("/teams/:teamID/members", h.Add)
	r.Delete("/teams/:teamID/members/:userID", h.Remove)

	r.Get("/projects/:projectID/members", h.ListProject)
	r.Post("/projects/:projectID/members", h.AddProject)
	r.Delete("/projects/:projectID/members/:userID", h.RemoveProject)
	r.Get("/projects/:projectID/assignees", h.ListAssignees)
}

// ListProject returns a project's *direct* members — the grants made on this
// project, not everyone who can reach it through its team. Those are different
// questions, and conflating them would make it impossible to see what a
// "remove" would actually revoke.
func (h *Handler) ListProject(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	members, err := h.repo.ListProjectMembers(c.UserContext(), projectID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"members": members})
}

// ListAssignees returns everyone who can see a project — through a direct grant,
// its team, its organization, or as an instance admin — i.e. who a finding in
// it may be assigned to, with their effective role.
func (h *Handler) ListAssignees(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	users, err := h.repo.UsersWithProjectAccess(c.UserContext(), projectID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"assignees": users})
}

// AddProject grants a user a role on one project, without adding them to its team.
func (h *Handler) AddProject(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var body addRequest
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
	if err := h.repo.AddToProject(c.UserContext(), projectID, u.ID, body.Role); err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(Member{UserID: u.ID, Email: u.Email, Role: body.Role})
}

// RemoveProject revokes a direct project grant. It does not touch team access —
// if the user still reaches the project through its team, they still can, and the
// response says so rather than pretending the access is gone.
func (h *Handler) RemoveProject(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	userID, err := httpx.ID(c, "userID")
	if err != nil {
		return err
	}
	if err := h.repo.RemoveFromProject(c.UserContext(), projectID, userID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "no direct grant for that user on this project")
		}
		return err
	}

	// Be honest about what was actually revoked.
	if role, stillHas, err := h.repo.RoleOnProject(c.UserContext(), userID, projectID); err == nil && stillHas {
		return c.JSON(fiber.Map{
			"removed":          true,
			"still_has_access": true,
			"effective_role":   role,
			"message":          "the direct grant was removed, but this user still reaches the project through its team or organization",
		})
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// List returns a team's members.
func (h *Handler) List(c *fiber.Ctx) error {
	teamID, err := httpx.ID(c, "teamID")
	if err != nil {
		return err
	}
	members, err := h.repo.List(c.UserContext(), teamID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"members": members})
}

type addRequest struct {
	Email string          `json:"email"`
	Role  domain.TeamRole `json:"role"`
}

// Add invites a user (by email) to the team with a role.
func (h *Handler) Add(c *fiber.Ctx) error {
	teamID, err := httpx.ID(c, "teamID")
	if err != nil {
		return err
	}
	var body addRequest
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
	if err := h.repo.Add(c.UserContext(), teamID, u.ID, body.Role); err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(Member{UserID: u.ID, Email: u.Email, Role: body.Role})
}

// Remove drops a member from the team.
func (h *Handler) Remove(c *fiber.Ctx) error {
	teamID, err := httpx.ID(c, "teamID")
	if err != nil {
		return err
	}
	userID, err := httpx.ID(c, "userID")
	if err != nil {
		return err
	}
	switch err := h.repo.Remove(c.UserContext(), teamID, userID); {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "member not found")
	case errors.Is(err, ErrLastOwner):
		return fiber.NewError(fiber.StatusBadRequest, "cannot remove the last owner")
	case err != nil:
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
