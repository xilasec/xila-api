package membership

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/user"
)

// Handler exposes team/project/org-member, user-group and custom-role
// management over HTTP. Member routes are owner-gated by authz; group and
// custom-role routes are org-admin-gated (see authz.parseScope).
type Handler struct {
	repo  *Repository
	users *user.Repository
}

// NewHandler constructs a membership Handler.
func NewHandler(repo *Repository, users *user.Repository) *Handler {
	return &Handler{repo: repo, users: users}
}

// Register mounts member, group and custom-role routes. Team/project member
// routes are owner-gated by authz; so are groups and custom roles, at the org
// admin level — granting access, defining a group or narrowing a role are all
// acts that change who can do what.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/teams/:teamID/members", h.List)
	r.Post("/teams/:teamID/members", h.Add)
	r.Delete("/teams/:teamID/members/:userID", h.Remove)
	r.Delete("/teams/:teamID/groups/:groupID", h.RemoveTeamGroup)

	r.Get("/projects/:projectID/members", h.ListProject)
	r.Post("/projects/:projectID/members", h.AddProject)
	r.Delete("/projects/:projectID/members/:userID", h.RemoveProject)
	r.Delete("/projects/:projectID/groups/:groupID", h.RemoveProjectGroup)
	r.Get("/projects/:projectID/assignees", h.ListAssignees)

	r.Get("/orgs/:orgID/groups", h.ListGroups)
	r.Post("/orgs/:orgID/groups", h.CreateGroup)
	r.Get("/orgs/:orgID/groups/:groupID", h.GetGroup)
	r.Put("/orgs/:orgID/groups/:groupID", h.RenameGroup)
	r.Delete("/orgs/:orgID/groups/:groupID", h.DeleteGroup)
	r.Post("/orgs/:orgID/groups/:groupID/members", h.AddGroupMember)
	r.Delete("/orgs/:orgID/groups/:groupID/members/:userID", h.RemoveGroupMember)

	r.Get("/orgs/:orgID/custom-roles", h.ListCustomRoles)
	r.Post("/orgs/:orgID/custom-roles", h.CreateCustomRole)
	r.Put("/orgs/:orgID/custom-roles/:roleID", h.UpdateCustomRole)
	r.Delete("/orgs/:orgID/custom-roles/:roleID", h.DeleteCustomRole)

	r.Get("/capabilities", h.ListCapabilities)
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

// grantRequest grants either a user (by email) or a user group (by id) a role,
// optionally narrowed by a custom role (team/project grants only).
type grantRequest struct {
	Email        string          `json:"email"`
	GroupID      string          `json:"group_id"`
	Role         domain.TeamRole `json:"role"`
	CustomRoleID string          `json:"custom_role_id"`
}

func (b grantRequest) validate() error {
	if (b.Email == "") == (b.GroupID == "") {
		return fiber.NewError(fiber.StatusBadRequest, "exactly one of email or group_id is required")
	}
	if !b.Role.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "invalid role")
	}
	return nil
}

// AddProject grants a user or group a role on one project, without adding
// them to its team.
func (h *Handler) AddProject(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var body grantRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	if err := body.validate(); err != nil {
		return err
	}
	if body.GroupID != "" {
		if err := h.repo.AddProjectGroup(c.UserContext(), projectID, body.GroupID, body.Role, body.CustomRoleID); err != nil {
			return mapGrantError(err)
		}
		g, err := h.repo.GetGroup(c.UserContext(), body.GroupID)
		if err != nil {
			return err
		}
		return c.Status(fiber.StatusCreated).JSON(Member{GroupID: g.ID, GroupName: g.Name, Role: body.Role, CustomRoleID: body.CustomRoleID})
	}
	body.Email = strings.TrimSpace(strings.ToLower(body.Email))
	u, err := h.users.GetByEmail(c.UserContext(), body.Email)
	if errors.Is(err, user.ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "no user with that email")
	}
	if err != nil {
		return err
	}
	if err := h.repo.AddToProject(c.UserContext(), projectID, u.ID, body.Role, body.CustomRoleID); err != nil {
		return mapGrantError(err)
	}
	return c.Status(fiber.StatusCreated).JSON(Member{UserID: u.ID, Email: u.Email, Role: body.Role, CustomRoleID: body.CustomRoleID})
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

// RemoveProjectGroup revokes a group's direct project grant.
func (h *Handler) RemoveProjectGroup(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	groupID, err := httpx.ID(c, "groupID")
	if err != nil {
		return err
	}
	if err := h.repo.RemoveProjectGroup(c.UserContext(), projectID, groupID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "no direct grant for that group on this project")
		}
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// List returns a team's members (users and groups).
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

// Add invites a user (by email) or grants a group a role on the team.
func (h *Handler) Add(c *fiber.Ctx) error {
	teamID, err := httpx.ID(c, "teamID")
	if err != nil {
		return err
	}
	var body grantRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	if err := body.validate(); err != nil {
		return err
	}
	if body.GroupID != "" {
		if err := h.repo.AddGroup(c.UserContext(), teamID, body.GroupID, body.Role, body.CustomRoleID); err != nil {
			return mapGrantError(err)
		}
		g, err := h.repo.GetGroup(c.UserContext(), body.GroupID)
		if err != nil {
			return err
		}
		return c.Status(fiber.StatusCreated).JSON(Member{GroupID: g.ID, GroupName: g.Name, Role: body.Role, CustomRoleID: body.CustomRoleID})
	}
	body.Email = strings.TrimSpace(strings.ToLower(body.Email))
	u, err := h.users.GetByEmail(c.UserContext(), body.Email)
	if errors.Is(err, user.ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "no user with that email")
	}
	if err != nil {
		return err
	}
	if err := h.repo.Add(c.UserContext(), teamID, u.ID, body.Role, body.CustomRoleID); err != nil {
		return mapGrantError(err)
	}
	return c.Status(fiber.StatusCreated).JSON(Member{UserID: u.ID, Email: u.Email, Role: body.Role, CustomRoleID: body.CustomRoleID})
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

// RemoveTeamGroup drops a group from the team.
func (h *Handler) RemoveTeamGroup(c *fiber.Ctx) error {
	teamID, err := httpx.ID(c, "teamID")
	if err != nil {
		return err
	}
	groupID, err := httpx.ID(c, "groupID")
	if err != nil {
		return err
	}
	switch err := h.repo.RemoveGroup(c.UserContext(), teamID, groupID); {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "group not a member of this team")
	case errors.Is(err, ErrLastOwner):
		return fiber.NewError(fiber.StatusBadRequest, "cannot remove the last owner")
	case err != nil:
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func mapGrantError(err error) error {
	if errors.Is(err, ErrNoUser) {
		return fiber.NewError(fiber.StatusNotFound, "no such user, group, team or project")
	}
	return err
}
