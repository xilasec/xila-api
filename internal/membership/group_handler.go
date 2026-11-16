package membership

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/user"
)

// ListGroups handles GET /orgs/{orgID}/groups.
func (h *Handler) ListGroups(c *fiber.Ctx) error {
	orgID, err := httpx.ID(c, "orgID")
	if err != nil {
		return err
	}
	groups, err := h.repo.ListGroups(c.UserContext(), orgID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"groups": groups})
}

type groupRequest struct {
	Name string `json:"name"`
}

// CreateGroup handles POST /orgs/{orgID}/groups.
func (h *Handler) CreateGroup(c *fiber.Ctx) error {
	orgID, err := httpx.ID(c, "orgID")
	if err != nil {
		return err
	}
	var body groupRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}
	g, err := h.repo.CreateGroup(c.UserContext(), orgID, body.Name, "")
	if errors.Is(err, ErrGroupDuplicate) {
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	if errors.Is(err, ErrNoUser) {
		return fiber.NewError(fiber.StatusNotFound, "organization not found")
	}
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(g)
}

// GetGroup handles GET /orgs/{orgID}/groups/{groupID}: the group with its members.
func (h *Handler) GetGroup(c *fiber.Ctx) error {
	groupID, err := httpx.ID(c, "groupID")
	if err != nil {
		return err
	}
	g, err := h.repo.GetGroup(c.UserContext(), groupID)
	if errors.Is(err, ErrGroupNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "group not found")
	}
	if err != nil {
		return err
	}
	members, err := h.repo.ListGroupMembers(c.UserContext(), groupID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"group": g, "members": members})
}

// RenameGroup handles PUT /orgs/{orgID}/groups/{groupID}.
func (h *Handler) RenameGroup(c *fiber.Ctx) error {
	groupID, err := httpx.ID(c, "groupID")
	if err != nil {
		return err
	}
	var body groupRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}
	g, err := h.repo.RenameGroup(c.UserContext(), groupID, body.Name)
	if errors.Is(err, ErrGroupNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "group not found")
	}
	if errors.Is(err, ErrGroupDuplicate) {
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	if err != nil {
		return err
	}
	return c.JSON(g)
}

// DeleteGroup handles DELETE /orgs/{orgID}/groups/{groupID}.
func (h *Handler) DeleteGroup(c *fiber.Ctx) error {
	groupID, err := httpx.ID(c, "groupID")
	if err != nil {
		return err
	}
	if err := h.repo.DeleteGroup(c.UserContext(), groupID); err != nil {
		if errors.Is(err, ErrGroupNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "group not found")
		}
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

type groupMemberRequest struct {
	Email string `json:"email"`
}

// AddGroupMember handles POST /orgs/{orgID}/groups/{groupID}/members.
func (h *Handler) AddGroupMember(c *fiber.Ctx) error {
	groupID, err := httpx.ID(c, "groupID")
	if err != nil {
		return err
	}
	var body groupMemberRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	body.Email = strings.TrimSpace(strings.ToLower(body.Email))
	if body.Email == "" {
		return fiber.NewError(fiber.StatusBadRequest, "email is required")
	}
	u, err := h.users.GetByEmail(c.UserContext(), body.Email)
	if errors.Is(err, user.ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "no user with that email")
	}
	if err != nil {
		return err
	}
	if err := h.repo.AddGroupMember(c.UserContext(), groupID, u.ID); err != nil {
		if errors.Is(err, ErrNoUser) {
			return fiber.NewError(fiber.StatusNotFound, "group not found")
		}
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(GroupMember{UserID: u.ID, Email: u.Email})
}

// RemoveGroupMember handles DELETE /orgs/{orgID}/groups/{groupID}/members/{userID}.
func (h *Handler) RemoveGroupMember(c *fiber.Ctx) error {
	groupID, err := httpx.ID(c, "groupID")
	if err != nil {
		return err
	}
	userID, err := httpx.ID(c, "userID")
	if err != nil {
		return err
	}
	if err := h.repo.RemoveGroupMember(c.UserContext(), groupID, userID); err != nil {
		if errors.Is(err, ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "user is not a member of this group")
		}
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
