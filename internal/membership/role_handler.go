package membership

import (
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/httpx"
)

// ListCustomRoles handles GET /orgs/{orgID}/custom-roles.
func (h *Handler) ListCustomRoles(c *fiber.Ctx) error {
	orgID, err := httpx.ID(c, "orgID")
	if err != nil {
		return err
	}
	roles, err := h.repo.ListCustomRoles(c.UserContext(), orgID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"custom_roles": roles})
}

type customRoleRequest struct {
	Name               string              `json:"name"`
	BaseRole           domain.TeamRole     `json:"base_role"`
	DeniedCapabilities []domain.Capability `json:"denied_capabilities"`
}

func (b customRoleRequest) validate() error {
	if strings.TrimSpace(b.Name) == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}
	if !b.BaseRole.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "invalid base_role")
	}
	if !domain.ValidCapabilities(b.DeniedCapabilities) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid denied_capabilities")
	}
	return nil
}

// CreateCustomRole handles POST /orgs/{orgID}/custom-roles.
func (h *Handler) CreateCustomRole(c *fiber.Ctx) error {
	orgID, err := httpx.ID(c, "orgID")
	if err != nil {
		return err
	}
	var body customRoleRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	if err := body.validate(); err != nil {
		return err
	}
	role, err := h.repo.CreateCustomRole(c.UserContext(), orgID, strings.TrimSpace(body.Name), body.BaseRole, body.DeniedCapabilities)
	if errors.Is(err, ErrRoleDuplicate) {
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	if errors.Is(err, ErrNoUser) {
		return fiber.NewError(fiber.StatusNotFound, "organization not found")
	}
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(role)
}

// UpdateCustomRole handles PUT /orgs/{orgID}/custom-roles/{roleID}.
func (h *Handler) UpdateCustomRole(c *fiber.Ctx) error {
	roleID, err := httpx.ID(c, "roleID")
	if err != nil {
		return err
	}
	var body customRoleRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	if err := body.validate(); err != nil {
		return err
	}
	role, err := h.repo.UpdateCustomRole(c.UserContext(), roleID, strings.TrimSpace(body.Name), body.BaseRole, body.DeniedCapabilities)
	if errors.Is(err, ErrRoleNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "custom role not found")
	}
	if errors.Is(err, ErrRoleDuplicate) {
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	if err != nil {
		return err
	}
	return c.JSON(role)
}

// DeleteCustomRole handles DELETE /orgs/{orgID}/custom-roles/{roleID}.
func (h *Handler) DeleteCustomRole(c *fiber.Ctx) error {
	roleID, err := httpx.ID(c, "roleID")
	if err != nil {
		return err
	}
	if err := h.repo.DeleteCustomRole(c.UserContext(), roleID); err != nil {
		if errors.Is(err, ErrRoleNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "custom role not found")
		}
		if errors.Is(err, ErrRoleInUse) {
			return fiber.NewError(fiber.StatusConflict, err.Error())
		}
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ListCapabilities handles GET /capabilities: the fixed reference list of
// capabilities a custom role may deny, for the role editor's checkbox list.
func (h *Handler) ListCapabilities(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"capabilities": domain.Capabilities})
}
