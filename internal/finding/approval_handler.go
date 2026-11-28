package finding

import (
	"errors"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/audit"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/membership"
)

// ListApprovers handles GET /projects/{id}/assessment-approvers: the
// project's designated assessment approvers (empty = any owner may decide).
func (h *Handler) ListApprovers(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	grants, err := h.access.ListAssessmentApproverGrants(c.UserContext(), id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"approvers": grants})
}

type setApproversRequest struct {
	UserIDs  []string `json:"user_ids"`
	GroupIDs []string `json:"group_ids"`
}

// SetApprovers handles PUT /projects/{id}/assessment-approvers: replaces the
// project's designated approvers with exactly these users and groups. Both
// empty restores "any owner may decide". A user without access to the
// project, or a group of another organization, is refused (400).
func (h *Handler) SetApprovers(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var body setApproversRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	for _, v := range append(append([]string{}, body.UserIDs...), body.GroupIDs...) {
		if uuid.Validate(v) != nil {
			return fiber.NewError(fiber.StatusBadRequest, "approver ids must be UUIDs")
		}
	}
	before, err := h.access.ListAssessmentApproverGrants(c.UserContext(), id)
	if err != nil {
		return err
	}
	if err := h.access.SetAssessmentApproverGrants(c.UserContext(), id, body.UserIDs, body.GroupIDs); err != nil {
		if bad, ok := errors.AsType[*membership.InvalidApproversError](err); ok {
			return fiber.NewError(fiber.StatusBadRequest, bad.Error())
		}
		return err
	}
	after, err := h.access.ListAssessmentApproverGrants(c.UserContext(), id)
	if err != nil {
		return err
	}
	audit.SetChanges(c, fiber.Map{"approvers": before}, fiber.Map{"approvers": after})
	return c.JSON(fiber.Map{"approvers": after})
}
