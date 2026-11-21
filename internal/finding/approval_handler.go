package finding

import (
	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/httpx"
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
// empty restores "any owner may decide".
func (h *Handler) SetApprovers(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var body setApproversRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	if err := h.access.SetAssessmentApproverGrants(c.UserContext(), id, body.UserIDs, body.GroupIDs); err != nil {
		return err
	}
	grants, err := h.access.ListAssessmentApproverGrants(c.UserContext(), id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"approvers": grants})
}
