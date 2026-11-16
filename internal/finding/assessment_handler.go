package finding

import (
	"errors"
	"log/slog"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/httpx"
)

// markDecidable sets CanDecide on each pending assessment the caller may
// approve or reject: an owner of its project (or instance admin) who isn't
// the requester.
func (h *Handler) markDecidable(c *fiber.Ctx, as []Assessment) error {
	uid := auth.UserID(c)
	owner := map[string]bool{}
	for i := range as {
		a := &as[i]
		if a.State != AssessmentPending || (a.RequestedBy != nil && *a.RequestedBy == uid) {
			continue
		}
		ok, seen := owner[a.ProjectID]
		if !seen {
			var err error
			if ok, err = h.can(c, uid, a.ProjectID, domain.TeamOwner); err != nil {
				return err
			}
			owner[a.ProjectID] = ok
		}
		a.CanDecide = ok
	}
	return nil
}

// ListAssessments handles GET /assessments?state=pending — the review queue
// across every project the caller can see (?project_id= narrows it).
// ?actionable=true keeps only what the caller may decide: pending
// assessments of projects they own that someone else requested.
func (h *Handler) ListAssessments(c *fiber.Ctx) error {
	filter := AssessmentFilter{State: AssessmentState(c.Query("state")), ProjectID: c.Query("project_id")}
	if filter.State != "" && !filter.State.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "state must be pending, approved or rejected")
	}
	if filter.ProjectID != "" && uuid.Validate(filter.ProjectID) != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid project_id")
	}
	if scope := authz.VisibleScope(c); !scope.AllAccess {
		filter.ProjectIDs = scope.ProjectIDs
		if filter.ProjectIDs == nil {
			filter.ProjectIDs = []string{}
		}
	}
	if c.QueryBool("actionable") {
		uid := auth.UserID(c)
		ids, err := h.decidableProjects(c, uid, filter.ProjectIDs, domain.CapTriage)
		if err != nil {
			return err
		}
		filter.State, filter.ExcludeRequester, filter.ProjectIDs = AssessmentPending, uid, ids
	}
	page := httpx.ParsePage(c)
	filter.Limit, filter.Offset = page.Limit+1, page.Offset
	as, err := h.repo.ListAssessments(c.UserContext(), filter)
	if err != nil {
		return err
	}
	hasMore := len(as) > page.Limit
	if hasMore {
		as = as[:page.Limit]
	}
	if err := h.markDecidable(c, as); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"assessments": as, "pagination": httpx.Meta(page, len(as), hasMore)})
}

// ListFindingAssessments handles GET /findings/{id}/assessments: every
// assessment of a finding, newest first.
func (h *Handler) ListFindingAssessments(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	as, err := h.repo.ListAssessments(c.UserContext(), AssessmentFilter{FindingID: id})
	if err != nil {
		return err
	}
	if err := h.markDecidable(c, as); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"assessments": as})
}

type decisionRequest struct {
	Note string `json:"note"`
}

// decision loads the assessment a decision targets and checks the caller may
// make it. authz already required project owner (or instance admin); this
// re-checks that and the four-eyes rule, so the answer doesn't hinge on
// route-level wiring.
func (h *Handler) decision(c *fiber.Ctx) (string, decisionRequest, error) {
	var body decisionRequest
	id, err := httpx.ID(c, "assessmentID")
	if err != nil {
		return "", body, err
	}
	if len(c.Body()) > 0 {
		if err := httpx.Parse(c, &body); err != nil {
			return "", body, err
		}
	}
	a, err := h.repo.Assessment(c.UserContext(), id)
	if errors.Is(err, ErrAssessmentNotFound) {
		return "", body, fiber.NewError(fiber.StatusNotFound, "assessment not found")
	}
	if err != nil {
		return "", body, err
	}
	uid := auth.UserID(c)
	if a.RequestedBy != nil && *a.RequestedBy == uid {
		return "", body, fiber.NewError(fiber.StatusForbidden, ErrSelfApproval.Error())
	}
	ok, err := h.can(c, uid, a.ProjectID, domain.TeamOwner)
	if err != nil {
		return "", body, err
	}
	if !ok {
		return "", body, fiber.NewError(fiber.StatusForbidden, "requires an owner of the finding's project")
	}
	return id, body, nil
}

// decisionError maps the repository's decision errors to HTTP.
func decisionError(err error) error {
	switch {
	case errors.Is(err, ErrAssessmentNotFound):
		return fiber.NewError(fiber.StatusNotFound, "assessment not found")
	case errors.Is(err, ErrSelfApproval):
		return fiber.NewError(fiber.StatusForbidden, err.Error())
	case errors.Is(err, ErrAssessmentDecided):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "finding not found")
	}
	return err
}

// ApproveAssessment handles POST /assessments/{id}/approve ({"note": "…"}):
// applies the requested change, attributed to the requester, and records the
// approval. The approver must own the finding's project (or be an instance
// admin) and must not be the requester.
func (h *Handler) ApproveAssessment(c *fiber.Ctx) error {
	id, body, err := h.decision(c)
	if err != nil {
		return err
	}
	a, f, err := h.repo.ApproveAssessment(c.UserContext(), id, auth.UserID(c), body.Note)
	if err != nil {
		return decisionError(err)
	}
	// Status and severity elect a cross-tool group's primary: regroup.
	if _, err := h.repo.Deduplicate(c.UserContext(), f.ProjectID); err != nil {
		slog.WarnContext(c.UserContext(), "dedup after assessment approval failed", "project_id", f.ProjectID, "error", err)
	}
	return c.JSON(fiber.Map{"assessment": a, "finding": f})
}

// RejectAssessment handles POST /assessments/{id}/reject ({"note": "…"}): the
// finding is left as it is. Same authorization as approve.
func (h *Handler) RejectAssessment(c *fiber.Ctx) error {
	id, body, err := h.decision(c)
	if err != nil {
		return err
	}
	a, err := h.repo.RejectAssessment(c.UserContext(), id, auth.UserID(c), body.Note)
	if err != nil {
		return decisionError(err)
	}
	return c.JSON(a)
}
