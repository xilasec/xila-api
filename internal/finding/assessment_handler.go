package finding

import (
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/httpx"
)

// uniqueNonEmpty sorts, deduplicates and drops "" from ids.
func uniqueNonEmpty(ids []string) []string {
	out := slices.DeleteFunc(slices.Clone(ids), func(s string) bool { return s == "" })
	slices.Sort(out)
	return slices.Compact(out)
}

// markDecidable sets CanDecide on each pending assessment the caller may
// approve or reject (mayDecide: an owner of its project, or one of its
// designated approvers when it has any, or instance admin) who isn't the
// requester.
func (h *Handler) markDecidable(c *fiber.Ctx, as []Assessment) error {
	uid := auth.UserID(c)
	decidable := map[string]bool{}
	for i := range as {
		a := &as[i]
		if a.State != AssessmentPending || (a.RequestedBy != nil && *a.RequestedBy == uid) {
			continue
		}
		ok, seen := decidable[a.ProjectID]
		if !seen {
			var err error
			if ok, err = h.mayDecide(c, uid, a.ProjectID); err != nil {
				return err
			}
			decidable[a.ProjectID] = ok
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
// make it (mayDecide); authz already allows down to viewer here, so this is
// the real check, not just a re-check. Also refuses the requester (four-eyes).
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
	ok, err := h.mayDecide(c, uid, a.ProjectID)
	if err != nil {
		return "", body, err
	}
	if !ok {
		return "", body, fiber.NewError(fiber.StatusForbidden, "requires an owner or a designated approver of the finding's project")
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

// bulkAssessmentRequest is the body of POST /assessments/approve|reject.
type bulkAssessmentRequest struct {
	IDs  []string `json:"ids"`
	Note string   `json:"note"`
	// VexJustification / VexResponse: "approve with edits" — overrides every
	// approved assessment's own stored analysis with this one. Omit to apply
	// each exactly as requested. Meaningless for reject.
	VexJustification *domain.VexJustification `json:"vex_justification"`
	VexResponse      []domain.VexResponse     `json:"vex_response"`
}

// authorizeAssessments splits ids into those uid may decide (mayDecide, and
// isn't the requester of), and the rest, recorded in failed with why.
func (h *Handler) authorizeAssessments(c *fiber.Ctx, uid string, ids []string) (allowed []string, failed []BulkFailure, err error) {
	for _, id := range ids {
		a, aerr := h.repo.Assessment(c.UserContext(), id)
		if errors.Is(aerr, ErrAssessmentNotFound) {
			failed = append(failed, BulkFailure{ID: id, Error: "assessment not found"})
			continue
		}
		if aerr != nil {
			return nil, nil, aerr
		}
		if a.RequestedBy != nil && *a.RequestedBy == uid {
			failed = append(failed, BulkFailure{ID: id, Error: ErrSelfApproval.Error()})
			continue
		}
		ok, aerr := h.mayDecide(c, uid, a.ProjectID)
		if aerr != nil {
			return nil, nil, aerr
		}
		if !ok {
			failed = append(failed, BulkFailure{ID: id, Error: "requires an owner or a designated approver of the finding's project"})
			continue
		}
		allowed = append(allowed, id)
	}
	return allowed, failed, nil
}

// BulkApproveAssessments handles POST /assessments/approve: approves many
// pending assessments at once (ids, up to MaxBulk), each authorized on its
// own finding's project like POST /findings/bulk — one the caller may not
// decide, or that doesn't exist, is reported in `failed` and left untouched.
// "approve with edits" (vex_justification / vex_response) overrides every
// approved assessment's own stored analysis with the one given.
func (h *Handler) BulkApproveAssessments(c *fiber.Ctx) error {
	var body bulkAssessmentRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	ids := uniqueNonEmpty(body.IDs)
	if len(ids) == 0 || len(ids) > MaxBulk {
		return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("ids must list 1–%d assessments", MaxBulk))
	}
	if body.VexJustification != nil && !body.VexJustification.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "invalid vex_justification")
	}
	if !domain.ValidVexResponses(body.VexResponse) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid vex_response")
	}
	uid := auth.UserID(c)
	allowed, failed, err := h.authorizeAssessments(c, uid, ids)
	if err != nil {
		return err
	}
	approved, findings, more, err := h.repo.ApproveAssessments(c.UserContext(), allowed, uid, body.Note, body.VexJustification, body.VexResponse)
	if err != nil {
		return err
	}
	failed = append(failed, more...)
	touched := map[string]bool{}
	for _, f := range findings {
		if touched[f.ProjectID] {
			continue
		}
		touched[f.ProjectID] = true
		if _, err := h.repo.Deduplicate(c.UserContext(), f.ProjectID); err != nil {
			slog.WarnContext(c.UserContext(), "dedup after bulk assessment approval failed", "project_id", f.ProjectID, "error", err)
		}
	}
	return c.JSON(fiber.Map{"approved": approved, "failed": failed})
}

// BulkRejectAssessments handles POST /assessments/reject: same shape as
// BulkApproveAssessments, leaving every finding as it is.
func (h *Handler) BulkRejectAssessments(c *fiber.Ctx) error {
	var body bulkAssessmentRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	ids := uniqueNonEmpty(body.IDs)
	if len(ids) == 0 || len(ids) > MaxBulk {
		return fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("ids must list 1–%d assessments", MaxBulk))
	}
	uid := auth.UserID(c)
	allowed, failed, err := h.authorizeAssessments(c, uid, ids)
	if err != nil {
		return err
	}
	rejected, more := h.repo.RejectAssessments(c.UserContext(), allowed, uid, body.Note)
	failed = append(failed, more...)
	return c.JSON(fiber.Map{"rejected": rejected, "failed": failed})
}
