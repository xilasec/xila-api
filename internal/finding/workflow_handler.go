package finding

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/membership"
	"github.com/xilasec/xila-api/internal/notify"
)

// accessChecker answers per-project authorization questions the route-level
// middleware can't (a bulk edit spans projects; an assignee is a third party).
// membership.Repository satisfies it.
type accessChecker interface {
	RoleOnProject(ctx context.Context, userID, projectID string) (domain.TeamRole, bool, error)
	AdminStatus(ctx context.Context, userID string) (isAdmin, isOwner bool, err error)
	OwnedProjectIDs(ctx context.Context, userID string) ([]string, error)
	ProjectCapabilityAllowed(ctx context.Context, userID, projectID string, min domain.TeamRole, cap domain.Capability) (bool, error)
	// ProjectApprovalSetting / AssessmentApprovers / ApproverProjectIDs back
	// the per-project assessment-approval setting (M13 13.9): the project's
	// inherit/required/off override, its designated approvers (groups
	// expanded; empty = any owner may decide), and the reverse lookup for the
	// cross-project review queue.
	ProjectApprovalSetting(ctx context.Context, projectID string) (string, error)
	AssessmentApprovers(ctx context.Context, projectID string) ([]string, error)
	ApproverProjectIDs(ctx context.Context, userID string) ([]string, error)
	ListAssessmentApproverGrants(ctx context.Context, projectID string) ([]membership.ApproverGrant, error)
	SetAssessmentApproverGrants(ctx context.Context, projectID string, userIDs, groupIDs []string) error
}

// decidableProjects narrows a cross-project queue to the projects whose
// requests the caller may decide: those they own (or, when a project has
// designated approvers, those where they are one — see mayDecide), within
// visible (the caller's visible scope; nil = every project). Instance admins
// decide everywhere. A project-scoped token never decides outside its
// project. The result follows the same convention: nil = every project.
//
// cap is the custom-role capability deciding needs: a project where every
// owner-level grant of the caller denies it is left out (designated-approver
// access, which doesn't require owner at all, is never narrowed by cap).
func (h *Handler) decidableProjects(c *fiber.Ctx, uid string, visible []string, cap domain.Capability) ([]string, error) {
	isAdmin, _, err := h.access.AdminStatus(c.UserContext(), uid)
	if err != nil {
		return nil, err
	}
	var mine []string // nil = every project
	if !isAdmin {
		owned, err := h.access.OwnedProjectIDs(c.UserContext(), uid)
		if err != nil {
			return nil, err
		}
		mine = []string{}
		for _, pid := range owned {
			ok, err := h.access.ProjectCapabilityAllowed(c.UserContext(), uid, pid, domain.TeamOwner, cap)
			if err != nil {
				return nil, err
			}
			approvers, err := h.access.AssessmentApprovers(c.UserContext(), pid)
			if err != nil {
				return nil, err
			}
			// Designated approvers narrow who, of the owners, may still decide.
			if ok && (len(approvers) == 0 || slices.Contains(approvers, uid)) {
				mine = append(mine, pid)
			}
		}
		// A designated approver who doesn't otherwise own the project can
		// still decide.
		theirs, err := h.access.ApproverProjectIDs(c.UserContext(), uid)
		if err != nil {
			return nil, err
		}
		mine = append(mine, theirs...)
		slices.Sort(mine)
		mine = slices.Compact(mine)
	}
	if a := auth.CurrentActor(c); a.ProjectID != "" && a.UserID == uid {
		mine = intersectIDs(mine, []string{a.ProjectID})
	}
	return intersectIDs(mine, visible), nil
}

// approvalRequired reports whether projectID's manual assessments need
// approval: its own inherit/required/off override (domain.ApprovalSetting),
// inherit following the instance-wide ASSESSMENT_REQUIRES_APPROVAL default.
func (h *Handler) approvalRequired(ctx context.Context, projectID string) (bool, error) {
	setting, err := h.access.ProjectApprovalSetting(ctx, projectID)
	if err != nil {
		return false, err
	}
	return domain.ApprovalSetting(setting).Effective(h.requireApproval), nil
}

// mayDecide reports whether uid may approve/reject an assessment of
// projectID: an instance admin always may; otherwise, when the project has
// designated approvers, only one of them; otherwise any owner of it (the
// original rule).
func (h *Handler) mayDecide(c *fiber.Ctx, uid, projectID string) (bool, error) {
	isAdmin, _, err := h.access.AdminStatus(c.UserContext(), uid)
	if err != nil || isAdmin {
		return isAdmin, err
	}
	approvers, err := h.access.AssessmentApprovers(c.UserContext(), projectID)
	if err != nil {
		return false, err
	}
	if len(approvers) > 0 {
		return slices.Contains(approvers, uid), nil
	}
	return h.can(c, uid, projectID, domain.TeamOwner)
}

// intersectIDs intersects two id sets where nil means "every id".
func intersectIDs(a, b []string) []string {
	switch {
	case a == nil:
		return b
	case b == nil:
		return a
	}
	out := []string{}
	for _, id := range a {
		if slices.Contains(b, id) {
			out = append(out, id)
		}
	}
	return out
}

// MaxAttachmentBytes caps one evidence file.
const MaxAttachmentBytes = 10 << 20

// MaxBulk caps how many findings one bulk edit may touch — by id list or filter.
const MaxBulk = 5000

// can reports whether userID holds at least min on projectID (instance admins
// always do). An API token scoped to one project can act on that project only.
func (h *Handler) can(c *fiber.Ctx, userID, projectID string, min domain.TeamRole) (bool, error) {
	if a := auth.CurrentActor(c); a.ProjectID != "" && a.UserID == userID && a.ProjectID != projectID {
		return false, nil
	}
	isAdmin, _, err := h.access.AdminStatus(c.UserContext(), userID)
	if err != nil || isAdmin {
		return isAdmin, err
	}
	role, ok, err := h.access.RoleOnProject(c.UserContext(), userID, projectID)
	if err != nil || !ok {
		return false, err
	}
	return role.AtLeast(min), nil
}

// canDo is can plus a custom role's deny-list: some grant meeting min must
// not deny cap (the middleware's rule, for the cross-project bulk edit it
// can't authorize).
func (h *Handler) canDo(c *fiber.Ctx, userID, projectID string, min domain.TeamRole, cap domain.Capability) (bool, error) {
	ok, err := h.can(c, userID, projectID, min)
	if err != nil || !ok {
		return false, err
	}
	if isAdmin, _, err := h.access.AdminStatus(c.UserContext(), userID); err != nil || isAdmin {
		return isAdmin, err
	}
	return h.access.ProjectCapabilityAllowed(c.UserContext(), userID, projectID, min, cap)
}

// assignable checks a would-be assignee can see every project involved.
func (h *Handler) assignable(c *fiber.Ctx, assigneeID string, projectIDs []string) error {
	if uuid.Validate(assigneeID) != nil {
		return fiber.NewError(fiber.StatusBadRequest, "assignee_id must be a user id")
	}
	for _, pid := range projectIDs {
		isAdmin, _, err := h.access.AdminStatus(c.UserContext(), assigneeID)
		if err != nil {
			return err
		}
		if isAdmin {
			return nil
		}
		if _, ok, err := h.access.RoleOnProject(c.UserContext(), assigneeID, pid); err != nil {
			return err
		} else if !ok {
			return fiber.NewError(fiber.StatusBadRequest, "the assignee has no access to this project")
		}
	}
	return nil
}

// History handles GET /findings/{id}/history: every status, severity and
// assignee change (with who and why), comments and attachments, oldest first.
func (h *Handler) History(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	events, err := h.repo.History(c.UserContext(), id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"events": events})
}

type assignRequest struct {
	AssigneeID *string `json:"assignee_id"`
}

// Assign handles PUT /findings/{id}/assignee — {"assignee_id": "…"} or null.
func (h *Handler) Assign(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	if done, err := h.precondition(c, id); done || err != nil {
		return err
	}
	var body assignRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	f, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "finding not found")
	}
	if err != nil {
		return err
	}
	if body.AssigneeID != nil {
		if err := h.assignable(c, *body.AssigneeID, []string{f.ProjectID}); err != nil {
			return err
		}
	}
	out, err := h.repo.Apply(c.UserContext(), []string{id}, Change{SetAssignee: true, AssigneeID: body.AssigneeID}, auth.UserID(c))
	if err != nil {
		return err
	}
	if body.AssigneeID != nil && (f.AssigneeID == nil || *f.AssigneeID != *body.AssigneeID) {
		h.notifyAssigned(out)
	}
	return c.JSON(out[0])
}

type tagsRequest struct {
	Tags []string `json:"tags"`
}

// SetTags handles PUT /findings/{id}/tags — {"tags": [...]} replaces the
// finding's tags (normalized: lowercase, sorted, deduplicated).
func (h *Handler) SetTags(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	if done, err := h.precondition(c, id); done || err != nil {
		return err
	}
	var body tagsRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	tags, err := NormalizeTags(body.Tags)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if len(tags) > MaxTags {
		return fiber.NewError(fiber.StatusBadRequest, ErrTooManyTags.Error())
	}
	out, err := h.repo.Apply(c.UserContext(), []string{id}, Change{SetTags: true, Tags: tags}, auth.UserID(c))
	if err != nil {
		return err
	}
	if len(out) == 0 {
		return fiber.NewError(fiber.StatusNotFound, "finding not found")
	}
	return c.JSON(out[0])
}

// Tags handles GET /findings/tags: every tag in use on the findings the
// caller can see (default versions, duplicates collapsed), with how many open
// findings carry it — for filter pickers and autocomplete. ?project_id= narrows.
func (h *Handler) Tags(c *fiber.Ctx) error {
	var scope []string
	if s := authz.VisibleScope(c); !s.AllAccess {
		scope = s.ProjectIDs
	}
	projectID := c.Query("project_id")
	if projectID != "" && uuid.Validate(projectID) != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid project_id")
	}
	tags, err := h.repo.TagCounts(c.UserContext(), projectID, scope)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"tags": tags})
}

type bulkRequest struct {
	IDs       []string              `json:"ids"`
	Status    *domain.FindingStatus `json:"status"`
	Reason    string                `json:"reason"`
	ExpiresAt *time.Time            `json:"expires_at"`
	// VexJustification / VexResponse: the structured analysis accompanying a
	// move to false_positive or wont_fix (M13 13.2); ignored for any other
	// status.
	VexJustification domain.VexJustification `json:"vex_justification"`
	VexResponse      []domain.VexResponse    `json:"vex_response"`
	// Title names the risk acceptance(s) status risk_accepted requests.
	Title    string           `json:"title"`
	Severity *domain.Severity `json:"severity"`
	// AssigneeID distinguishes absent (leave alone) from null (unassign).
	AssigneeID json.RawMessage `json:"assignee_id"`
	// Filter selects the findings instead of IDs: the same keys as
	// GET /findings (status, severity, project_id, assignee, sla, kev, …),
	// within what the caller can see.
	Filter map[string]string `json:"filter"`
	// AddTags / RemoveTags edit each finding's tags.
	AddTags    []string `json:"add_tags"`
	RemoveTags []string `json:"remove_tags"`
}

// bulkTargets resolves the findings a bulk edit names: its ids, or everything
// its filter matches in the caller's visible scope (refusing more than MaxBulk
// rather than silently editing a prefix).
func (h *Handler) bulkTargets(c *fiber.Ctx, body bulkRequest) ([]string, error) {
	if len(body.IDs) > 0 && len(body.Filter) > 0 {
		return nil, fiber.NewError(fiber.StatusBadRequest, "give ids or filter, not both")
	}
	if len(body.Filter) == 0 {
		ids := slices.Clone(body.IDs)
		slices.Sort(ids)
		ids = slices.Compact(ids)
		if len(ids) == 0 || len(ids) > MaxBulk {
			return nil, fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("ids must list 1–%d findings", MaxBulk))
		}
		return ids, nil
	}
	filter, err := filterFrom(body.Filter, auth.UserID(c))
	if err != nil {
		return nil, err
	}
	filter.ProjectID = body.Filter["project_id"]
	filter.AssetID = body.Filter["asset_id"]
	filter.VersionName = body.Filter["branch"]
	if scope := authz.VisibleScope(c); !scope.AllAccess {
		filter.ProjectIDs = scope.ProjectIDs
	}
	filter.Limit = MaxBulk + 1
	matched, err := h.repo.List(c.UserContext(), filter)
	if err != nil {
		return nil, err
	}
	if len(matched) == 0 {
		return nil, fiber.NewError(fiber.StatusBadRequest, "the filter matches no findings")
	}
	if len(matched) > MaxBulk {
		return nil, fiber.NewError(fiber.StatusBadRequest, fmt.Sprintf("the filter matches more than %d findings — narrow it", MaxBulk))
	}
	ids := make([]string, len(matched))
	for i, f := range matched {
		ids[i] = f.ID
	}
	return ids, nil
}

// BulkFailure is one finding a bulk edit skipped, and why.
type BulkFailure struct {
	ID    string `json:"id"`
	Error string `json:"error"`
}

// Bulk handles POST /findings/bulk: one status / severity / assignee change
// applied to many findings (up to MaxBulk, by ids or by filter), across
// projects. Each finding is authorized on its own project (editor or above);
// the ones the caller can't edit, or that don't exist, are reported in
// `failed` and left untouched — the rest are applied in one transaction.
// A status / severity change becomes one pending assessment per finding
// (`pending`, 202) instead of applying at once wherever its project's
// assessment-approval setting requires it (the project's own
// inherit/required/off override, inherit following ASSESSMENT_REQUIRES_APPROVAL);
// different projects in the same bulk edit may split this way. An assignee
// or tag change still applies at once regardless. Status risk_accepted
// requests one risk acceptance per project (`acceptances`, 202) — the
// findings only become risk_accepted once it is approved.
func (h *Handler) Bulk(c *fiber.Ctx) error {
	var body bulkRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	change := Change{Status: body.Status, Reason: body.Reason, ExpiresAt: body.ExpiresAt, Severity: body.Severity,
		VexJustification: body.VexJustification, VexResponse: body.VexResponse}
	if change.Status != nil && !change.Status.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "invalid status")
	}
	if change.Severity != nil && !change.Severity.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "invalid severity")
	}
	if !change.VexJustification.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "invalid vex_justification")
	}
	if !domain.ValidVexResponses(change.VexResponse) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid vex_response")
	}
	if len(body.AssigneeID) > 0 {
		change.SetAssignee = true
		if string(body.AssigneeID) != "null" {
			var a string
			if err := json.Unmarshal(body.AssigneeID, &a); err != nil {
				return fiber.NewError(fiber.StatusBadRequest, "assignee_id must be a user id or null")
			}
			change.AssigneeID = &a
		}
	}
	var err error
	if change.AddTags, err = NormalizeTags(body.AddTags); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if change.RemoveTags, err = NormalizeTags(body.RemoveTags); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if change.Empty() {
		return fiber.NewError(fiber.StatusBadRequest, "nothing to change: give status, severity, assignee_id, add_tags and/or remove_tags")
	}
	acceptRisk := change.Status != nil && *change.Status == domain.FindingRiskAccepted
	if acceptRisk {
		if strings.TrimSpace(change.Reason) == "" {
			return fiber.NewError(fiber.StatusBadRequest, "accepting a risk needs a reason")
		}
		if change.ExpiresAt != nil && !change.ExpiresAt.After(time.Now()) {
			return fiber.NewError(fiber.StatusBadRequest, "expires_at must be in the future")
		}
	}
	targets, err := h.bulkTargets(c, body)
	if err != nil {
		return err
	}

	var valid []string
	failed := []BulkFailure{}
	for _, id := range targets {
		if uuid.Validate(id) != nil {
			failed = append(failed, BulkFailure{id, "not a finding id"})
		} else {
			valid = append(valid, id)
		}
	}
	projects, err := h.repo.ProjectsOf(c.UserContext(), valid)
	if err != nil {
		return err
	}
	allowed := map[string]bool{}
	var ids, touched []string
	for _, id := range valid {
		pid, ok := projects[id]
		if !ok {
			failed = append(failed, BulkFailure{id, "finding not found"})
			continue
		}
		ok, seen := allowed[pid]
		if !seen {
			if ok, err = h.canDo(c, auth.UserID(c), pid, domain.TeamEditor, domain.CapTriage); err != nil {
				return err
			}
			allowed[pid] = ok
			touched = append(touched, pid)
		}
		if !ok {
			// Same answer as a missing finding: don't confirm what exists elsewhere.
			failed = append(failed, BulkFailure{id, "finding not found"})
			continue
		}
		ids = append(ids, id)
	}
	if change.AssigneeID != nil && len(ids) > 0 {
		var editable []string
		for _, pid := range touched {
			if allowed[pid] {
				editable = append(editable, pid)
			}
		}
		if err := h.assignable(c, *change.AssigneeID, editable); err != nil {
			return err
		}
	}

	updated, pending, acceptances := []Finding{}, []Assessment{}, []RiskAcceptance{}
	if len(ids) > 0 {
		direct := change
		if acceptRisk {
			created, busy, err := h.repo.RequestAcceptances(c.UserContext(), ids, AcceptanceInput{
				Title: strings.TrimSpace(body.Title), Justification: change.Reason, ExpiresAt: change.ExpiresAt,
			}, auth.UserID(c))
			if err != nil {
				return err
			}
			acceptances = created
			for _, a := range created {
				h.notifyAcceptance(notify.EventRiskAcceptanceRequested, "Risk acceptance requested", a)
			}
			for _, id := range busy {
				failed = append(failed, BulkFailure{id, "already in a risk acceptance, or not open"})
			}
			direct.Status, direct.Reason, direct.ExpiresAt = nil, "", nil
			change.Status = nil
		}
		// A status / severity change may need approval on some of the touched
		// projects and not others (each project's own setting): split ids
		// accordingly, rather than one blanket answer for the whole edit.
		var needApproval []string
		if change.Status != nil || change.Severity != nil {
			approvalFor := map[string]bool{}
			for _, pid := range touched {
				if !allowed[pid] {
					continue
				}
				req, err := h.approvalRequired(c.UserContext(), pid)
				if err != nil {
					return err
				}
				approvalFor[pid] = req
			}
			var directIDs []string
			for _, id := range ids {
				if approvalFor[projects[id]] {
					needApproval = append(needApproval, id)
				} else {
					directIDs = append(directIDs, id)
				}
			}
			if len(needApproval) > 0 {
				created, busy, rerr := h.repo.RequestAssessments(c.UserContext(), needApproval, change, auth.UserID(c))
				if rerr != nil {
					return rerr
				}
				pending = created
				for _, id := range busy {
					failed = append(failed, BulkFailure{id, ErrAssessmentPending.Error()})
				}
			}
			ids = directIDs
		}
		if !direct.Empty() {
			if updated, err = h.repo.Apply(c.UserContext(), ids, direct, auth.UserID(c)); errors.Is(err, ErrTooManyTags) {
				return fiber.NewError(fiber.StatusBadRequest, err.Error())
			} else if err != nil {
				return err
			}
			if direct.SetAssignee && direct.AssigneeID != nil {
				h.notifyAssigned(updated)
			}
		}
		if len(needApproval) > 0 && (direct.SetAssignee || direct.touchesTags()) {
			// Assignment and tags aren't assessments: they still apply at once
			// to findings whose status / severity is held for review.
			assignTags := Change{SetAssignee: direct.SetAssignee, AssigneeID: direct.AssigneeID,
				AddTags: direct.AddTags, RemoveTags: direct.RemoveTags}
			more, aerr := h.repo.Apply(c.UserContext(), needApproval, assignTags, auth.UserID(c))
			if aerr != nil {
				return aerr
			}
			updated = append(updated, more...)
			if assignTags.SetAssignee && assignTags.AssigneeID != nil {
				h.notifyAssigned(more)
			}
		}
		// Severity elects a cross-tool group's primary: regroup what moved.
		if direct.Severity != nil || direct.Status != nil {
			for _, pid := range touched {
				if !allowed[pid] {
					continue
				}
				if _, err := h.repo.Deduplicate(c.UserContext(), pid); err != nil {
					slog.WarnContext(c.UserContext(), "dedup after bulk edit failed", "project_id", pid, "error", err)
				}
			}
		}
	}
	status := fiber.StatusOK
	if len(pending) > 0 || len(acceptances) > 0 {
		status = fiber.StatusAccepted
	}
	return c.Status(status).JSON(fiber.Map{"updated": updated, "failed": failed, "pending": pending, "acceptances": acceptances})
}

// notifyAssigned raises finding.assigned for each assigned finding (the
// assignee's personal subscription routes it to them).
func (h *Handler) notifyAssigned(fs []Finding) {
	if h.notifier == nil {
		return
	}
	for _, f := range fs {
		if f.AssigneeID == nil {
			continue
		}
		e := notify.Event{Type: notify.EventFindingAssigned, ProjectID: f.ProjectID, FindingID: f.ID,
			Severity: string(f.Severity), Title: "Assigned: " + f.Title,
			Text:   fmt.Sprintf("%s (%s) was assigned to %s.", f.Title, f.Severity, deref(f.AssigneeEmail)),
			Fields: map[string]string{"severity": string(f.Severity), "assignee": deref(f.AssigneeEmail)}}
		go h.notifier.Notify(context.Background(), e)
	}
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

type commentRequest struct {
	Body string `json:"body"`
}

// ListComments handles GET /findings/{id}/comments.
func (h *Handler) ListComments(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	comments, err := h.repo.Comments(c.UserContext(), id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"comments": comments})
}

// AddComment handles POST /findings/{id}/comments.
func (h *Handler) AddComment(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	var body commentRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	body.Body = strings.TrimSpace(body.Body)
	if body.Body == "" || len(body.Body) > 20000 {
		return fiber.NewError(fiber.StatusBadRequest, "comment body must be 1–20000 characters")
	}
	cm, err := h.repo.AddComment(c.UserContext(), id, auth.UserID(c), body.Body)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "finding not found")
	}
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(cm)
}

// DeleteComment handles DELETE /findings/{id}/comments/{commentID}: the author
// may delete their own comment; a project owner or admin may delete any.
func (h *Handler) DeleteComment(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	commentID, err := httpx.ID(c, "commentID")
	if err != nil {
		return err
	}
	cm, err := h.repo.Comment(c.UserContext(), id, commentID)
	if errors.Is(err, ErrCommentNotFound) {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	if err != nil {
		return err
	}
	if err := h.ownOrOwner(c, cm.AuthorID, id); err != nil {
		return err
	}
	if err := h.repo.DeleteComment(c.UserContext(), id, commentID); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// ownOrOwner allows the resource's author, or an owner of the finding's project.
func (h *Handler) ownOrOwner(c *fiber.Ctx, authorID *string, findingID string) error {
	uid := auth.UserID(c)
	if authorID != nil && *authorID == uid {
		return nil
	}
	f, err := h.repo.Get(c.UserContext(), findingID)
	if err != nil {
		return err
	}
	ok, err := h.can(c, uid, f.ProjectID, domain.TeamOwner)
	if err != nil {
		return err
	}
	if !ok {
		return fiber.NewError(fiber.StatusForbidden, "only the author or a project owner can delete this")
	}
	return nil
}

// ListAttachments handles GET /findings/{id}/attachments.
func (h *Handler) ListAttachments(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	list, err := h.repo.Attachments(c.UserContext(), id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"attachments": list})
}

// AddAttachment handles POST /findings/{id}/attachments (multipart, field
// "file", ≤ 10 MiB).
func (h *Handler) AddAttachment(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	fh, err := c.FormFile("file")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "upload a file in the multipart field \"file\"")
	}
	if fh.Size > MaxAttachmentBytes {
		return fiber.NewError(fiber.StatusRequestEntityTooLarge, "attachments are limited to 10 MiB")
	}
	file, err := fh.Open()
	if err != nil {
		return err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, MaxAttachmentBytes+1))
	if err != nil {
		return err
	}
	if len(data) > MaxAttachmentBytes {
		return fiber.NewError(fiber.StatusRequestEntityTooLarge, "attachments are limited to 10 MiB")
	}
	name := filepath.Base(strings.ReplaceAll(fh.Filename, "\\", "/"))
	if name == "" || name == "." || name == "/" {
		name = "attachment"
	}
	a, err := h.repo.AddAttachment(c.UserContext(), id, auth.UserID(c), name, http.DetectContentType(data), data)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "finding not found")
	}
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(a)
}

// inlineSafe is what may be served with its own type; everything else (HTML,
// SVG, scripts) is sent as an opaque download so a file can't run in our origin.
var inlineSafe = []string{"image/png", "image/jpeg", "image/gif", "image/webp", "application/pdf", "text/plain; charset=utf-8"}

// DownloadAttachment handles GET /findings/{id}/attachments/{attachmentID}.
func (h *Handler) DownloadAttachment(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	attachmentID, err := httpx.ID(c, "attachmentID")
	if err != nil {
		return err
	}
	a, err := h.repo.Attachment(c.UserContext(), id, attachmentID)
	if errors.Is(err, ErrAttachmentNotFound) {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	if err != nil {
		return err
	}
	ctype := "application/octet-stream"
	if slices.Contains(inlineSafe, a.ContentType) {
		ctype = a.ContentType
	}
	c.Set(fiber.HeaderContentType, ctype)
	c.Set("X-Content-Type-Options", "nosniff")
	c.Set(fiber.HeaderContentDisposition, mime.FormatMediaType("attachment", map[string]string{"filename": a.Filename}))
	return c.Send(a.Data)
}

// DeleteAttachment handles DELETE /findings/{id}/attachments/{attachmentID}.
func (h *Handler) DeleteAttachment(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	attachmentID, err := httpx.ID(c, "attachmentID")
	if err != nil {
		return err
	}
	a, err := h.repo.Attachment(c.UserContext(), id, attachmentID)
	if errors.Is(err, ErrAttachmentNotFound) {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	if err != nil {
		return err
	}
	if err := h.ownOrOwner(c, a.UploadedBy, id); err != nil {
		return err
	}
	if err := h.repo.DeleteAttachment(c.UserContext(), id, attachmentID); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
