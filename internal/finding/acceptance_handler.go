package finding

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/notify"
)

// WithRiskAcceptanceApproval turns on four-eyes for risk acceptances
// (RISK_ACCEPTANCE_REQUIRES_APPROVAL): the requester can't approve or reject
// their own request.
func (h *Handler) WithRiskAcceptanceApproval(required bool) *Handler {
	h.acceptanceApproval = required
	return h
}

// registerAcceptances mounts the risk-acceptance routes. authz requires viewer
// to read, editor to request / edit / change membership, and owner to
// approve, reject or revoke.
func (h *Handler) registerAcceptances(r fiber.Router) {
	r.Get("/risk-acceptances", h.ListAllAcceptances)
	r.Get("/projects/:projectID/risk-acceptances", h.ListAcceptances)
	r.Post("/projects/:projectID/risk-acceptances", h.CreateAcceptance)
	r.Get("/projects/:projectID/risk-acceptances/:acceptanceID", h.GetAcceptance)
	r.Patch("/projects/:projectID/risk-acceptances/:acceptanceID", h.UpdateAcceptance)
	r.Delete("/projects/:projectID/risk-acceptances/:acceptanceID", h.DeleteAcceptance)
	r.Post("/projects/:projectID/risk-acceptances/:acceptanceID/approve", h.ApproveAcceptance)
	r.Post("/projects/:projectID/risk-acceptances/:acceptanceID/reject", h.RejectAcceptance)
	r.Post("/projects/:projectID/risk-acceptances/:acceptanceID/revoke", h.RevokeAcceptance)
	r.Post("/projects/:projectID/risk-acceptances/:acceptanceID/findings", h.AddAcceptanceFindings)
	r.Delete("/projects/:projectID/risk-acceptances/:acceptanceID/findings/:findingID", h.RemoveAcceptanceFinding)
	r.Get("/findings/:findingID/risk-acceptances", h.FindingLedger)
}

// acceptanceError maps the repository's risk-acceptance errors to HTTP.
func acceptanceError(err error) error {
	switch {
	case errors.Is(err, ErrAcceptanceNotFound):
		return fiber.NewError(fiber.StatusNotFound, "risk acceptance not found")
	case errors.Is(err, ErrNotMember):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	case errors.Is(err, ErrAcceptanceSelfDecision):
		return fiber.NewError(fiber.StatusForbidden, err.Error())
	case errors.Is(err, ErrAcceptanceState), errors.Is(err, ErrAcceptanceLapsed):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	return err
}

// markAcceptances sets CanApprove / CanRevoke for the caller: an owner of the
// project (or instance admin) may revoke a live acceptance and decide a
// request — except, with four-eyes, their own.
func (h *Handler) markAcceptances(c *fiber.Ctx, as []RiskAcceptance) error {
	uid := auth.UserID(c)
	owner := map[string]bool{}
	for i := range as {
		a := &as[i]
		if !a.State.Live() {
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
		a.CanRevoke = ok
		a.CanApprove = ok && a.State == AcceptanceRequested && !h.selfDecision(*a, uid)
	}
	return nil
}

// selfDecision reports whether four-eyes forbids uid deciding a.
func (h *Handler) selfDecision(a RiskAcceptance, uid string) bool {
	return h.acceptanceApproval && a.RequestedBy != nil && *a.RequestedBy == uid
}

func acceptanceState(c *fiber.Ctx) (AcceptanceState, error) {
	s := AcceptanceState(c.Query("state"))
	if s != "" && !s.Valid() {
		return "", fiber.NewError(fiber.StatusBadRequest, "state must be requested, approved, expired, revoked or rejected")
	}
	return s, nil
}

// respondAcceptances writes a paginated acceptance list.
func (h *Handler) respondAcceptances(c *fiber.Ctx, f AcceptanceFilter) error {
	page := httpx.ParsePage(c)
	f.Limit, f.Offset = page.Limit+1, page.Offset
	as, err := h.repo.ListAcceptances(c.UserContext(), f)
	if err != nil {
		return err
	}
	hasMore := len(as) > page.Limit
	if hasMore {
		as = as[:page.Limit]
	}
	if err := h.markAcceptances(c, as); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"risk_acceptances": as, "pagination": httpx.Meta(page, len(as), hasMore)})
}

// ListAllAcceptances handles GET /risk-acceptances?state=requested — the
// approval queue across every project the caller can see. ?actionable=true
// keeps only the requests the caller may approve; ?owner=me and
// ?expires_within_days=N find the acceptances someone has to renew.
func (h *Handler) ListAllAcceptances(c *fiber.Ctx) error {
	state, err := acceptanceState(c)
	if err != nil {
		return err
	}
	f := AcceptanceFilter{State: state, ProjectID: c.Query("project_id")}
	if f.ProjectID != "" && uuid.Validate(f.ProjectID) != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid project_id")
	}
	if scope := authz.VisibleScope(c); !scope.AllAccess {
		f.ProjectIDs = scope.ProjectIDs
		if f.ProjectIDs == nil {
			f.ProjectIDs = []string{}
		}
	}
	uid := auth.UserID(c)
	switch o := c.Query("owner"); o {
	case "":
	case "me":
		f.OwnerID = uid
	default:
		if uuid.Validate(o) != nil {
			return fiber.NewError(fiber.StatusBadRequest, "owner must be me or a user id")
		}
		f.OwnerID = o
	}
	if d := c.Query("expires_within_days"); d != "" {
		n, err := strconv.Atoi(d)
		if err != nil || n < 1 || n > 3650 {
			return fiber.NewError(fiber.StatusBadRequest, "expires_within_days must be 1 to 3650")
		}
		before := time.Now().Add(time.Duration(n) * 24 * time.Hour)
		f.ExpiresBefore = &before
	}
	if c.QueryBool("actionable") {
		ids, err := h.decidableProjects(c, uid, f.ProjectIDs)
		if err != nil {
			return err
		}
		f.State, f.ProjectIDs = AcceptanceRequested, ids
		if h.acceptanceApproval {
			f.ExcludeRequester = uid
		}
	}
	return h.respondAcceptances(c, f)
}

// ListAcceptances handles GET /projects/{id}/risk-acceptances (?state=).
func (h *Handler) ListAcceptances(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	state, err := acceptanceState(c)
	if err != nil {
		return err
	}
	return h.respondAcceptances(c, AcceptanceFilter{ProjectID: pid, State: state})
}

type acceptanceRequest struct {
	Title         string     `json:"title"`
	Justification string     `json:"justification"`
	OwnerID       *string    `json:"owner_id"`
	ExpiresAt     *time.Time `json:"expires_at"`
	FindingIDs    []string   `json:"finding_ids"`
}

const (
	maxAcceptanceTitle = 200
	maxJustification   = 20000
)

// validFindingIDs dedups ids and checks they're uuids and within MaxBulk.
func validFindingIDs(ids []string) ([]string, error) {
	if len(ids) > MaxBulk {
		return nil, fiber.NewError(fiber.StatusBadRequest, "too many finding_ids")
	}
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if uuid.Validate(id) != nil {
			return nil, fiber.NewError(fiber.StatusBadRequest, "finding_ids must be finding ids")
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out, nil
}

// ownerAllowed checks a would-be owner can see the project.
func (h *Handler) ownerAllowed(c *fiber.Ctx, ownerID, projectID string) error {
	if uuid.Validate(ownerID) != nil {
		return fiber.NewError(fiber.StatusBadRequest, "owner_id must be a user id")
	}
	isAdmin, _, err := h.access.AdminStatus(c.UserContext(), ownerID)
	if err != nil || isAdmin {
		return err
	}
	if _, ok, err := h.access.RoleOnProject(c.UserContext(), ownerID, projectID); err != nil {
		return err
	} else if !ok {
		return fiber.NewError(fiber.StatusBadRequest, "the owner has no access to this project")
	}
	return nil
}

// CreateAcceptance handles POST /projects/{id}/risk-acceptances: a request to
// accept the risk of finding_ids (open / confirmed findings of the project
// not already in a live acceptance; others come back in `skipped`). The
// findings stay open and counted until it is approved.
func (h *Handler) CreateAcceptance(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var body acceptanceRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	body.Title = strings.TrimSpace(body.Title)
	if body.Title == "" || len(body.Title) > maxAcceptanceTitle {
		return fiber.NewError(fiber.StatusBadRequest, "title is required (at most 200 characters)")
	}
	if strings.TrimSpace(body.Justification) == "" || len(body.Justification) > maxJustification {
		return fiber.NewError(fiber.StatusBadRequest, "justification is required (at most 20000 characters)")
	}
	if body.ExpiresAt != nil && !body.ExpiresAt.After(time.Now()) {
		return fiber.NewError(fiber.StatusBadRequest, "expires_at must be in the future")
	}
	ids, err := validFindingIDs(body.FindingIDs)
	if err != nil {
		return err
	}
	if body.OwnerID != nil {
		if err := h.ownerAllowed(c, *body.OwnerID, pid); err != nil {
			return err
		}
	}
	a, skipped, err := h.repo.CreateAcceptance(c.UserContext(), AcceptanceInput{
		ProjectID: pid, Title: body.Title, Justification: body.Justification,
		OwnerID: body.OwnerID, ExpiresAt: body.ExpiresAt, FindingIDs: ids,
	}, auth.UserID(c))
	if err != nil {
		return err
	}
	h.notifyAcceptance(notify.EventRiskAcceptanceRequested, "Risk acceptance requested", a)
	as := []RiskAcceptance{a}
	if err := h.markAcceptances(c, as); err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"risk_acceptance": as[0], "skipped": skipped})
}

// GetAcceptance handles GET /projects/{id}/risk-acceptances/{aid}: the
// acceptance and its membership ledger (current and past members).
func (h *Handler) GetAcceptance(c *fiber.Ctx) error {
	pid, id, err := acceptanceIDs(c)
	if err != nil {
		return err
	}
	a, err := h.repo.Acceptance(c.UserContext(), pid, id)
	if err != nil {
		return acceptanceError(err)
	}
	members, err := h.repo.AcceptanceMembers(c.UserContext(), id)
	if err != nil {
		return err
	}
	as := []RiskAcceptance{a}
	if err := h.markAcceptances(c, as); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"risk_acceptance": as[0], "findings": members})
}

func acceptanceIDs(c *fiber.Ctx) (string, string, error) {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return "", "", err
	}
	id, err := httpx.ID(c, "acceptanceID")
	return pid, id, err
}

type acceptancePatchRequest struct {
	Title         *string         `json:"title"`
	Justification *string         `json:"justification"`
	OwnerID       *string         `json:"owner_id"`
	ExpiresAt     json.RawMessage `json:"expires_at"` // absent = keep, null = never expires
}

// UpdateAcceptance handles PATCH /projects/{id}/risk-acceptances/{aid}: edit a
// request before it is decided.
func (h *Handler) UpdateAcceptance(c *fiber.Ctx) error {
	pid, id, err := acceptanceIDs(c)
	if err != nil {
		return err
	}
	var body acceptancePatchRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	p := AcceptancePatch{Justification: body.Justification, OwnerID: body.OwnerID}
	if body.Title != nil {
		t := strings.TrimSpace(*body.Title)
		if t == "" || len(t) > maxAcceptanceTitle {
			return fiber.NewError(fiber.StatusBadRequest, "title is required (at most 200 characters)")
		}
		p.Title = &t
	}
	if body.Justification != nil && (strings.TrimSpace(*body.Justification) == "" || len(*body.Justification) > maxJustification) {
		return fiber.NewError(fiber.StatusBadRequest, "justification is required (at most 20000 characters)")
	}
	if len(body.ExpiresAt) > 0 {
		p.SetExpiry = true
		if string(body.ExpiresAt) != "null" {
			var t time.Time
			if err := json.Unmarshal(body.ExpiresAt, &t); err != nil {
				return fiber.NewError(fiber.StatusBadRequest, "expires_at must be an RFC 3339 time or null")
			}
			if !t.After(time.Now()) {
				return fiber.NewError(fiber.StatusBadRequest, "expires_at must be in the future")
			}
			p.ExpiresAt = &t
		}
	}
	if body.OwnerID != nil {
		if err := h.ownerAllowed(c, *body.OwnerID, pid); err != nil {
			return err
		}
	}
	a, err := h.repo.UpdateAcceptance(c.UserContext(), pid, id, p)
	if err != nil {
		return acceptanceError(err)
	}
	as := []RiskAcceptance{a}
	if err := h.markAcceptances(c, as); err != nil {
		return err
	}
	return c.JSON(as[0])
}

// DeleteAcceptance handles DELETE /projects/{id}/risk-acceptances/{aid}:
// withdraw a request that never took effect (requested or rejected). Its
// requester or a project owner may.
func (h *Handler) DeleteAcceptance(c *fiber.Ctx) error {
	pid, id, err := acceptanceIDs(c)
	if err != nil {
		return err
	}
	a, err := h.repo.Acceptance(c.UserContext(), pid, id)
	if err != nil {
		return acceptanceError(err)
	}
	uid := auth.UserID(c)
	if a.RequestedBy == nil || *a.RequestedBy != uid {
		ok, err := h.can(c, uid, pid, domain.TeamOwner)
		if err != nil {
			return err
		}
		if !ok {
			return fiber.NewError(fiber.StatusForbidden, "only the requester or a project owner can delete a risk acceptance")
		}
	}
	if err := h.repo.DeleteAcceptance(c.UserContext(), pid, id); err != nil {
		return acceptanceError(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

type acceptanceDecisionRequest struct {
	Note string `json:"note"`
}

func parseDecision(c *fiber.Ctx) (acceptanceDecisionRequest, error) {
	var body acceptanceDecisionRequest
	if len(c.Body()) > 0 {
		if err := httpx.Parse(c, &body); err != nil {
			return body, err
		}
	}
	return body, nil
}

// ApproveAcceptance handles POST /projects/{id}/risk-acceptances/{aid}/approve
// ({"note": "…"}): its findings become risk_accepted and their SLA clocks
// pause. Needs a project owner (authz); with RISK_ACCEPTANCE_REQUIRES_APPROVAL
// not the requester.
func (h *Handler) ApproveAcceptance(c *fiber.Ctx) error {
	pid, id, err := acceptanceIDs(c)
	if err != nil {
		return err
	}
	body, err := parseDecision(c)
	if err != nil {
		return err
	}
	a, moved, err := h.repo.ApproveAcceptance(c.UserContext(), pid, id, auth.UserID(c), body.Note, h.acceptanceApproval)
	if err != nil {
		return acceptanceError(err)
	}
	h.regroup(c.UserContext(), pid, len(moved))
	h.notifyAcceptance(notify.EventRiskAcceptanceApproved, "Risk accepted", a)
	as := []RiskAcceptance{a}
	if err := h.markAcceptances(c, as); err != nil {
		return err
	}
	return c.JSON(as[0])
}

// RejectAcceptance handles POST /projects/{id}/risk-acceptances/{aid}/reject:
// the request is turned down; its findings never changed.
func (h *Handler) RejectAcceptance(c *fiber.Ctx) error {
	pid, id, err := acceptanceIDs(c)
	if err != nil {
		return err
	}
	body, err := parseDecision(c)
	if err != nil {
		return err
	}
	a, err := h.repo.RejectAcceptance(c.UserContext(), pid, id, auth.UserID(c), body.Note, h.acceptanceApproval)
	if err != nil {
		return acceptanceError(err)
	}
	return c.JSON(a)
}

// RevokeAcceptance handles POST /projects/{id}/risk-acceptances/{aid}/revoke:
// ends a live acceptance early; an approved one's findings reopen.
func (h *Handler) RevokeAcceptance(c *fiber.Ctx) error {
	pid, id, err := acceptanceIDs(c)
	if err != nil {
		return err
	}
	body, err := parseDecision(c)
	if err != nil {
		return err
	}
	a, err := h.repo.RevokeAcceptance(c.UserContext(), pid, id, auth.UserID(c), body.Note)
	if err != nil {
		return acceptanceError(err)
	}
	h.regroup(c.UserContext(), pid, a.FindingCount)
	return c.JSON(a)
}

type acceptanceFindingsRequest struct {
	FindingIDs []string `json:"finding_ids"`
}

// AddAcceptanceFindings handles POST /projects/{id}/risk-acceptances/{aid}/findings
// ({"finding_ids": […]}). Adding to an approved acceptance accepts the
// findings at once, so it takes someone who could approve it.
func (h *Handler) AddAcceptanceFindings(c *fiber.Ctx) error {
	pid, id, err := acceptanceIDs(c)
	if err != nil {
		return err
	}
	var body acceptanceFindingsRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	ids, err := validFindingIDs(body.FindingIDs)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "finding_ids is required")
	}
	cur, err := h.repo.Acceptance(c.UserContext(), pid, id)
	if err != nil {
		return acceptanceError(err)
	}
	uid := auth.UserID(c)
	if cur.State == AcceptanceApproved {
		ok, err := h.can(c, uid, pid, domain.TeamOwner)
		if err != nil {
			return err
		}
		if !ok || h.selfDecision(cur, uid) {
			return fiber.NewError(fiber.StatusForbidden, "adding findings to an approved risk acceptance accepts them: it takes someone who may approve it")
		}
	}
	a, skipped, err := h.repo.AddAcceptanceFindings(c.UserContext(), pid, id, ids, uid)
	if err != nil {
		return acceptanceError(err)
	}
	if a.State == AcceptanceApproved {
		h.regroup(c.UserContext(), pid, len(ids)-len(skipped))
	}
	as := []RiskAcceptance{a}
	if err := h.markAcceptances(c, as); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"risk_acceptance": as[0], "skipped": skipped})
}

// RemoveAcceptanceFinding handles DELETE
// /projects/{id}/risk-acceptances/{aid}/findings/{fid}?reason=…: the finding
// leaves (reopening if the acceptance was approved); the ledger keeps the row.
func (h *Handler) RemoveAcceptanceFinding(c *fiber.Ctx) error {
	pid, id, err := acceptanceIDs(c)
	if err != nil {
		return err
	}
	fid, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	reason := strings.TrimSpace(c.Query("reason"))
	if len(reason) > maxAcceptanceTitle {
		return fiber.NewError(fiber.StatusBadRequest, "reason is at most 200 characters")
	}
	a, err := h.repo.RemoveAcceptanceFinding(c.UserContext(), pid, id, fid, auth.UserID(c), reason)
	if err != nil {
		return acceptanceError(err)
	}
	if a.State == AcceptanceApproved {
		h.regroup(c.UserContext(), pid, 1)
	}
	as := []RiskAcceptance{a}
	if err := h.markAcceptances(c, as); err != nil {
		return err
	}
	return c.JSON(as[0])
}

// FindingLedger handles GET /findings/{id}/risk-acceptances: every acceptance
// the finding was ever in, with when and why it joined and left.
func (h *Handler) FindingLedger(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	entries, err := h.repo.FindingLedger(c.UserContext(), id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"risk_acceptances": entries})
}

// regroup recomputes a project's cross-tool groups after statuses moved:
// status decides which findings take part in a group.
func (h *Handler) regroup(ctx context.Context, projectID string, moved int) {
	if moved == 0 {
		return
	}
	if _, err := h.repo.Deduplicate(ctx, projectID); err != nil {
		slog.WarnContext(ctx, "dedup after risk acceptance change failed", "project_id", projectID, "error", err)
	}
}

// notifyAcceptance announces (best-effort, through the outbox) an acceptance event.
func (h *Handler) notifyAcceptance(event, prefix string, a RiskAcceptance) {
	if h.notifier == nil {
		return
	}
	go h.notifier.Notify(context.Background(), AcceptanceEvent(event, prefix, a))
}

// AcceptanceEvent is the notification for a risk-acceptance event.
func AcceptanceEvent(event, prefix string, a RiskAcceptance) notify.Event {
	expires := "never"
	if a.ExpiresAt != nil {
		expires = a.ExpiresAt.Format(time.RFC3339)
	}
	fields := map[string]string{
		"acceptance_id": a.ID,
		"project":       a.ProjectName,
		"findings":      strconv.Itoa(a.FindingCount),
		"requester":     a.Requester,
		"expires":       expires,
	}
	if a.Approver != "" {
		fields["approver"] = a.Approver
	}
	if a.OwnerEmail != nil {
		fields["owner"] = *a.OwnerEmail
	}
	return notify.Event{
		Type:      event,
		Title:     prefix + ": " + a.Title,
		Text:      a.Justification,
		ProjectID: a.ProjectID,
		Fields:    fields,
	}
}
