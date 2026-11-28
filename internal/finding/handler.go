package finding

import (
	"cmp"
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/projecttree"
)

// Notifier delivers events (e.g. when a risk is accepted). Optional.
type Notifier interface {
	Notify(ctx context.Context, e notify.Event)
}

// Handler exposes finding listing and triage over HTTP.
type Handler struct {
	repo     *Repository
	notifier Notifier // optional
	access   accessChecker
	// requireApproval (ASSESSMENT_REQUIRES_APPROVAL) turns manual status /
	// severity changes into pending assessments a second person approves.
	requireApproval bool
	// acceptanceApproval (RISK_ACCEPTANCE_REQUIRES_APPROVAL): a risk
	// acceptance's requester can't decide it.
	acceptanceApproval bool
	// customFields lists the finding custom fields an export adds a column for
	// (optional: nil = none).
	customFields customFieldLister
	// comments is told about every comment a person posts (optional).
	comments CommentListener
}

// CommentListener is told when a person comments on a finding, after the
// comment is stored (issuetracker.Service pushes it to the linked issue). It
// runs detached from the request: it must bound its own work.
type CommentListener interface {
	CommentAdded(ctx context.Context, findingID string)
}

// WithCommentListener registers l for new comments.
func (h *Handler) WithCommentListener(l CommentListener) *Handler {
	h.comments = l
	return h
}

// customFieldLister lists custom-field definitions (customfield.Repository).
type customFieldLister interface {
	List(ctx context.Context, entity customfield.Entity) ([]customfield.Definition, error)
}

// WithCustomFields makes exports carry one column per finding custom field.
func (h *Handler) WithCustomFields(defs customFieldLister) *Handler {
	h.customFields = defs
	return h
}

// NewHandler constructs a finding Handler. notifier may be nil.
func NewHandler(repo *Repository, notifier Notifier, access accessChecker, requireApproval bool) *Handler {
	return &Handler{repo: repo, notifier: notifier, access: access, requireApproval: requireApproval}
}

// Register mounts finding routes. authz resolves /findings/{id}/… to the
// finding's project (reads need viewer, writes editor); /findings/bulk spans
// projects and is authorized per finding in the handler.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/findings", h.ListAll)
	r.Get("/findings/export", h.ExportAll)
	r.Get("/projects/:projectID/findings", h.List)
	r.Get("/projects/:projectID/findings/export", h.Export)
	r.Get("/assets/:assetID/findings", h.ListByAsset)
	r.Post("/findings/expire-exceptions", h.ExpireExceptions)
	r.Post("/findings/bulk", h.Bulk)
	r.Get("/findings/expiring", h.ListExpiring)
	r.Get("/findings/tags", h.Tags)
	r.Get("/findings/:findingID", h.Get)
	r.Patch("/findings/:findingID", h.UpdateStatus)
	r.Put("/findings/:findingID/assignee", h.Assign)
	r.Put("/findings/:findingID/tags", h.SetTags)
	r.Patch("/findings/:findingID/details", h.UpdateDetails)
	r.Patch("/findings/:findingID/fields", h.EditFields)
	r.Get("/findings/:findingID/history", h.History)
	r.Get("/findings/:findingID/comments", h.ListComments)
	r.Post("/findings/:findingID/comments", h.AddComment)
	r.Delete("/findings/:findingID/comments/:commentID", h.DeleteComment)
	r.Get("/findings/:findingID/attachments", h.ListAttachments)
	r.Post("/findings/:findingID/attachments", h.AddAttachment)
	r.Get("/findings/:findingID/attachments/:attachmentID", h.DownloadAttachment)
	r.Delete("/findings/:findingID/attachments/:attachmentID", h.DeleteAttachment)
	r.Get("/findings/:findingID/exceptions", h.ListExceptions)
	r.Get("/findings/:findingID/duplicates", h.ListDuplicates)
	r.Post("/findings/:findingID/duplicate-of", h.MarkDuplicate)
	r.Delete("/findings/:findingID/duplicate-of", h.UnmarkDuplicate)
	r.Get("/findings/:findingID/assessments", h.ListFindingAssessments)
	r.Get("/assessments", h.ListAssessments)
	r.Post("/assessments/approve", h.BulkApproveAssessments)
	r.Post("/assessments/reject", h.BulkRejectAssessments)
	r.Post("/assessments/:assessmentID/approve", h.ApproveAssessment)
	r.Post("/assessments/:assessmentID/reject", h.RejectAssessment)
	r.Get("/projects/:projectID/assessment-approvers", h.ListApprovers)
	r.Put("/projects/:projectID/assessment-approvers", h.SetApprovers)
	h.registerAcceptances(r)
}

// List handles GET /projects/{id}/findings (optionally ?asset_id= too).
func (h *Handler) List(c *fiber.Ctx) error {
	filter, err := h.projectFilter(c)
	if err != nil {
		return err
	}
	return h.respondList(c, filter)
}

// ListAll handles GET /findings — the cross-project triage inbox. Supports the
// shared filters plus ?project_id= and ?scanner=/?kev=.
func (h *Handler) ListAll(c *fiber.Ctx) error {
	filter, err := portfolioFilter(c)
	if err != nil {
		return err
	}
	return h.respondList(c, filter)
}

// projectFilter is the filter of GET /projects/{id}/findings (and its export):
// the shared parameters within the project — or, with children included (see
// projecttree.Rollup), within it and its descendants — plus ?asset_id= and
// ?branch=.
func (h *Handler) projectFilter(c *fiber.Ctx) (Filter, error) {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return Filter{}, err
	}
	filter, err := queryFilter(c)
	if err != nil {
		return Filter{}, err
	}
	ids, err := projecttree.Rollup(c, h.repo.db, projectID)
	if err != nil {
		return Filter{}, err
	}
	if len(ids) > 1 {
		filter.ProjectIDs = ids
	} else {
		filter.ProjectID = projectID
	}
	filter.AssetID = c.Query("asset_id")
	filter.VersionName = c.Query("branch") // by name: only meaningful within one project
	return filter, nil
}

// portfolioFilter is the filter of GET /findings (and its export): the shared
// parameters plus ?project_id= and ?asset_id=, restricted to the actor's
// visible projects.
func portfolioFilter(c *fiber.Ctx) (Filter, error) {
	filter, err := queryFilter(c)
	if err != nil {
		return Filter{}, err
	}
	filter.ProjectID = c.Query("project_id")
	filter.AssetID = c.Query("asset_id")
	if scope := authz.VisibleScope(c); !scope.AllAccess {
		filter.ProjectIDs = scope.ProjectIDs // RBAC: restrict to the actor's projects
	}
	return filter, nil
}

// ListByAsset handles GET /assets/{id}/findings.
func (h *Handler) ListByAsset(c *fiber.Ctx) error {
	assetID, err := httpx.ID(c, "assetID")
	if err != nil {
		return err
	}
	filter, err := queryFilter(c)
	if err != nil {
		return err
	}
	filter.AssetID = assetID
	return h.respondList(c, filter)
}

// queryFilter reads the shared finding query parameters and validates enums.
func queryFilter(c *fiber.Ctx) (Filter, error) {
	return filterFrom(c.Queries(), auth.UserID(c))
}

// filterFrom builds a Filter from the shared finding parameters, however they
// arrive (a query string, or a bulk edit's "filter" object). userID resolves
// assignee=me; cf.<key>[.op] parameters filter on custom fields.
func filterFrom(params map[string]string, userID string) (Filter, error) {
	get := func(k string) string { return params[k] }
	flag := func(k string) bool { b, _ := strconv.ParseBool(get(k)); return b }
	filter := Filter{
		Status:            domain.FindingStatus(get("status")),
		Severity:          domain.Severity(get("severity")),
		Category:          domain.Category(get("category")),
		Scanner:           get("scanner"),
		RuleID:            get("rule_id"),
		KEVOnly:           flag("kev"),
		MaliciousOnly:     flag("malicious"),
		RansomwareOnly:    flag("kev_ransomware"),
		OpenOnly:          flag("active"),
		ScanID:            get("scan_id"),
		EngagementID:      get("engagement_id"),
		Exploit:           get("exploit"),
		VersionID:         get("version_id"),
		AllVersions:       flag("all_versions"),
		NewOnly:           flag("new"),
		ReachableOnly:     flag("reachable"),
		DirectOnly:        flag("direct"),
		Scope:             domain.DepScope(get("scope")),
		SLA:               domain.SLAStatus(get("sla")),
		IncludeDuplicates: flag("include_duplicates"),
		FailsGate:         flag("fails_gate"),
		Archived:          flag("archived"),
		Sort:              get("sort"),
		Query:             strings.TrimSpace(get("q")),
	}
	if t := get("tag"); t != "" {
		tags, err := NormalizeTags(strings.Split(t, ","))
		if err != nil {
			return Filter{}, fiber.NewError(fiber.StatusBadRequest, err.Error())
		}
		filter.Tags = tags
	}
	custom, err := customfield.ParseFilters(params)
	if err != nil {
		return Filter{}, fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	filter.Custom = custom
	if len(filter.Query) > 500 {
		return Filter{}, fiber.NewError(fiber.StatusBadRequest, "q is at most 500 characters")
	}
	if filter.Status != "" && !filter.Status.Valid() {
		return Filter{}, fiber.NewError(fiber.StatusBadRequest, "invalid status filter")
	}
	if filter.Severity != "" && !filter.Severity.Valid() {
		return Filter{}, fiber.NewError(fiber.StatusBadRequest, "invalid severity filter")
	}
	if filter.Category != "" && !filter.Category.Valid() {
		return Filter{}, fiber.NewError(fiber.StatusBadRequest, "invalid category filter")
	}
	if filter.SLA != "" && !filter.SLA.Valid() {
		return Filter{}, fiber.NewError(fiber.StatusBadRequest, "invalid sla filter")
	}
	if filter.VersionID != "" && uuid.Validate(filter.VersionID) != nil {
		return Filter{}, fiber.NewError(fiber.StatusBadRequest, "invalid version_id")
	}
	switch filter.Exploit {
	case "", "any", "poc", "weaponized":
	default:
		return Filter{}, fiber.NewError(fiber.StatusBadRequest, "exploit must be any, poc or weaponized")
	}
	if filter.EngagementID != "" && uuid.Validate(filter.EngagementID) != nil {
		return Filter{}, fiber.NewError(fiber.StatusBadRequest, "invalid engagement_id")
	}
	switch a := get("assignee"); a {
	case "":
	case "none":
		filter.Unassigned = true
	case "me":
		filter.AssigneeID = userID
	default:
		if uuid.Validate(a) != nil {
			return Filter{}, fiber.NewError(fiber.StatusBadRequest, "assignee must be me, none or a user id")
		}
		filter.AssigneeID = a
	}
	return filter, nil
}

func (h *Handler) respondList(c *fiber.Ctx, filter Filter) error {
	page := httpx.ParsePage(c)
	filter.Limit = page.Limit + 1 // fetch one extra to detect a next page
	filter.Offset = page.Offset

	findings, err := h.repo.List(c.UserContext(), filter)
	if err != nil {
		return err
	}
	hasMore := len(findings) > page.Limit
	if hasMore {
		findings = findings[:page.Limit]
	}
	// Badge each row with how many other tools reported the same issue.
	ids := make([]string, len(findings))
	for i := range findings {
		ids[i] = findings[i].ID
	}
	if counts, err := h.repo.DuplicateCounts(c.UserContext(), ids); err == nil {
		for i := range findings {
			findings[i].DuplicateCount = counts[findings[i].ID]
		}
	}
	return c.JSON(fiber.Map{"findings": findings, "pagination": httpx.Meta(page, len(findings), hasMore)})
}

// Get handles GET /findings/{id}.
func (h *Handler) Get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	f, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "finding not found")
	}
	if err != nil {
		return err
	}
	if f.FilePath != "" {
		repo, commit, branch, err := h.repo.SourceRef(c.UserContext(), id)
		if err != nil {
			return err
		}
		if u, ok := SourceURL(repo, cmp.Or(commit, branch), f.FilePath, f.Line); ok {
			f.SourceURL = &u
		}
	}
	return c.JSON(f)
}

type updateStatusRequest struct {
	Status    domain.FindingStatus `json:"status"`
	Reason    string               `json:"reason"`
	ExpiresAt *time.Time           `json:"expires_at"`
	// VexJustification / VexResponse: the structured analysis accompanying a
	// move to false_positive or wont_fix (M13 13.2); ignored for any other
	// status.
	VexJustification domain.VexJustification `json:"vex_justification"`
	VexResponse      []domain.VexResponse    `json:"vex_response"`
	// Title names the risk acceptance requested by status risk_accepted.
	Title string `json:"title"`
}

// UpdateStatus handles PATCH /findings/{id} to triage a finding. With
// ASSESSMENT_REQUIRES_APPROVAL the change is held as a pending assessment
// instead (202), and applies only once a different owner approves it.
// status risk_accepted requests a risk acceptance of the finding instead
// (202 + the acceptance): it only becomes risk_accepted once that is approved.
func (h *Handler) UpdateStatus(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	if done, err := h.precondition(c, id); done || err != nil {
		return err
	}
	var body updateStatusRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	if !body.Status.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "invalid status")
	}
	if !body.VexJustification.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "invalid vex_justification")
	}
	if !domain.ValidVexResponses(body.VexResponse) {
		return fiber.NewError(fiber.StatusBadRequest, "invalid vex_response")
	}
	if body.Status == domain.FindingRiskAccepted {
		return h.requestAcceptance(c, id, body)
	}

	cur, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "finding not found")
	}
	if err != nil {
		return err
	}
	required, err := h.approvalRequired(c.UserContext(), cur.ProjectID)
	if err != nil {
		return err
	}
	if required {
		// Re-stating the current non-exception status changes nothing; anything
		// else (a new status, or an exception's reason / expiry / analysis) is
		// reviewed.
		if cur.Status != body.Status || isExceptionStatus(body.Status) {
			a, err := h.repo.RequestAssessment(c.UserContext(), id, Change{
				Status: &body.Status, Reason: body.Reason, ExpiresAt: body.ExpiresAt,
				VexJustification: body.VexJustification, VexResponse: body.VexResponse,
			}, auth.UserID(c))
			switch {
			case errors.Is(err, ErrNotFound):
				return fiber.NewError(fiber.StatusNotFound, "finding not found")
			case errors.Is(err, ErrAssessmentPending):
				return fiber.NewError(fiber.StatusConflict, err.Error())
			case err != nil:
				return err
			}
			return c.Status(fiber.StatusAccepted).JSON(a)
		}
	}

	f, err := h.repo.SetStatusManual(c.UserContext(), id, Triage{
		Status:           body.Status,
		Reason:           body.Reason,
		Actor:            auth.UserID(c),
		ExpiresAt:        body.ExpiresAt,
		VexJustification: body.VexJustification,
		VexResponse:      body.VexResponse,
	})
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "finding not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(f)
}

// requestAcceptance is PATCH status=risk_accepted: one requested acceptance
// of the finding, titled body.Title (derived when empty), justified by
// body.Reason.
func (h *Handler) requestAcceptance(c *fiber.Ctx, id string, body updateStatusRequest) error {
	if strings.TrimSpace(body.Reason) == "" {
		return fiber.NewError(fiber.StatusBadRequest, "accepting a risk needs a reason")
	}
	if body.ExpiresAt != nil && !body.ExpiresAt.After(time.Now()) {
		return fiber.NewError(fiber.StatusBadRequest, "expires_at must be in the future")
	}
	created, busy, err := h.repo.RequestAcceptances(c.UserContext(), []string{id}, AcceptanceInput{
		Title: strings.TrimSpace(body.Title), Justification: body.Reason, ExpiresAt: body.ExpiresAt,
	}, auth.UserID(c))
	switch {
	case err != nil:
		return err
	case len(created) == 1:
		h.notifyAcceptance(notify.EventRiskAcceptanceRequested, "Risk acceptance requested", created[0])
		return c.Status(fiber.StatusAccepted).JSON(created[0])
	case len(busy) == 1:
		return fiber.NewError(fiber.StatusConflict, "the finding is already in a risk acceptance, or isn't open")
	}
	return fiber.NewError(fiber.StatusNotFound, "finding not found")
}

// ListExpiring handles GET /findings/expiring?days=30 — acceptances lapsing soon.
func (h *Handler) ListExpiring(c *fiber.Ctx) error {
	days, _ := strconv.Atoi(c.Query("days"))
	if days <= 0 {
		days = 30
	}
	var pids []string
	if scope := authz.VisibleScope(c); !scope.AllAccess {
		pids = scope.ProjectIDs
	}
	findings, err := h.repo.ListExpiring(c.UserContext(), days, pids)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"findings": findings, "days": days})
}

// ListDuplicates handles GET /findings/{id}/duplicates — the other scanners'
// reports of the same issue, collapsed under this primary.
func (h *Handler) ListDuplicates(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	dups, err := h.repo.ListDuplicatesOf(c.UserContext(), id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"duplicates": dups})
}

type duplicateOfRequest struct {
	PrimaryID string `json:"primary_id"`
}

// MarkDuplicate handles POST /findings/{id}/duplicate-of: a person says this
// finding is the same issue as primary_id (same project and version).
// Automatic dedup (Repository.Deduplicate) never rewrites the decision.
func (h *Handler) MarkDuplicate(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	var body duplicateOfRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	if _, err := uuid.Parse(body.PrimaryID); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "primary_id is required")
	}
	f, err := h.repo.MarkDuplicateManual(c.UserContext(), id, body.PrimaryID, auth.UserID(c))
	switch {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "finding not found")
	case errors.Is(err, ErrSelfDuplicate), errors.Is(err, ErrDuplicateScope), errors.Is(err, ErrDuplicateChain):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case err != nil:
		return err
	}
	return c.JSON(f)
}

// UnmarkDuplicate handles DELETE /findings/{id}/duplicate-of.
func (h *Handler) UnmarkDuplicate(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	f, err := h.repo.UnmarkDuplicateManual(c.UserContext(), id, auth.UserID(c))
	switch {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "finding not found")
	case errors.Is(err, ErrNotManualDuplicate):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case err != nil:
		return err
	}
	return c.JSON(f)
}

// ListExceptions handles GET /findings/{id}/exceptions (audit history).
func (h *Handler) ListExceptions(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	exceptions, err := h.repo.ListExceptions(c.UserContext(), id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"exceptions": exceptions})
}

// ExpireExceptions handles POST /findings/expire-exceptions: reopen findings
// whose risk acceptance has lapsed. Also run periodically in the background.
func (h *Handler) ExpireExceptions(c *fiber.Ctx) error {
	n, err := h.repo.ExpireExceptions(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"expired": n})
}
