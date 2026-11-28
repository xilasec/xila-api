package project

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/audit"
	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/projecttree"
)

// accessChecker answers "what may this user do on that project"
// (membership.Repository): moving a project needs owner on both ends.
type accessChecker interface {
	AdminStatus(ctx context.Context, userID string) (isAdmin, isOwner bool, err error)
	RoleOnProject(ctx context.Context, userID, projectID string) (domain.TeamRole, bool, error)
}

// Handler exposes project CRUD and the risk summary over HTTP.
type Handler struct {
	repo     *Repository
	findings *finding.Repository
	access   accessChecker
	// tagsChanged runs after an update that set the project's tags: component
	// policies scoped by tag re-evaluate the project (optional).
	tagsChanged func(projectID string)
}

// WithTagsChanged sets the hook run after a project's tags are updated.
func (h *Handler) WithTagsChanged(fn func(projectID string)) *Handler {
	h.tagsChanged = fn
	return h
}

// NewHandler constructs a project Handler. The finding repository backs the
// per-project risk summary; access authorizes moves in the hierarchy.
func NewHandler(repo *Repository, findings *finding.Repository, access accessChecker) *Handler {
	return &Handler{repo: repo, findings: findings, access: access}
}

// Register mounts project routes.
func (h *Handler) Register(r fiber.Router) {
	r.Post("/teams/:teamID/projects", h.Create)
	r.Get("/projects", h.List)
	r.Get("/projects/:projectID", h.Get)
	r.Patch("/projects/:projectID", h.Update)
	r.Get("/projects/:projectID/children", h.Children)
	r.Get("/projects/:projectID/summary", h.Summary)
	r.Get("/projects/:projectID/priority-weights", h.GetPriorityWeights)
	r.Put("/projects/:projectID/priority-weights", h.SetPriorityWeights)
	r.Delete("/projects/:projectID/priority-weights", h.ResetPriorityWeights)
	r.Get("/projects/:projectID/triage-carry", h.GetTriageCarry)
	r.Put("/projects/:projectID/triage-carry", h.SetTriageCarry)
	r.Get("/projects/:projectID/versions", h.ListVersions)
	r.Patch("/projects/:projectID/versions/:versionID", h.UpdateVersion)
	r.Delete("/projects/:projectID/versions/:versionID", h.DeleteVersion)
}

// isOwner reports whether the caller is owner of a project (instance admins
// are), and whether they can see it at all. An actor confined to one project
// (a project-scoped token) owns nothing else.
func (h *Handler) isOwner(c *fiber.Ctx, projectID string) (owner, visible bool, err error) {
	a := auth.CurrentActor(c)
	if a.ProjectID != "" && a.ProjectID != projectID {
		return false, false, nil
	}
	isAdmin, _, err := h.access.AdminStatus(c.UserContext(), a.UserID)
	if err != nil || isAdmin {
		return isAdmin, isAdmin, err
	}
	role, ok, err := h.access.RoleOnProject(c.UserContext(), a.UserID, projectID)
	if err != nil || !ok {
		return false, false, err
	}
	return role.AtLeast(domain.TeamOwner), true, nil
}

// checkParent authorizes placing a project under parentID: the caller must
// own the parent, since everyone with a grant on it gains the child.
func (h *Handler) checkParent(c *fiber.Ctx, parentID string) error {
	if uuid.Validate(parentID) != nil {
		return fiber.NewError(fiber.StatusBadRequest, "parent_id must be a project id")
	}
	owner, visible, err := h.isOwner(c, parentID)
	switch {
	case err != nil:
		return err
	case !visible:
		return fiber.NewError(fiber.StatusNotFound, ErrNoParent.Error())
	case !owner:
		return fiber.NewError(fiber.StatusForbidden, "requires owner on the parent project")
	}
	return nil
}

// writeStatus maps a repository write error to its HTTP status.
func writeStatus(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	case errors.Is(err, ErrDuplicate):
		return fiber.NewError(fiber.StatusConflict, "project slug already exists in team")
	case errors.Is(err, ErrNoTeam):
		return fiber.NewError(fiber.StatusNotFound, "team not found")
	case errors.Is(err, ErrNoParent):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	case errors.Is(err, ErrParentOrg), errors.Is(err, ErrCycle), errors.Is(err, ErrTooDeep):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, ErrNotEmpty):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	return err
}

type createRequest struct {
	Slug                string             `json:"slug"`
	Name                string             `json:"name"`
	Description         string             `json:"description"`
	RepoURL             string             `json:"repo_url"`
	BusinessCriticality domain.Criticality `json:"business_criticality"`
	Tags                []string           `json:"tags"`
	ParentID            *string            `json:"parent_id"`
	IsCollection        bool               `json:"is_collection"`
}

func (h *Handler) Create(c *fiber.Ctx) error {
	teamID, err := httpx.ID(c, "teamID")
	if err != nil {
		return err
	}
	var body createRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	body.Slug = strings.TrimSpace(body.Slug)
	body.Name = strings.TrimSpace(body.Name)
	if body.Slug == "" || body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "slug and name are required")
	}
	if body.BusinessCriticality == "" {
		body.BusinessCriticality = domain.CriticalityMedium
	}
	if !body.BusinessCriticality.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "invalid business_criticality")
	}
	if body.Tags == nil {
		body.Tags = []string{}
	}
	if body.ParentID != nil && *body.ParentID == "" {
		body.ParentID = nil
	}
	if body.ParentID != nil {
		if err := h.checkParent(c, *body.ParentID); err != nil {
			return err
		}
	}

	p, err := h.repo.Create(c.UserContext(), Project{
		TeamID:              teamID,
		ParentID:            body.ParentID,
		IsCollection:        body.IsCollection,
		Slug:                body.Slug,
		Name:                body.Name,
		Description:         body.Description,
		RepoURL:             body.RepoURL,
		BusinessCriticality: body.BusinessCriticality,
		Tags:                body.Tags,
	})
	if err != nil {
		return writeStatus(err)
	}
	return c.Status(fiber.StatusCreated).JSON(p)
}

func (h *Handler) List(c *fiber.Ctx) error {
	// Optional ?team_id= filter for the portfolio view.
	teamID := c.Query("team_id")
	var scope []string
	if s := authz.VisibleScope(c); !s.AllAccess {
		// Scope by *project* ids, not team ids: a direct grant on one project is
		// access without team membership, and it has to be visible here too.
		scope = s.ProjectIDs
	}
	// ?archived=true lists the archived projects (authz narrows the scope to
	// the ones the caller owns).
	custom, err := customfield.ParseFilters(c.Queries())
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	projects, err := h.repo.List(c.UserContext(), teamID, scope, custom, c.QueryBool("archived"))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"projects": projects})
}

func (h *Handler) Get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	p, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(p)
}

type updateRequest struct {
	Name                *string             `json:"name"`
	Description         *string             `json:"description"`
	RepoURL             *string             `json:"repo_url"`
	BusinessCriticality *domain.Criticality `json:"business_criticality"`
	Tags                []string            `json:"tags"`
	AITriageOptOut      *bool               `json:"ai_triage_opt_out"`
	// AssessmentApproval overrides ASSESSMENT_REQUIRES_APPROVAL for this
	// project (inherit/required/off; M13 13.9).
	AssessmentApproval *domain.ApprovalSetting `json:"assessment_approval"`
	// ParentID distinguishes absent (leave alone) from null (make it a root).
	ParentID     json.RawMessage `json:"parent_id"`
	IsCollection *bool           `json:"is_collection"`
}

func (h *Handler) Update(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var body updateRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	if body.BusinessCriticality != nil && !body.BusinessCriticality.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "invalid business_criticality")
	}
	if body.AssessmentApproval != nil && !body.AssessmentApproval.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "invalid assessment_approval")
	}
	fields := UpdateFields{
		Name:                body.Name,
		Description:         body.Description,
		RepoURL:             body.RepoURL,
		BusinessCriticality: body.BusinessCriticality,
		Tags:                body.Tags,
		AITriageOptOut:      body.AITriageOptOut,
		AssessmentApproval:  body.AssessmentApproval,
		IsCollection:        body.IsCollection,
	}
	if len(body.ParentID) > 0 {
		// Moving a project changes who can reach it: owner on the project, and
		// on the new parent, whose grants it will inherit.
		if err := json.Unmarshal(body.ParentID, &fields.ParentID); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "parent_id must be a project id or null")
		}
		if fields.ParentID != nil && *fields.ParentID == "" {
			fields.ParentID = nil
		}
		fields.SetParent = true
		if owner, _, err := h.isOwner(c, id); err != nil {
			return err
		} else if !owner {
			return fiber.NewError(fiber.StatusForbidden, "moving a project requires owner on it")
		}
		if fields.ParentID != nil {
			if err := h.checkParent(c, *fields.ParentID); err != nil {
				return err
			}
		}
	}

	p, err := h.repo.Update(c.UserContext(), id, fields)
	if err != nil {
		return writeStatus(err)
	}
	if body.Tags != nil && h.tagsChanged != nil {
		h.tagsChanged(p.ID)
	}
	return c.JSON(p)
}

// Children handles GET /projects/{id}/children: the direct children. Anyone
// who can read a project can read its whole subtree (grants inherit down).
func (h *Handler) Children(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	children, err := h.repo.Children(c.UserContext(), id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"projects": children})
}

// Summary is the persona-facing rollup: severity/status breakdowns and a
// business-weighted risk score. Executives read the score, PMs the open counts,
// developers drill into the findings list. With children included it covers
// ProjectIDs — the project and its descendants — each weighted by its own
// criticality.
type Summary struct {
	ProjectID  string                       `json:"project_id"`
	ProjectIDs []string                     `json:"project_ids"`
	RiskScore  float64                      `json:"risk_score"`
	TotalOpen  int                          `json:"total_open"`
	Total      int                          `json:"total"`
	BySeverity map[domain.Severity]int      `json:"open_by_severity"`
	ByStatus   map[domain.FindingStatus]int `json:"by_status"`
	// SLA is the project's posture against its remediation deadlines.
	SLA finding.SLAStats `json:"sla"`
}

func (h *Handler) Summary(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	if _, err := h.repo.Get(c.UserContext(), id); errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	} else if err != nil {
		return err
	}
	ids, err := projecttree.Rollup(c, h.repo.db, id)
	if err != nil {
		return err
	}

	counts, err := h.findings.CountByProjects(c.UserContext(), ids)
	if err != nil {
		return err
	}

	slaStats, err := h.findings.SLAStats(c.UserContext(), ids)
	if err != nil {
		return err
	}

	summary := computeSummary(id, counts)
	summary.ProjectIDs = ids
	summary.SLA = slaStats
	return c.JSON(summary)
}

// computeSummary rolls per (status, severity, criticality) counts into the
// persona-facing summary. Kept pure (no I/O) so it can be unit-tested directly.
func computeSummary(projectID string, counts []finding.StatusSeverityCount) Summary {
	summary := Summary{
		ProjectID:  projectID,
		BySeverity: map[domain.Severity]int{},
		ByStatus:   map[domain.FindingStatus]int{},
	}
	for _, cnt := range counts {
		summary.Total += cnt.Count
		summary.ByStatus[cnt.Status] += cnt.Count
		if cnt.Status.CountsRisk() {
			summary.TotalOpen += cnt.Count
			summary.BySeverity[cnt.Severity] += cnt.Count
			summary.RiskScore += cnt.Severity.Weight() * float64(cnt.Count) * cnt.Criticality.Multiplier()
		}
	}
	return summary
}

// weightsResponse is what a project's priority weights resolve to, whether
// they are the project's own, and the defaults to compare with.
func weightsResponse(raw []byte) fiber.Map {
	return fiber.Map{"weights": domain.WeightsFromJSON(raw), "custom": len(raw) > 0 && string(raw) != "null",
		"defaults": domain.DefaultWeights}
}

// GetPriorityWeights handles GET /projects/{id}/priority-weights.
func (h *Handler) GetPriorityWeights(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	raw, err := h.repo.PriorityWeights(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(weightsResponse(raw))
}

// SetPriorityWeights handles PUT /projects/{id}/priority-weights (owner): the
// factors to override (fields left out keep their default). It recomputes the
// project's priorities and regroups its findings, since priority elects a
// dedup group's primary.
func (h *Handler) SetPriorityWeights(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	w := domain.DefaultWeights
	dec := json.NewDecoder(bytes.NewReader(c.Body()))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&w); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid priority weights: "+err.Error())
	}
	if err := w.Validate(); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	raw, err := json.Marshal(w)
	if err != nil {
		return err
	}
	return h.storeWeights(c, id, raw)
}

// ResetPriorityWeights handles DELETE /projects/{id}/priority-weights: back
// to the defaults.
func (h *Handler) ResetPriorityWeights(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	return h.storeWeights(c, id, nil)
}

func (h *Handler) storeWeights(c *fiber.Ctx, id string, raw []byte) error {
	ctx := c.UserContext()
	before, err := h.repo.PriorityWeights(ctx, id)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	}
	if err != nil {
		return err
	}
	if err := h.repo.SetPriorityWeights(ctx, id, raw); err != nil {
		return err
	}
	audit.SetChanges(c, weightsResponse(before)["weights"], weightsResponse(raw)["weights"])
	moved, n, err := h.findings.Reprioritize(ctx, finding.PriorityScope{ProjectID: id})
	if err != nil {
		return err
	}
	if len(moved) > 0 {
		if _, err := h.findings.Deduplicate(ctx, id); err != nil {
			return fmt.Errorf("regroup after new priority weights: %w", err)
		}
	}
	out := weightsResponse(raw)
	out["reprioritized"] = n
	return c.JSON(out)
}

// triageCarrySettings is a project's triage-carry configuration (M13 13.1):
// opt-in carrying of a manual false_positive / wont_fix / reopen decision to
// the project's other versions. BranchRegex scopes which versions receive and
// share decisions; empty means every version. See internal/triagecarry and
// CLAUDE.md's "Carry triage across branches" note.
type triageCarrySettings struct {
	Enabled     bool   `json:"enabled"`
	BranchRegex string `json:"branch_regex"`
}

// GetTriageCarry handles GET /projects/{id}/triage-carry.
func (h *Handler) GetTriageCarry(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	enabled, branchRegex, err := h.repo.TriageCarrySettings(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(triageCarrySettings{Enabled: enabled, BranchRegex: branchRegex})
}

// SetTriageCarry handles PUT /projects/{id}/triage-carry.
func (h *Handler) SetTriageCarry(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var body triageCarrySettings
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	if body.BranchRegex != "" {
		if _, err := regexp.Compile(body.BranchRegex); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid branch_regex: "+err.Error())
		}
	}
	if err := h.repo.SetTriageCarrySettings(c.UserContext(), id, body.Enabled, body.BranchRegex); err != nil {
		if errors.Is(err, ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "project not found")
		}
		return err
	}
	return c.JSON(body)
}
