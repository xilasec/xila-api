package gate

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/ingesthealth"
)

// statsProvider yields the live gate aggregates for a project version
// (finding.Repository). An empty versionID means the default version; an empty
// baselineVersionID means no baseline comparison.
type statsProvider interface {
	ComputeGateStats(ctx context.Context, projectID, versionID string, newOnly bool, baselineVersionID string) (finding.GateStats, error)
}

// versionFinder looks a project version up by name (project.Repository).
type versionFinder interface {
	FindVersion(ctx context.Context, projectID, name string) (string, bool, error)
}

// expectationChecker finds declared scan expectations with no completed scan
// within their window (internal/ingesthealth.Repository).
type expectationChecker interface {
	Check(ctx context.Context, scope []string, now time.Time) ([]ingesthealth.Anomaly, error)
}

// Handler exposes gate evaluation + policy management.
type Handler struct {
	policies     *Repository
	stats        statsProvider
	versions     versionFinder
	expectations expectationChecker
}

// NewHandler constructs a gate Handler.
func NewHandler(policies *Repository, stats statsProvider, versions versionFinder, expectations expectationChecker) *Handler {
	return &Handler{policies: policies, stats: stats, versions: versions, expectations: expectations}
}

// Register mounts the routes. Project routes are team-gated by authz (eval/PUT
// need editor, GET needs viewer); the global policy is admin-only.
func (h *Handler) Register(r fiber.Router) {
	r.Post("/projects/:projectID/gate", h.Evaluate)
	r.Get("/projects/:projectID/gate/status", h.Status)
	r.Get("/projects/:projectID/gate/policy", h.GetProjectPolicy)
	r.Put("/projects/:projectID/gate/policy", h.SetProjectPolicy)
	r.Delete("/projects/:projectID/gate/policy", h.DeleteProjectPolicy)
	r.Get("/gate/policy", h.GetGlobalPolicy)
	r.Put("/gate/policy", h.SetGlobalPolicy)
}

type evaluateRequest struct {
	// Policy, if set, overrides the stored policy for this evaluation only (handy
	// for CI: gate with ad-hoc thresholds without persisting them).
	Policy *Policy `json:"policy"`
	// NewOnly, if set, overrides the policy's new_only for this run — so CI can
	// switch a stored policy between "total" and "new" without losing thresholds.
	NewOnly *bool `json:"new_only"`
}

// missingExpectations is the expected-scans part of a gate run: the scans a
// policy with RequireExpectedScans counts as missing. One definition for the
// on-demand endpoint and the stored state (Evaluator), so they can't disagree.
func missingExpectations(ctx context.Context, checker expectationChecker, projectID string, policy Policy) ([]string, error) {
	if !policy.RequireExpectedScans || checker == nil {
		return nil, nil
	}
	anomalies, err := checker.Check(ctx, []string{projectID}, time.Now())
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, a := range anomalies {
		if a.Kind == ingesthealth.KindMissing {
			missing = append(missing, a.Detail)
		}
	}
	return missing, nil
}

// Evaluate runs the gate for a project. Returns 200 when it passes, 422 when it
// fails — both with the full result — so plain `curl --fail-with-body` works and
// a CLI can read the body.
func (h *Handler) Evaluate(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var body evaluateRequest
	if len(c.Body()) > 0 {
		if err := httpx.Parse(c, &body); err != nil {
			return err
		}
	}

	var (
		policy Policy
		scope  string
	)
	if body.Policy != nil {
		if err := validatePolicy(*body.Policy); err != nil {
			return err
		}
		policy, scope = *body.Policy, "inline"
	} else if policy, scope, err = h.policies.Effective(c.UserContext(), projectID); err != nil {
		return err
	}

	newOnly := policy.NewOnly
	if body.NewOnly != nil {
		newOnly = *body.NewOnly
	}
	versionID, err := h.version(c, projectID)
	if err != nil {
		return err
	}
	baselineName, baselineVersionID, err := h.baseline(c, projectID, policy)
	if err != nil {
		return err
	}
	stats, err := h.stats.ComputeGateStats(c.UserContext(), projectID, versionID, newOnly, baselineVersionID)
	if err != nil {
		return err
	}

	missing, err := missingExpectations(c.UserContext(), h.expectations, projectID, policy)
	if err != nil {
		return err
	}
	result := Evaluate(policy, stats, missing)
	result.Scope = scope
	result.VersionID = versionID
	result.NewOnly = newOnly
	result.Baseline = baselineName
	status := fiber.StatusOK
	if !result.Passed {
		status = fiber.StatusUnprocessableEntity
	}
	return c.Status(status).JSON(result)
}

// statusResponse is GET /projects/{id}/gate/status: the stored result from
// the last re-evaluation (ingest, enrichment/exploit/KEV sweep, or leader
// interval), not a fresh run — see Evaluator. Evaluated is false for a
// project that hasn't been evaluated yet (no scans/SBOMs, or not reached by
// a sweep yet).
type statusResponse struct {
	Evaluated   bool        `json:"evaluated"`
	Passed      bool        `json:"passed"`
	Violations  []Violation `json:"violations"`
	VersionID   string      `json:"version_id,omitempty"`
	EvaluatedAt *time.Time  `json:"evaluated_at,omitempty"`
}

// Status handles GET /projects/{id}/gate/status: the project's currently
// stored gate result, read straight from project_gate_state (no
// re-evaluation). Same version resolution as Evaluate (?version_id=,
// ?branch=, ?release=, else the default version).
func (h *Handler) Status(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	versionID, err := h.version(c, projectID)
	if err != nil {
		return err
	}
	st, ok, err := h.policies.GetState(c.UserContext(), projectID, versionID)
	if err != nil {
		return err
	}
	if !ok {
		return c.JSON(statusResponse{Evaluated: false})
	}
	return c.JSON(statusResponse{
		Evaluated: true, Passed: st.Passed, Violations: st.Violations,
		VersionID: st.VersionID, EvaluatedAt: &st.EvaluatedAt,
	})
}

// version resolves which project version a gate evaluates: ?version_id=, or
// ?branch= / ?release= by name, or (none given) the default version. A named
// version that doesn't exist is a 404 — a CI job gating a branch it never
// uploaded to must fail loudly, not pass against an empty backlog.
func (h *Handler) version(c *fiber.Ctx, projectID string) (string, error) {
	if id := c.Query("version_id"); id != "" {
		return id, nil
	}
	name := strings.TrimSpace(c.Query("branch"))
	if r := strings.TrimSpace(c.Query("release")); r != "" {
		if name != "" {
			return "", fiber.NewError(fiber.StatusBadRequest, "give branch or release, not both")
		}
		name = r
	}
	if name == "" {
		return "", nil
	}
	return h.resolveNamedVersion(c, projectID, name)
}

// baseline resolves the name and id of the baseline version to compare "new"
// findings against: ?baseline= overrides the policy's stored baseline_branch; no
// baseline resolved from either returns ("", "", nil). An unknown name is a 404,
// same as a missing gate target — a misconfigured or mistyped baseline must
// never silently fall back to "no baseline" and pass.
func (h *Handler) baseline(c *fiber.Ctx, projectID string, policy Policy) (string, string, error) {
	name := strings.TrimSpace(c.Query("baseline"))
	if name == "" && policy.BaselineBranch != nil {
		name = strings.TrimSpace(*policy.BaselineBranch)
	}
	if name == "" {
		return "", "", nil
	}
	id, err := h.resolveNamedVersion(c, projectID, name)
	if err != nil {
		return "", "", err
	}
	return name, id, nil
}

// resolveNamedVersion looks a branch/release name up to its version id. A name
// with no scans or SBOMs uploaded is a 404.
func (h *Handler) resolveNamedVersion(c *fiber.Ctx, projectID, name string) (string, error) {
	id, ok, err := h.versions.FindVersion(c.UserContext(), projectID, name)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fiber.NewError(fiber.StatusNotFound, "no scans or SBOMs uploaded for "+name+" yet")
	}
	return id, nil
}

// GetProjectPolicy returns the policy in effect for a project (its own or the
// inherited global), with the scope.
func (h *Handler) GetProjectPolicy(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	policy, scope, err := h.policies.Effective(c.UserContext(), projectID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"policy": policy, "scope": scope})
}

// SetProjectPolicy stores a project's gate policy.
func (h *Handler) SetProjectPolicy(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	return h.upsert(c, &projectID)
}

// DeleteProjectPolicy removes a project's policy (it then inherits the global).
func (h *Handler) DeleteProjectPolicy(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	if err := h.policies.Delete(c.UserContext(), &projectID); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// GetGlobalPolicy returns the global default policy (admin).
func (h *Handler) GetGlobalPolicy(c *fiber.Ctx) error {
	policy, ok, err := h.policies.Get(c.UserContext(), nil)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"policy": policy, "exists": ok})
}

// SetGlobalPolicy stores the global default policy (admin).
func (h *Handler) SetGlobalPolicy(c *fiber.Ctx) error {
	return h.upsert(c, nil)
}

func (h *Handler) upsert(c *fiber.Ctx, projectID *string) error {
	var policy Policy
	if err := httpx.Parse(c, &policy); err != nil {
		return err
	}
	if err := validatePolicy(policy); err != nil {
		return err
	}
	policy.ProjectID = projectID
	out, err := h.policies.Upsert(c.UserContext(), policy)
	if errors.Is(err, ErrNoProject) {
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(out)
}

func validatePolicy(p Policy) error {
	if p.MaxCritical != nil && *p.MaxCritical < 0 {
		return fiber.NewError(fiber.StatusBadRequest, "max_critical must be ≥ 0")
	}
	if p.MaxHigh != nil && *p.MaxHigh < 0 {
		return fiber.NewError(fiber.StatusBadRequest, "max_high must be ≥ 0")
	}
	for name, v := range map[string]*int{"max_medium": p.MaxMedium, "max_low": p.MaxLow, "max_info": p.MaxInfo} {
		if v != nil && *v < 0 {
			return fiber.NewError(fiber.StatusBadRequest, name+" must be ≥ 0")
		}
	}
	if p.MaxEPSS != nil && (*p.MaxEPSS < 0 || *p.MaxEPSS > 1) {
		return fiber.NewError(fiber.StatusBadRequest, "max_epss must be between 0 and 1")
	}
	if p.MaxRiskScore != nil && *p.MaxRiskScore < 0 {
		return fiber.NewError(fiber.StatusBadRequest, "max_risk_score must be ≥ 0")
	}
	for _, s := range p.KEVSources {
		if !domain.ValidKEVCatalog(s) {
			return fiber.NewError(fiber.StatusBadRequest, "kev_sources must name "+strings.Join(domain.KEVCatalogs, ", "))
		}
	}
	return nil
}
