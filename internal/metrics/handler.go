package metrics

import (
	"context"
	"slices"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/projecttree"
)

// Handler exposes metric trends and the on-demand snapshot.
type Handler struct {
	repo   *Repository
	writer *Repository
	after  func(context.Context) error
}

// NewHandler constructs a metrics Handler.
func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo, writer: repo}
}

// WithSnapshotter makes POST /metrics/snapshot write through writer (repo may
// read from a replica) and then run after (the portfolio parts), like the job.
func (h *Handler) WithSnapshotter(writer *Repository, after func(context.Context) error) *Handler {
	h.writer = writer
	h.after = after
	return h
}

// Register mounts the metrics routes.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/metrics/trends", h.PortfolioTrend)
	r.Post("/metrics/snapshot", h.SnapshotNow)
	r.Get("/projects/:projectID/metrics/trends", h.scopeTrend(ScopeProject, "projectID"))
	r.Get("/teams/:teamID/metrics/trends", h.scopeTrend(ScopeTeam, "teamID"))
	r.Get("/orgs/:orgID/metrics/trends", h.OrgTrend)
}

// trendResponse is the body of every trend route.
type trendResponse struct {
	Days   int     `json:"days"`
	Points []Point `json:"points"`
}

// parseDays reads ?days= (default DefaultTrendDays, capped at MaxTrendDays).
func parseDays(c *fiber.Ctx) (int, error) {
	raw := c.Query("days")
	if raw == "" {
		return DefaultTrendDays, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		return 0, fiber.NewError(fiber.StatusBadRequest, "days must be a positive integer")
	}
	return min(n, MaxTrendDays), nil
}

func respond(c *fiber.Ctx, days int, points []Point) error {
	return c.JSON(trendResponse{Days: days, Points: points})
}

// PortfolioTrend handles GET /metrics/trends. Admins read the stored portfolio
// row; everyone else gets the sum of the projects they can see, so a trend
// never reveals posture of projects outside the caller's scope.
func (h *Handler) PortfolioTrend(c *fiber.Ctx) error {
	days, err := parseDays(c)
	if err != nil {
		return err
	}
	now := time.Now()
	var points []Point
	if s := authz.VisibleScope(c); s.AllAccess {
		points, err = h.repo.Trend(c.UserContext(), ScopePortfolio, "", days, now)
	} else {
		points, err = h.repo.ProjectsTrend(c.UserContext(), s.ProjectIDs, "", days, now)
	}
	if err != nil {
		return err
	}
	return respond(c, days, points)
}

// OrgTrend handles GET /orgs/{orgID}/metrics/trends. Org membership doesn't
// imply access to every project in the org, so the route is list-scoped:
// members get the sum of the org's projects they can see; admins the org row.
func (h *Handler) OrgTrend(c *fiber.Ctx) error {
	orgID, err := httpx.ID(c, "orgID")
	if err != nil {
		return err
	}
	days, err := parseDays(c)
	if err != nil {
		return err
	}
	now := time.Now()
	var points []Point
	s := authz.VisibleScope(c)
	switch {
	case s.AllAccess:
		points, err = h.repo.Trend(c.UserContext(), ScopeOrg, orgID, days, now)
	case !slices.Contains(s.OrgIDs, orgID):
		return fiber.NewError(fiber.StatusForbidden, "not a member of this organization")
	default:
		points, err = h.repo.ProjectsTrend(c.UserContext(), s.ProjectIDs, orgID, days, now)
	}
	if err != nil {
		return err
	}
	return respond(c, days, points)
}

// scopeTrend serves a stored project/team series; the authz middleware has
// already checked the caller's role on it (team viewers see every project in
// the team; a project's readers see its descendants).
func (h *Handler) scopeTrend(kind ScopeKind, param string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id, err := httpx.ID(c, param)
		if err != nil {
			return err
		}
		days, err := parseDays(c)
		if err != nil {
			return err
		}
		var points []Point
		if kind == ScopeProject {
			// A project with its children included sums its subtree's rows
			// (every stored figure is summable).
			ids, err := projecttree.Rollup(c, h.repo.db, id)
			if err != nil {
				return err
			}
			if len(ids) > 1 {
				points, err = h.repo.ProjectsTrend(c.UserContext(), ids, "", days, time.Now())
				if err != nil {
					return err
				}
				return respond(c, days, points)
			}
		}
		points, err = h.repo.Trend(c.UserContext(), kind, id, days, time.Now())
		if err != nil {
			return err
		}
		return respond(c, days, points)
	}
}

// SnapshotNow handles POST /metrics/snapshot (admin): runs the periodic job
// immediately — backfill on first run, then yesterday and today.
func (h *Handler) SnapshotNow(c *fiber.Ctx) error {
	res, err := h.writer.Run(c.UserContext(), time.Now())
	if err != nil {
		return err
	}
	if h.after != nil {
		if err := h.after(c.UserContext()); err != nil {
			return err
		}
	}
	return c.JSON(res)
}
