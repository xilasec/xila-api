package pkgmeta

import (
	"errors"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/httpx"
)

// sweepTimeout bounds a sweep started from the API in the background.
const sweepTimeout = 2 * time.Hour

// Handler exposes cached package metadata and on-demand sweeps.
type Handler struct {
	repo *Repository
	svc  *Service // nil when PKGMETA_ENABLED=false: the cache stays readable
}

// NewHandler constructs the Handler. A nil svc (registry lookups disabled)
// makes POST /pkgmeta/refresh answer 503.
func NewHandler(repo *Repository, svc *Service) *Handler {
	return &Handler{repo: repo, svc: svc}
}

// Register mounts the routes. GET /pkgmeta serves public registry data to any
// signed-in user; POST /pkgmeta/refresh is admin-only (authz); the snapshot
// summary is scoped to the SBOM's project by its path.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/pkgmeta", h.Get)
	r.Post("/pkgmeta/refresh", h.Refresh)
	r.Get("/sboms/:sbomID/freshness", h.SbomFreshness)
}

// Get handles GET /pkgmeta?purl=pkg:npm/lodash@4.17.20: the cached registry
// metadata of the purl's package, plus — when the purl has a version — that
// version's freshness (null when it can't be judged).
func (h *Handler) Get(c *fiber.Ctx) error {
	raw := c.Query("purl")
	if raw == "" {
		return fiber.NewError(fiber.StatusBadRequest, "purl is required")
	}
	p, err := ParsePURL(raw)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "purl is not a valid package url")
	}
	if !Supported(p.Type) {
		return fiber.NewError(fiber.StatusBadRequest, "unsupported ecosystem "+p.Type)
	}
	m, err := h.repo.Get(c.UserContext(), p.Base())
	if errors.Is(err, ErrNoMeta) {
		return fiber.NewError(fiber.StatusNotFound, "no metadata for this package yet")
	}
	if err != nil {
		return err
	}
	var st *Info
	if info, ok := evaluate(p.Type, m, p.Version); ok {
		st = &info
	}
	return c.JSON(fiber.Map{"package": m, "version": p.Version, "status": st})
}

// Refresh handles POST /pkgmeta/refresh: start a sweep now in the background
// (202), or with ?wait=true run it and return its summary. 409 while one runs;
// 503 when registry lookups are disabled.
func (h *Handler) Refresh(c *fiber.Ctx) error {
	if h.svc == nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "package metadata lookups are disabled (PKGMETA_ENABLED=false)")
	}
	if c.QueryBool("wait") {
		res, err := h.svc.TrySweep(c.UserContext())
		if errors.Is(err, ErrSweepRunning) {
			return fiber.NewError(fiber.StatusConflict, err.Error())
		}
		if err != nil {
			return err
		}
		return c.JSON(res)
	}
	if errors.Is(h.svc.StartSweep(sweepTimeout), ErrSweepRunning) {
		return fiber.NewError(fiber.StatusConflict, ErrSweepRunning.Error())
	}
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"status": "started"})
}

// SbomFreshness handles GET /sboms/{id}/freshness: the snapshot's components
// counted as outdated / up to date / unknown.
func (h *Handler) SbomFreshness(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "sbomID")
	if err != nil {
		return err
	}
	f, err := h.repo.SbomFreshness(c.UserContext(), id)
	if errors.Is(err, ErrSbomNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "sbom not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(f)
}
