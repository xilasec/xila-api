package rootcause

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/fixplan"
	"github.com/xilasec/xila-api/internal/httpx"
)

// Handler serves root causes.
type Handler struct{ svc *Service }

// NewHandler constructs the handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Register mounts the routes. authz gates GET /root-causes and the detail
// route as portfolio-wide lists, scoped to the caller's visible projects; the
// create route spans every project carrying the change and is authorized per
// project in the handler, like POST /findings/bulk.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/root-causes", h.list)
	r.Get("/root-causes/:kind/:key", h.detail)
	r.Post("/root-causes/:kind/:key/remediation", h.createMissing)
}

func kindParam(c *fiber.Ctx) (fixplan.Kind, error) {
	k := fixplan.Kind(c.Params("kind"))
	if !k.Valid() {
		return "", fiber.NewError(fiber.StatusBadRequest, "kind must be package_upgrade, base_image, iac_rule, code_location or config")
	}
	return k, nil
}

// keyParam decodes the base64url-encoded key path segment: a change's key can
// contain slashes, "@" and "|" (scoped package names, purl bases), which
// aren't safe raw path segments.
func keyParam(c *fiber.Ctx) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(c.Params("key"))
	if err != nil {
		return "", fiber.NewError(fiber.StatusBadRequest, "invalid key")
	}
	return string(b), nil
}

func parseFilter(c *fiber.Ctx) (Filter, error) {
	var f Filter
	if k := fixplan.Kind(c.Query("kind")); k != "" {
		if !k.Valid() {
			return f, fiber.NewError(fiber.StatusBadRequest, "kind must be package_upgrade, base_image, iac_rule, code_location or config")
		}
		f.Kind = k
	}
	f.Ecosystem = strings.TrimSpace(c.Query("ecosystem"))
	f.Query = strings.TrimSpace(c.Query("q"))
	f.KEVOnly = c.QueryBool("kev")
	if sev := domain.Severity(c.Query("min_severity")); sev != "" {
		if !sev.Valid() {
			return f, fiber.NewError(fiber.StatusBadRequest, "min_severity must be a known severity")
		}
		f.MinSeverity = sev
	}
	return f, nil
}

// visiblePIDs returns the caller's visible project ids (nil for an instance
// admin: every project).
func visiblePIDs(c *fiber.Ctx) []string {
	s := authz.VisibleScope(c)
	if s.AllAccess {
		return nil
	}
	if s.ProjectIDs == nil {
		return []string{}
	}
	return s.ProjectIDs
}

func (h *Handler) list(c *fiber.Ctx) error {
	f, err := parseFilter(c)
	if err != nil {
		return err
	}
	f.ProjectIDs = visiblePIDs(c)
	out, err := h.svc.List(c.UserContext(), f)
	if err != nil {
		return err
	}
	page := httpx.ParsePage(c)
	from := min(page.Offset, len(out))
	to := min(from+page.Limit, len(out))
	return c.JSON(fiber.Map{"root_causes": out[from:to], "pagination": httpx.Meta(page, to-from, to < len(out))})
}

func (h *Handler) detail(c *fiber.Ctx) error {
	kind, err := kindParam(c)
	if err != nil {
		return err
	}
	key, err := keyParam(c)
	if err != nil {
		return err
	}
	d, err := h.svc.Detail(c.UserContext(), visiblePIDs(c), kind, key)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, err.Error())
		}
		return err
	}
	return c.JSON(d)
}

// createMissing handles POST /root-causes/{kind}/{key}/remediation: creates
// the live remediation action in every visible project carrying the change
// where the caller holds at least editor, skipping and reporting the rest.
func (h *Handler) createMissing(c *fiber.Ctx) error {
	kind, err := kindParam(c)
	if err != nil {
		return err
	}
	key, err := keyParam(c)
	if err != nil {
		return err
	}
	res, err := h.svc.CreateMissing(c.UserContext(), auth.UserID(c), visiblePIDs(c), kind, key)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, err.Error())
		}
		return err
	}
	return c.JSON(res)
}
