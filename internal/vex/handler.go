package vex

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/notify"
)

// eventNotifier dispatches events (notify.Service satisfies it). Optional.
type eventNotifier interface {
	Notify(ctx context.Context, e notify.Event)
}

// Handler exposes VEX upload and management over HTTP.
type Handler struct {
	repo      *Repository
	svc       *Service
	publicURL string
	notifier  eventNotifier // optional
}

// NewHandler constructs a VEX Handler.
func NewHandler(repo *Repository, svc *Service) *Handler {
	return &Handler{repo: repo, svc: svc}
}

// WithPublicURL sets the instance origin exports name as their publisher and
// build their document ids from (empty = a urn: identity).
func (h *Handler) WithPublicURL(u string) *Handler {
	h.publicURL = strings.TrimRight(u, "/")
	return h
}

// WithNotifier raises vex.processed when a document is ingested.
func (h *Handler) WithNotifier(n eventNotifier) *Handler {
	h.notifier = n
	return h
}

// Register mounts the VEX routes. They are project-scoped, so team RBAC covers
// them: reading needs viewer, uploading needs editor.
func (h *Handler) Register(r fiber.Router) {
	r.Post("/projects/:projectID/vex", h.Ingest)
	r.Get("/projects/:projectID/vex", h.List)
	r.Get("/projects/:projectID/vex/export", h.Export)
	r.Delete("/vex/:vexID", h.Delete)
}

// Ingest handles POST /projects/{id}/vex — the raw OpenVEX or CycloneDX VEX
// document as the body. It reports how many existing findings the analysis
// resolved, because that is what the uploader actually wants to know.
func (h *Handler) Ingest(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	if len(c.Body()) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "request body (a VEX document) is required")
	}

	stored, applied, err := h.svc.Ingest(c.UserContext(), projectID, bytes.NewReader(c.Body()))
	switch {
	case errors.Is(err, ErrProjectNotFound):
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	case err != nil:
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}
	if h.notifier != nil {
		go h.notifier.Notify(context.WithoutCancel(c.UserContext()), notify.Event{
			Type:      notify.EventVEXProcessed,
			Title:     fmt.Sprintf("VEX processed: %d statement(s), %d finding(s) resolved", len(stored), applied),
			ProjectID: projectID,
			Fields: map[string]string{
				"statements": strconv.Itoa(len(stored)),
				"resolved":   strconv.Itoa(applied),
			},
		})
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{
		"statements":        stored,
		"findings_resolved": applied,
	})
}

// List handles GET /projects/{id}/vex.
func (h *Handler) List(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	stmts, err := h.repo.ListByProject(c.UserContext(), projectID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"statements": stmts})
}

// Delete handles DELETE /vex/{id}.
func (h *Handler) Delete(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "vexID")
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.UserContext(), id); err != nil {
		if errors.Is(err, ErrNotFound) {
			return fiber.NewError(fiber.StatusNotFound, "vex statement not found")
		}
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Export handles GET /projects/{id}/vex/export?format=openvex|cyclonedx|csaf
// (&branch= or &version_id=; default = the project's default version): the
// project's analysis — its triage merged with its stored statements — as a
// downloadable VEX document.
func (h *Handler) Export(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	format := strings.ToLower(c.Query("format", FormatOpenVEX))
	if !slices.Contains(ExportFormats, format) {
		return fiber.NewError(fiber.StatusBadRequest, "format must be one of: "+strings.Join(ExportFormats, ", "))
	}
	spec, err := ParseCDXSpec(c.Query("spec"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	versionID, branch := c.Query("version_id"), strings.TrimSpace(c.Query("branch"))
	if versionID != "" && branch != "" {
		return fiber.NewError(fiber.StatusBadRequest, "give branch or version_id, not both")
	}
	if versionID != "" && uuid.Validate(versionID) != nil {
		return fiber.NewError(fiber.StatusBadRequest, "version_id must be a uuid")
	}

	ctx := c.UserContext()
	scope, err := h.repo.ExportScope(ctx, projectID, versionID, branch, auth.UserID(c))
	switch {
	case errors.Is(err, ErrNoProject):
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	case errors.Is(err, ErrNoVersion):
		return fiber.NewError(fiber.StatusNotFound, "version not found")
	case err != nil:
		return err
	}
	scope.PublicURL = h.publicURL
	findings, err := h.repo.ExportFindings(ctx, projectID, scope.VersionID)
	if err != nil {
		return err
	}
	stored, err := h.repo.ListByProject(ctx, projectID)
	if err != nil {
		return err
	}
	stmts := BuildStatements(scope, findings, stored)

	now := time.Now().UTC()
	var doc any
	contentType, ext := fiber.MIMEApplicationJSON, "openvex.json"
	switch format {
	case FormatCycloneDX:
		doc = CycloneDXVEX(scope, stmts, uuid.NewString(), spec, now)
		contentType, ext = "application/vnd.cyclonedx+json", "vex.cdx.json"
	case FormatCSAF:
		doc = CSAFVEX(scope, stmts, now)
		ext = "csaf.json"
	default:
		doc = OpenVEX(scope, stmts, now)
	}
	c.Set(fiber.HeaderContentDisposition,
		fmt.Sprintf(`attachment; filename="%s-%s.%s"`, scope.ProjectSlug, safeFilename(scope.VersionName), ext))
	if err := c.JSON(doc); err != nil {
		return err
	}
	c.Set(fiber.HeaderContentType, contentType)
	return nil
}

// safeFilename keeps a version name usable in a Content-Disposition filename.
func safeFilename(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == '"' || r < 0x20 {
			return '_'
		}
		return r
	}, s)
}
