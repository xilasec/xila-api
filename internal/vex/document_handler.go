package vex

import (
	"errors"
	"fmt"
	"strconv"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/httpx"
)

// DocumentHandler exposes stored VEX document management over HTTP.
type DocumentHandler struct {
	svc *DocumentService
}

// NewDocumentHandler constructs a DocumentHandler.
func NewDocumentHandler(svc *DocumentService) *DocumentHandler { return &DocumentHandler{svc: svc} }

// Register mounts the /vex-documents routes. They span every visible project
// (list) or one document that may belong to any project (or, for a
// vulnerability-scope document, no single project); authz routes them as a
// global-list path and this handler authorizes each document against its own
// scope, like POST /findings/bulk and /root-causes.
func (h *DocumentHandler) Register(r fiber.Router) {
	r.Get("/vex-documents", h.List)
	r.Post("/vex-documents", h.Create)
	r.Get("/vex-documents/:documentID", h.Get)
	r.Put("/vex-documents/:documentID", h.Update)
	r.Delete("/vex-documents/:documentID", h.Delete)
	r.Post("/vex-documents/:documentID/publish", h.Publish)
	r.Get("/vex-documents/:documentID/revisions", h.ListRevisions)
	r.Get("/vex-documents/:documentID/revisions/:number/download", h.Download)
}

func scopeOf(c *fiber.Ctx) (isAdmin bool, pids []string) {
	s := authz.VisibleScope(c)
	if s.AllAccess {
		return true, nil
	}
	if s.ProjectIDs == nil {
		return false, []string{}
	}
	return false, s.ProjectIDs
}

func mapDocErr(err error) error {
	switch {
	case errors.Is(err, ErrDocNotFound), errors.Is(err, ErrDocNoRevision), errors.Is(err, ErrDocNotPublished):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	case errors.Is(err, ErrNoProject), errors.Is(err, ErrDocUnknownVersion):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, ErrDocForbidden):
		return fiber.NewError(fiber.StatusForbidden, err.Error())
	}
	return err
}

func (h *DocumentHandler) id(c *fiber.Ctx) (string, error) { return httpx.ID(c, "documentID") }

func actorID(c *fiber.Ctx) *string {
	if uid := auth.UserID(c); uid != "" {
		return &uid
	}
	return nil
}

// List handles GET /vex-documents.
func (h *DocumentHandler) List(c *fiber.Ctx) error {
	isAdmin, pids := scopeOf(c)
	page := httpx.ParsePage(c)
	list, err := h.svc.List(c.UserContext(), isAdmin, pids, page.Limit+1, page.Offset)
	if err != nil {
		return mapDocErr(err)
	}
	hasMore := len(list) > page.Limit
	if hasMore {
		list = list[:page.Limit]
	}
	return c.JSON(fiber.Map{"documents": list, "pagination": httpx.Meta(page, len(list), hasMore)})
}

// Get handles GET /vex-documents/{id}.
func (h *DocumentHandler) Get(c *fiber.Ctx) error {
	id, err := h.id(c)
	if err != nil {
		return err
	}
	isAdmin, _ := scopeOf(c)
	d, err := h.svc.Get(c.UserContext(), auth.UserID(c), isAdmin, id)
	if err != nil {
		return mapDocErr(err)
	}
	return c.JSON(d)
}

// Create handles POST /vex-documents.
func (h *DocumentHandler) Create(c *fiber.Ctx) error {
	var d Document
	if err := httpx.Parse(c, &d); err != nil {
		return err
	}
	isAdmin, _ := scopeOf(c)
	out, err := h.svc.Create(c.UserContext(), auth.UserID(c), isAdmin, d, actorID(c))
	if err != nil {
		return mapDocErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

// Update handles PUT /vex-documents/{id}.
func (h *DocumentHandler) Update(c *fiber.Ctx) error {
	id, err := h.id(c)
	if err != nil {
		return err
	}
	var d Document
	if err := httpx.Parse(c, &d); err != nil {
		return err
	}
	d.ID = id
	isAdmin, _ := scopeOf(c)
	out, err := h.svc.Update(c.UserContext(), auth.UserID(c), isAdmin, d)
	if err != nil {
		return mapDocErr(err)
	}
	return c.JSON(out)
}

// Delete handles DELETE /vex-documents/{id}.
func (h *DocumentHandler) Delete(c *fiber.Ctx) error {
	id, err := h.id(c)
	if err != nil {
		return err
	}
	isAdmin, _ := scopeOf(c)
	if err := h.svc.Delete(c.UserContext(), auth.UserID(c), isAdmin, id); err != nil {
		return mapDocErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Publish handles POST /vex-documents/{id}/publish.
func (h *DocumentHandler) Publish(c *fiber.Ctx) error {
	id, err := h.id(c)
	if err != nil {
		return err
	}
	isAdmin, _ := scopeOf(c)
	out, changed, err := h.svc.Publish(c.UserContext(), auth.UserID(c), isAdmin, id)
	if err != nil {
		return mapDocErr(err)
	}
	return c.JSON(fiber.Map{"document": out, "changed": changed})
}

// ListRevisions handles GET /vex-documents/{id}/revisions.
func (h *DocumentHandler) ListRevisions(c *fiber.Ctx) error {
	id, err := h.id(c)
	if err != nil {
		return err
	}
	isAdmin, _ := scopeOf(c)
	revs, err := h.svc.ListRevisions(c.UserContext(), auth.UserID(c), isAdmin, id)
	if err != nil {
		return mapDocErr(err)
	}
	return c.JSON(fiber.Map{"revisions": revs})
}

// Download handles GET /vex-documents/{id}/revisions/{number}/download.
func (h *DocumentHandler) Download(c *fiber.Ctx) error {
	id, err := h.id(c)
	if err != nil {
		return err
	}
	number, err := strconv.Atoi(c.Params("number"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "revision number must be an integer")
	}
	isAdmin, _ := scopeOf(c)
	content, d, err := h.svc.RevisionContent(c.UserContext(), auth.UserID(c), isAdmin, id, number)
	if err != nil {
		return mapDocErr(err)
	}
	ext := "openvex.json"
	switch d.Format {
	case FormatCSAF:
		ext = "csaf.json"
	case FormatCycloneDX:
		ext = "vex.cdx.json"
	}
	c.Set(fiber.HeaderContentDisposition, fmt.Sprintf(`attachment; filename="%s-r%d.%s"`, d.DocumentID, number, ext))
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSONCharsetUTF8)
	return c.Send(content)
}
