package psirt

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
)

// Handler serves the admin API (instance-admin; authz) and the public CSAF
// provider directory.
type Handler struct {
	svc  *Service
	repo *Repository
}

// NewHandler constructs the handler.
func NewHandler(svc *Service, repo *Repository) *Handler { return &Handler{svc: svc, repo: repo} }

// Register mounts the admin routes.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/psirt/advisories", h.List)
	r.Post("/psirt/advisories", h.Create)
	r.Get("/psirt/advisories/:advisoryID", h.Get)
	r.Put("/psirt/advisories/:advisoryID", h.Update)
	r.Delete("/psirt/advisories/:advisoryID", h.Delete)
	r.Get("/psirt/advisories/:advisoryID/preview", h.Preview)
	r.Get("/psirt/advisories/:advisoryID/csaf", h.Download)
	r.Post("/psirt/advisories/:advisoryID/publish", h.Publish)
	r.Post("/psirt/advisories/:advisoryID/withdraw", h.Withdraw)
}

// RegisterPublic mounts the CSAF provider directory at the site root. The
// routes always exist (so the SPA can't answer them) and are 404 unless
// PSIRT_PUBLIC is on.
func (h *Handler) RegisterPublic(app fiber.Router) {
	app.Get("/.well-known/csaf/provider-metadata.json", h.public(h.ProviderMetadata))
	app.Get("/csaf/advisories/index.txt", h.public(h.Index))
	app.Get("/csaf/advisories/changes.csv", h.public(h.Changes))
	app.Get("/csaf/advisories/:year/:file", h.public(h.File))
}

func (h *Handler) public(next fiber.Handler) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if !h.svc.cfg.Public {
			return fiber.ErrNotFound
		}
		return next(c)
	}
}

func mapErr(err error) error {
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrNotPublished):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	case errors.Is(err, ErrNoProject), errors.Is(err, ErrUnknownVersion), errors.Is(err, ErrNoteRequired),
		errors.Is(err, ErrNoSourceAdvisory), errors.Is(err, ErrInvalid):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, ErrState), errors.Is(err, ErrPublisher):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	return err
}

func actor(c *fiber.Ctx) *string {
	if a := auth.CurrentActor(c); a.UserID != "" {
		return &a.UserID
	}
	return nil
}

// List returns advisories (?project_id=, ?state=) plus the publishing setup.
func (h *Handler) List(c *fiber.Ctx) error {
	page := httpx.ParsePage(c)
	state := State(c.Query("state"))
	if state != "" && state != StateDraft && state != StatePublished && state != StateWithdrawn {
		return fiber.NewError(fiber.StatusBadRequest, "state must be draft, published or withdrawn")
	}
	list, err := h.repo.List(c.UserContext(), Filter{ProjectID: c.Query("project_id"), State: state,
		Limit: page.Limit + 1, Offset: page.Offset})
	if err != nil {
		return err
	}
	hasMore := len(list) > page.Limit
	if hasMore {
		list = list[:page.Limit]
	}
	cfg := h.svc.cfg
	return c.JSON(fiber.Map{
		"advisories": list, "pagination": httpx.Meta(page, len(list), hasMore),
		"publishing": fiber.Map{"public": cfg.Public, "prefix": cfg.Prefix, "publisher": cfg.Publisher,
			"configured": cfg.Publisher.Configured()},
	})
}

func (h *Handler) id(c *fiber.Ctx) (string, error) { return httpx.ID(c, "advisoryID") }

// Get returns one advisory with its revision history.
func (h *Handler) Get(c *fiber.Ctx) error {
	id, err := h.id(c)
	if err != nil {
		return err
	}
	a, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		return mapErr(err)
	}
	return c.JSON(a)
}

// Create stores a draft.
func (h *Handler) Create(c *fiber.Ctx) error {
	var a Advisory
	if err := httpx.Parse(c, &a); err != nil {
		return err
	}
	if _, err := uuid.Parse(a.ProjectID); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "project_id is required")
	}
	out, err := h.svc.Create(c.UserContext(), a, actor(c))
	if err != nil {
		return mapErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

// Update replaces the editable fields.
func (h *Handler) Update(c *fiber.Ctx) error {
	id, err := h.id(c)
	if err != nil {
		return err
	}
	var a Advisory
	if err := httpx.Parse(c, &a); err != nil {
		return err
	}
	a.ID = id
	if err := a.Validate(); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	out, err := h.repo.Update(c.UserContext(), a)
	if err != nil {
		return mapErr(err)
	}
	return c.JSON(out)
}

// Delete removes a never-published draft.
func (h *Handler) Delete(c *fiber.Ctx) error {
	id, err := h.id(c)
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.UserContext(), id); err != nil {
		return mapErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Preview renders what the next publish would freeze.
func (h *Handler) Preview(c *fiber.Ctx) error {
	id, err := h.id(c)
	if err != nil {
		return err
	}
	doc, err := h.svc.Preview(c.UserContext(), id)
	if err != nil {
		return mapErr(err)
	}
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSONCharsetUTF8)
	return c.Send(doc)
}

// Download returns the frozen, distributed document (attachment).
func (h *Handler) Download(c *fiber.Ctx) error {
	id, err := h.id(c)
	if err != nil {
		return err
	}
	a, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		return mapErr(err)
	}
	doc, err := h.repo.Document(c.UserContext(), id)
	if err != nil {
		return mapErr(err)
	}
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSONCharsetUTF8)
	c.Set(fiber.HeaderContentDisposition, `attachment; filename="`+FileName(a.TrackingID)+`"`)
	return c.Send(doc)
}

type releaseBody struct {
	Note string `json:"note"`
}

// Publish releases (or re-releases) the advisory.
func (h *Handler) Publish(c *fiber.Ctx) error {
	return h.release(c, h.svc.Publish)
}

// Withdraw retracts a published advisory.
func (h *Handler) Withdraw(c *fiber.Ctx) error {
	return h.release(c, h.svc.Withdraw)
}

func (h *Handler) release(c *fiber.Ctx, do func(ctx context.Context, id, note string, actor *string) (Advisory, error)) error {
	id, err := h.id(c)
	if err != nil {
		return err
	}
	var body releaseBody
	if len(c.Body()) > 0 {
		if err := httpx.Parse(c, &body); err != nil {
			return err
		}
	}
	out, err := do(c.UserContext(), id, body.Note, actor(c))
	if err != nil {
		return mapErr(err)
	}
	return c.JSON(out)
}

// --- public CSAF provider directory (CSAF 2.0 §7) ---

// ProviderMetadata is /.well-known/csaf/provider-metadata.json.
func (h *Handler) ProviderMetadata(c *fiber.Ctx) error {
	cfg := h.svc.cfg
	released, err := h.repo.Released(c.UserContext())
	if err != nil {
		return err
	}
	last := time.Now().UTC()
	if len(released) > 0 {
		last = released[0].CurrentReleaseAt
	}
	base := strings.TrimRight(cfg.BaseURL, "/")
	return c.JSON(fiber.Map{
		"canonical_url":              base + "/.well-known/csaf/provider-metadata.json",
		"distributions":              []fiber.Map{{"directory_url": base + "/csaf/advisories/"}},
		"last_updated":               csafDate(last),
		"list_on_CSAF_aggregators":   true,
		"metadata_version":           "2.0",
		"mirror_on_CSAF_aggregators": true,
		"publisher": csafPublisher{Category: "vendor", Name: cfg.Publisher.Name, Namespace: cfg.Publisher.Namespace,
			ContactDetails: cfg.Publisher.Contact},
		// No OpenPGP signatures are produced, so this is the publisher role.
		"role": "csaf_publisher",
	})
}

// Index is index.txt: one released document path per line.
func (h *Handler) Index(c *fiber.Ctx) error {
	released, err := h.repo.Released(c.UserContext())
	if err != nil {
		return err
	}
	var b strings.Builder
	for _, d := range released {
		b.WriteString(DocumentPath(d.TrackingID, d.InitialReleaseAt) + "\n")
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
	return c.SendString(b.String())
}

// Changes is changes.csv: path and current release date, newest first.
func (h *Handler) Changes(c *fiber.Ctx) error {
	released, err := h.repo.Released(c.UserContext())
	if err != nil {
		return err
	}
	var b strings.Builder
	w := csv.NewWriter(&b)
	w.UseCRLF = false
	for _, d := range released {
		_ = w.Write([]string{DocumentPath(d.TrackingID, d.InitialReleaseAt), csafDate(d.CurrentReleaseAt)})
	}
	w.Flush()
	c.Set(fiber.HeaderContentType, "text/csv; charset=utf-8")
	return c.SendString(b.String())
}

// File serves <year>/<file>.json and its .sha256 / .sha512 hash files.
func (h *Handler) File(c *fiber.Ctx) error {
	path := c.Params("year") + "/" + c.Params("file")
	name, hashExt := path, ""
	for _, ext := range []string{".sha256", ".sha512"} {
		if before, ok := strings.CutSuffix(path, ext); ok {
			name, hashExt = before, ext
		}
	}
	released, err := h.repo.Released(c.UserContext())
	if err != nil {
		return err
	}
	for _, d := range released {
		if DocumentPath(d.TrackingID, d.InitialReleaseAt) != name {
			continue
		}
		file := name[strings.LastIndexByte(name, '/')+1:]
		switch hashExt {
		case ".sha256":
			sum := sha256.Sum256(d.Document)
			c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
			return c.SendString(hex.EncodeToString(sum[:]) + "  " + file + "\n")
		case ".sha512":
			sum := sha512.Sum512(d.Document)
			c.Set(fiber.HeaderContentType, fiber.MIMETextPlainCharsetUTF8)
			return c.SendString(hex.EncodeToString(sum[:]) + "  " + file + "\n")
		}
		c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSONCharsetUTF8)
		return c.Send(d.Document)
	}
	return fiber.ErrNotFound
}
