package license

import (
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/httpx"
)

// Handler exposes the license catalog and license groups over HTTP. Reads are
// open to every signed-in user; group mutations are admin-only (authz).
type Handler struct {
	groups *Groups
}

// NewHandler constructs a license Handler.
func NewHandler(groups *Groups) *Handler { return &Handler{groups: groups} }

// Register mounts the license routes.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/licenses", h.ListLicenses)
	r.Get("/licenses/:licenseID", h.GetLicense)
	r.Get("/license-groups", h.ListGroups)
	r.Post("/license-groups", h.CreateGroup)
	r.Get("/license-groups/:groupID", h.GetGroup)
	r.Put("/license-groups/:groupID", h.UpdateGroup)
	r.Delete("/license-groups/:groupID", h.DeleteGroup)
}

// ListLicenses handles GET /licenses?q=&category=&osi=&deprecated=: the SPDX
// License List with ScanCode categories, paginated.
func (h *Handler) ListLicenses(c *fiber.Ctx) error {
	f := CatalogFilter{Query: c.Query("q")}
	if cat := c.Query("category"); cat != "" {
		canon, ok := CanonicalCategory(cat)
		if !ok {
			return fiber.NewError(fiber.StatusBadRequest, "unknown category")
		}
		f.Category = canon
	}
	var err error
	if f.OSI, err = optBool(c, "osi"); err != nil {
		return err
	}
	if f.Deprecated, err = optBool(c, "deprecated"); err != nil {
		return err
	}
	all := Search(f)
	page := httpx.ParsePage(c)
	start := min(page.Offset, len(all))
	end := min(start+page.Limit, len(all))
	return c.JSON(fiber.Map{
		"licenses":     all[start:end],
		"total":        len(all),
		"list_version": CatalogVersion(),
		"categories":   Categories(),
		"pagination":   httpx.Meta(page, end-start, end < len(all)),
	})
}

func optBool(c *fiber.Ctx, name string) (*bool, error) {
	v := c.Query(name)
	if v == "" {
		return nil, nil
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusBadRequest, name+" must be true or false")
	}
	return &b, nil
}

// LicenseDetail is one catalog entry plus the custom groups containing it.
type LicenseDetail struct {
	Info
	// Kind is "license" or "exception" (a WITH exception).
	Kind   string     `json:"kind"`
	Groups []GroupRef `json:"groups"`
}

// GroupRef names a custom group.
type GroupRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// GetLicense handles GET /licenses/{id}: a license (or exception) by SPDX id or
// LicenseRef-scancode-* key, any case.
func (h *Handler) GetLicense(c *fiber.Ctx) error {
	id, err := url.PathUnescape(c.Params("licenseID"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid license id")
	}
	d := LicenseDetail{Kind: "license"}
	var ok bool
	if d.Info, ok = Lookup(id); !ok {
		if d.Info, ok = LookupException(id); !ok {
			return fiber.NewError(fiber.StatusNotFound, "license not found")
		}
		d.Kind = "exception"
	}
	if d.Groups, err = h.groups.Containing(c.UserContext(), d.ID); err != nil {
		return err
	}
	return c.JSON(d)
}

// ListGroups handles GET /license-groups: custom groups (paginated) plus the
// built-in per-category groups.
func (h *Handler) ListGroups(c *fiber.Ctx) error {
	page := httpx.ParsePage(c)
	groups, err := h.groups.List(c.UserContext(), page.Limit+1, page.Offset)
	if err != nil {
		return err
	}
	hasMore := len(groups) > page.Limit
	if hasMore {
		groups = groups[:page.Limit]
	}
	return c.JSON(fiber.Map{
		"groups":     groups,
		"builtin":    BuiltinGroups(),
		"pagination": httpx.Meta(page, len(groups), hasMore),
	})
}

// GetGroup handles GET /license-groups/{ref}: a custom group by id, or a
// built-in one as category:<Category>.
func (h *Handler) GetGroup(c *fiber.Ctx) error {
	ref, err := url.PathUnescape(c.Params("groupID"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid group reference")
	}
	if cat, ok := strings.CutPrefix(ref, CategoryRefPrefix); ok {
		canon, known := CanonicalCategory(cat)
		if !known {
			return fiber.NewError(fiber.StatusNotFound, "unknown license category")
		}
		return c.JSON(fiber.Map{"ref": CategoryRefPrefix + canon, "category": canon, "license_ids": CategoryMembers(canon)})
	}
	if _, err := httpx.ID(c, "groupID"); err != nil {
		return err
	}
	g, err := h.groups.Get(c.UserContext(), ref)
	if errors.Is(err, ErrGroupNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "license group not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(g)
}

// groupInput is the body of POST / PUT /license-groups.
type groupInput struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	LicenseIDs  []string `json:"license_ids"`
}

func (in groupInput) group() (Group, error) {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return Group{}, fiber.NewError(fiber.StatusBadRequest, "name is required")
	}
	ids, err := NormalizeIDs(in.LicenseIDs)
	if err != nil {
		return Group{}, fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return Group{Name: name, Description: strings.TrimSpace(in.Description), LicenseIDs: ids}, nil
}

// CreateGroup handles POST /license-groups.
func (h *Handler) CreateGroup(c *fiber.Ctx) error {
	var in groupInput
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	g, err := in.group()
	if err != nil {
		return err
	}
	out, err := h.groups.Create(c.UserContext(), g)
	if errors.Is(err, ErrDuplicateGroup) {
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

// UpdateGroup handles PUT /license-groups/{id}: replaces name, description and
// members.
func (h *Handler) UpdateGroup(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "groupID")
	if err != nil {
		return err
	}
	var in groupInput
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	g, err := in.group()
	if err != nil {
		return err
	}
	g.ID = id
	out, err := h.groups.Update(c.UserContext(), g)
	switch {
	case errors.Is(err, ErrGroupNotFound):
		return fiber.NewError(fiber.StatusNotFound, "license group not found")
	case errors.Is(err, ErrDuplicateGroup):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	case err != nil:
		return err
	}
	return c.JSON(out)
}

// DeleteGroup handles DELETE /license-groups/{id}.
func (h *Handler) DeleteGroup(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "groupID")
	if err != nil {
		return err
	}
	err = h.groups.Delete(c.UserContext(), id)
	if errors.Is(err, ErrGroupNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "license group not found")
	}
	if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
