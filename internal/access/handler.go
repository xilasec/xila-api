package access

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/export"
	"github.com/xilasec/xila-api/internal/httpx"
)

// Handler serves the permission audit.
type Handler struct {
	repo *Repository
}

// NewHandler constructs a Handler.
func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

// Register mounts the routes. /permissions is instance-admin only (authz);
// a project's access list needs owner on that project.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/permissions", h.list)
	r.Get("/permissions/export", h.export)
	r.Get("/projects/:projectID/access", h.project)
}

func parseFilter(c *fiber.Ctx) (Filter, error) {
	f := Filter{
		User:          c.Query("user"),
		UserID:        c.Query("user_id"),
		ProjectID:     c.Query("project_id"),
		TeamID:        c.Query("team_id"),
		OrgID:         c.Query("org_id"),
		Role:          strings.ToLower(c.Query("role")),
		Source:        strings.ToLower(c.Query("source")),
		PrincipalKind: strings.ToLower(c.Query("principal_kind")),
	}
	for name, id := range map[string]string{"user_id": f.UserID, "project_id": f.ProjectID, "team_id": f.TeamID, "org_id": f.OrgID} {
		if id != "" {
			if _, err := uuid.Parse(id); err != nil {
				return f, fiber.NewError(fiber.StatusBadRequest, name+" must be a UUID")
			}
		}
	}
	switch f.Role {
	case "", "owner", "editor", "viewer", "admin":
	default:
		return f, fiber.NewError(fiber.StatusBadRequest, "role must be owner, editor, viewer or admin")
	}
	switch f.Source {
	case "", "manual", "sso":
	default:
		return f, fiber.NewError(fiber.StatusBadRequest, "source must be manual or sso")
	}
	switch f.PrincipalKind {
	case "", "user", "service":
	default:
		return f, fiber.NewError(fiber.StatusBadRequest, "principal_kind must be user or service")
	}
	return f, nil
}

func (h *Handler) respond(c *fiber.Ctx, f Filter) error {
	page := httpx.ParsePage(c)
	f.Limit, f.Offset = page.Limit+1, page.Offset
	entries, err := h.repo.List(c.UserContext(), f)
	if err != nil {
		return err
	}
	hasMore := len(entries) > page.Limit
	if hasMore {
		entries = entries[:page.Limit]
	}
	return c.JSON(fiber.Map{"entries": entries, "pagination": httpx.Meta(page, len(entries), hasMore)})
}

// list handles GET /permissions.
func (h *Handler) list(c *fiber.Ctx) error {
	f, err := parseFilter(c)
	if err != nil {
		return err
	}
	return h.respond(c, f)
}

// project handles GET /projects/{id}/access: who can reach it and why.
func (h *Handler) project(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	f, err := parseFilter(c)
	if err != nil {
		return err
	}
	f.ProjectID, f.TeamID, f.OrgID = id, "", ""
	return h.respond(c, f)
}

var exportHeader = []string{"principal", "principal_kind", "disabled", "org", "team", "project", "project_id",
	"effective_role", "grant", "grant_role", "source", "via", "sso_mappings"}

// export handles GET /permissions/export: one row per contributing grant, so a
// reviewer can filter the sheet by any of them.
func (h *Handler) export(c *fiber.Ctx) error {
	f, err := parseFilter(c)
	if err != nil {
		return err
	}
	return export.Respond(c, "xila-permissions", "Permissions", exportHeader, func(t export.Table) (bool, error) {
		rows := export.Rows{T: t}
		err := h.repo.Each(c.UserContext(), f, export.MaxRows+1, func(e Entry) error {
			project, projectID, team, org := "(every project)", "", "", ""
			if e.ProjectID != nil {
				project, projectID = deref(e.ProjectName), *e.ProjectID
				team, org = deref(e.TeamName), deref(e.OrgName)
			}
			for _, g := range e.Grants {
				if err := rows.Add(e.Email, e.PrincipalKind, e.Disabled, org, team, project, projectID,
					e.EffectiveRole, g.Kind, g.Role, g.Source, deref(g.ViaName), strings.Join(g.SSOMappings, " ")); err != nil {
					return err
				}
			}
			return nil
		})
		return rows.Truncated, err
	})
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
