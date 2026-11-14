package audit

import (
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/export"
	"github.com/xilasec/xila-api/internal/httpx"
)

// Handler serves the audit log (instance admin only, in authz).
type Handler struct{ repo *Repository }

// NewHandler constructs the audit-log handler.
func NewHandler(repo *Repository) *Handler { return &Handler{repo: repo} }

// Register mounts /audit-log.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/audit-log", h.list)
	r.Get("/audit-log/export", h.export)
}

// parseFilter reads the shared list / export query parameters.
func parseFilter(c *fiber.Ctx) (Filter, error) {
	f := Filter{
		ActorID:      c.Query("actor_id"),
		Actor:        c.Query("actor"),
		ActorKind:    c.Query("actor_kind"),
		Action:       c.Query("action"),
		ResourceType: c.Query("resource_type"),
		ResourceID:   c.Query("resource_id"),
		ProjectID:    c.Query("project_id"),
		Outcome:      c.Query("outcome"),
	}
	for _, id := range []string{f.ActorID, f.ProjectID} {
		if id != "" && !isUUID(id) {
			return f, fiber.NewError(fiber.StatusBadRequest, "actor_id and project_id must be UUIDs")
		}
	}
	switch f.ActorKind {
	case "", ActorUser, ActorServiceAccount, ActorAPIToken, ActorSystem, ActorAnonymous:
	default:
		return f, fiber.NewError(fiber.StatusBadRequest, "actor_kind must be user, service_account, api_token, system or anonymous")
	}
	if f.Outcome != "" && f.Outcome != OutcomeSuccess && f.Outcome != OutcomeFailure {
		return f, fiber.NewError(fiber.StatusBadRequest, "outcome must be success or failure")
	}
	var err error
	if f.From, err = parseTime(c.Query("from"), false); err != nil {
		return f, err
	}
	if f.To, err = parseTime(c.Query("to"), true); err != nil {
		return f, err
	}
	return f, nil
}

// parseTime accepts RFC 3339 or a date. A date as the upper bound includes
// that whole day.
func parseTime(s string, upper bool) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		return time.Time{}, fiber.NewError(fiber.StatusBadRequest, "from / to must be RFC 3339 times or YYYY-MM-DD dates")
	}
	if upper {
		t = t.AddDate(0, 0, 1)
	}
	return t, nil
}

func (h *Handler) list(c *fiber.Ctx) error {
	f, err := parseFilter(c)
	if err != nil {
		return err
	}
	page := httpx.ParsePage(c)
	entries, err := h.repo.List(c.UserContext(), f, page.Limit+1, page.Offset)
	if err != nil {
		return err
	}
	hasMore := len(entries) > page.Limit
	if hasMore {
		entries = entries[:page.Limit]
	}
	return c.JSON(fiber.Map{"entries": entries, "pagination": httpx.Meta(page, len(entries), hasMore)})
}

var exportHeader = []string{
	"Time", "Actor kind", "Actor", "Actor user id", "API token id", "Action", "Resource type", "Resource id",
	"Project id", "Team id", "Org id", "Method", "Path", "Client IP", "Status", "Outcome", "Request id", "Changes",
}

func (h *Handler) export(c *fiber.Ctx) error {
	f, err := parseFilter(c)
	if err != nil {
		return err
	}
	return export.Respond(c, "xila-audit-log", "Audit log", exportHeader, func(t export.Table) (bool, error) {
		rows := export.Rows{T: t}
		err := h.repo.Each(c.UserContext(), f, export.MaxRows+1, func(e Entry) error {
			return rows.Add(e.CreatedAt, e.ActorKind, e.ActorEmail, e.ActorUserID, e.ActorTokenID, e.Action,
				e.ResourceType, e.ResourceID, e.ProjectID, e.TeamID, e.OrgID, e.Method, e.Path, e.ClientIP,
				e.Status, e.Outcome, e.RequestID, string(e.Changes))
		})
		return rows.Truncated, err
	})
}
