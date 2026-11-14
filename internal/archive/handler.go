package archive

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
)

// regrouper re-elects a project's cross-tool dedup primaries
// (finding.Repository): archiving or restoring a finding changes which
// findings may be a group's primary.
type regrouper interface {
	Deduplicate(ctx context.Context, projectID string) (int, error)
}

// Handler serves archive / restore / purge. authz: archiving needs editor
// (a project: owner), restoring owner, `?purge=true` an instance admin.
type Handler struct {
	repo    *Repository
	regroup regrouper
	window  time.Duration // ARCHIVE_RETENTION: how long a record stays restorable
}

// NewHandler constructs the handler.
func NewHandler(repo *Repository, regroup regrouper, window time.Duration) *Handler {
	return &Handler{repo: repo, regroup: regroup, window: window}
}

// Register mounts DELETE (archive, or purge with ?purge=true) and POST
// …/restore for each archivable entity.
func (h *Handler) Register(r fiber.Router) {
	for _, e := range []struct {
		kind  Kind
		path  string
		param string
		label string
	}{
		{KindProject, "/projects/:projectID", "projectID", "project"},
		{KindEngagement, "/engagements/:engagementID", "engagementID", "engagement"},
		{KindScan, "/scans/:scanID", "scanID", "scan"},
		{KindFinding, "/findings/:findingID", "findingID", "finding"},
	} {
		r.Delete(e.path, h.archive(e.kind, e.param, e.label))
		r.Post(e.path+"/restore", h.restore(e.kind, e.param, e.label))
	}
}

func (h *Handler) archive(kind Kind, param, label string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id, err := httpx.ID(c, param)
		if err != nil {
			return err
		}
		ctx := c.UserContext()
		var pid string
		if c.QueryBool("purge") {
			pid, err = h.repo.Purge(ctx, kind, id, auth.UserID(c))
		} else {
			pid, err = h.repo.Archive(ctx, kind, id, auth.UserID(c))
		}
		if err != nil {
			return mapErr(err, label)
		}
		h.regroupAfter(ctx, kind, pid)
		return c.SendStatus(fiber.StatusNoContent)
	}
}

func (h *Handler) restore(kind Kind, param, label string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		id, err := httpx.ID(c, param)
		if err != nil {
			return err
		}
		pid, err := h.repo.Restore(c.UserContext(), kind, id, h.window)
		if err != nil {
			return mapErr(err, label)
		}
		h.regroupAfter(c.UserContext(), kind, pid)
		return c.SendStatus(fiber.StatusNoContent)
	}
}

// regroupAfter re-elects dedup primaries where findings came or went. An
// engagement carries no findings of its own (its scans stay with the project).
// The change is committed either way: a failed regroup is logged and the next
// ingest's dedup repairs it.
func (h *Handler) regroupAfter(ctx context.Context, kind Kind, projectID string) {
	if kind == KindEngagement || h.regroup == nil {
		return
	}
	if _, err := h.regroup.Deduplicate(ctx, projectID); err != nil {
		slog.WarnContext(ctx, "archive: regroup failed", "project_id", projectID, "error", err)
	}
}

func mapErr(err error, label string) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, label+" not found")
	case errors.Is(err, ErrNotArchived):
		return fiber.NewError(fiber.StatusConflict, label+" is not archived")
	case errors.Is(err, ErrExpired):
		return fiber.NewError(fiber.StatusGone, label+" was "+err.Error())
	}
	return err
}
