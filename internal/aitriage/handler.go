package aitriage

import (
	"errors"
	"math"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/httpx"
)

// Handler exposes AI triage under /findings/{id}/ai-proposals. authz
// resolves the finding's project: reads need viewer, requests and decisions
// editor. The routes are always mounted; while AI triage is off they answer
// 404.
type Handler struct{ svc *Service }

// NewHandler constructs a Handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Register mounts the routes.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/ai-proposals", h.ListOpen)
	r.Get("/findings/:findingID/ai-proposals", h.List)
	r.Get("/findings/:findingID/ai-proposals/prompt", h.Prompt)
	r.Post("/findings/:findingID/ai-proposals", h.Ask)
	r.Post("/findings/:findingID/ai-proposals/:proposalID/accept", h.Accept)
	r.Post("/findings/:findingID/ai-proposals/:proposalID/reject", h.Reject)
}

// mapError turns service errors into HTTP errors.
func mapError(c *fiber.Ctx, err error) error {
	var rl RateLimitError
	var re RemoteError
	switch {
	case errors.Is(err, ErrDisabled):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	case errors.Is(err, finding.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "finding not found")
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	case errors.Is(err, ErrOptedOut):
		return fiber.NewError(fiber.StatusForbidden, err.Error())
	case errors.Is(err, ErrInvalidKind):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, ErrDecided), errors.Is(err, ErrBusy), errors.Is(err, finding.ErrAssessmentPending):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	case errors.As(err, &rl):
		c.Set(fiber.HeaderRetryAfter, strconv.Itoa(int(math.Ceil(rl.RetryAfter.Seconds()))))
		return fiber.NewError(fiber.StatusTooManyRequests, err.Error())
	case errors.As(err, &re):
		// The provider's own words go to instance admins only.
		msg := re.Public()
		if authz.VisibleScope(c).AllAccess {
			msg = re.Error()
		}
		return fiber.NewError(fiber.StatusBadGateway, msg)
	}
	return err
}

// enabled answers 404 while AI triage is off.
func (h *Handler) enabled() error {
	if !h.svc.Enabled() {
		return fiber.NewError(fiber.StatusNotFound, ErrDisabled.Error())
	}
	return nil
}

// List handles GET /findings/{id}/ai-proposals: the finding's proposals and
// what asking would use (provider, model, whether the project opted out).
func (h *Handler) List(c *fiber.Ctx) error {
	if err := h.enabled(); err != nil {
		return err
	}
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	f, err := h.svc.findings.Get(c.UserContext(), id)
	if err != nil {
		return mapError(c, err)
	}
	optedOut, err := h.svc.OptedOut(c.UserContext(), f.ProjectID)
	if err != nil {
		return err
	}
	page := httpx.ParsePage(c)
	ps, err := h.svc.List(c.UserContext(), id, page.Limit+1, page.Offset)
	if err != nil {
		return err
	}
	hasMore := len(ps) > page.Limit
	if hasMore {
		ps = ps[:page.Limit]
	}
	return c.JSON(fiber.Map{
		"provider": h.svc.Provider(), "model": h.svc.Model(), "opted_out": optedOut,
		"proposals": ps, "pagination": httpx.Meta(page, len(ps), hasMore),
	})
}

// ListOpen handles GET /ai-proposals: open proposals across every project the
// caller can see, newest first; ?mine=true keeps the ones they asked for or
// whose finding is assigned to them.
func (h *Handler) ListOpen(c *fiber.Ctx) error {
	if err := h.enabled(); err != nil {
		return err
	}
	f := OpenFilter{}
	if scope := authz.VisibleScope(c); !scope.AllAccess {
		f.ProjectIDs = scope.ProjectIDs
		if f.ProjectIDs == nil {
			f.ProjectIDs = []string{}
		}
	}
	if c.QueryBool("mine") {
		f.Mine = auth.UserID(c)
	}
	page := httpx.ParsePage(c)
	f.Limit, f.Offset = page.Limit+1, page.Offset
	ps, err := h.svc.ListOpen(c.UserContext(), f)
	if err != nil {
		return err
	}
	hasMore := len(ps) > page.Limit
	if hasMore {
		ps = ps[:page.Limit]
	}
	return c.JSON(fiber.Map{"proposals": ps, "pagination": httpx.Meta(page, len(ps), hasMore)})
}

func kindParam(s string) (Kind, error) {
	k := Kind(strings.TrimSpace(s))
	if !k.Valid() {
		return "", fiber.NewError(fiber.StatusBadRequest, ErrInvalidKind.Error())
	}
	return k, nil
}

// Prompt handles GET /findings/{id}/ai-proposals/prompt?kind=: exactly what
// asking would send, shown before anything is sent.
func (h *Handler) Prompt(c *fiber.Ctx) error {
	if err := h.enabled(); err != nil {
		return err
	}
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	kind, err := kindParam(c.Query("kind"))
	if err != nil {
		return err
	}
	p, err := h.svc.Preview(c.UserContext(), id, kind)
	if err != nil {
		return mapError(c, err)
	}
	return c.JSON(p)
}

type askRequest struct {
	Kind string `json:"kind"`
}

// Ask handles POST /findings/{id}/ai-proposals: send the finding to the
// model and record its proposal (201). Nothing about the finding changes. An
// answer that fails validation is recorded as invalid: 502 with it.
func (h *Handler) Ask(c *fiber.Ctx) error {
	if err := h.enabled(); err != nil {
		return err
	}
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	var body askRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	kind, err := kindParam(body.Kind)
	if err != nil {
		return err
	}
	p, err := h.svc.Ask(c.UserContext(), id, kind, auth.UserID(c))
	if errors.Is(err, ErrInvalidAnswer) {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error(), "proposal": p})
	}
	if err != nil {
		return mapError(c, err)
	}
	return c.Status(fiber.StatusCreated).JSON(p)
}

type decisionRequest struct {
	Note string `json:"note"`
}

func ids(c *fiber.Ctx) (string, string, decisionRequest, error) {
	var body decisionRequest
	fid, err := httpx.ID(c, "findingID")
	if err != nil {
		return "", "", body, err
	}
	pid, err := httpx.ID(c, "proposalID")
	if err != nil {
		return "", "", body, err
	}
	if len(c.Body()) > 0 {
		if err := httpx.Parse(c, &body); err != nil {
			return "", "", body, err
		}
	}
	if len(body.Note) > 2000 {
		return "", "", body, fiber.NewError(fiber.StatusBadRequest, "note is at most 2000 characters")
	}
	return fid, pid, body, nil
}

// Accept handles POST /findings/{id}/ai-proposals/{pid}/accept: apply it as
// the caller (200), or file the request it needs — a pending assessment or a
// risk acceptance (202).
func (h *Handler) Accept(c *fiber.Ctx) error {
	if err := h.enabled(); err != nil {
		return err
	}
	fid, pid, body, err := ids(c)
	if err != nil {
		return err
	}
	res, err := h.svc.Accept(c.UserContext(), fid, pid, auth.UserID(c), strings.TrimSpace(body.Note))
	if err != nil {
		return mapError(c, err)
	}
	if res.Pending() {
		return c.Status(fiber.StatusAccepted).JSON(res)
	}
	return c.JSON(res)
}

// Reject handles POST /findings/{id}/ai-proposals/{pid}/reject.
func (h *Handler) Reject(c *fiber.Ctx) error {
	if err := h.enabled(); err != nil {
		return err
	}
	fid, pid, body, err := ids(c)
	if err != nil {
		return err
	}
	p, err := h.svc.Reject(c.UserContext(), fid, pid, auth.UserID(c), strings.TrimSpace(body.Note))
	if err != nil {
		return mapError(c, err)
	}
	return c.JSON(p)
}
