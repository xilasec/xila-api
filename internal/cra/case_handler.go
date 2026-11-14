package cra

import (
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/httpx"
)

// CaseHandler serves Article 14 reporting: a project's product declaration
// and cases, the instance case list, and each case's transitions and report.
type CaseHandler struct{ svc *Service }

// NewCaseHandler constructs the handler.
func NewCaseHandler(svc *Service) *CaseHandler { return &CaseHandler{svc: svc} }

// Register mounts the routes. Authorization (internal/authz): project routes
// by project role (the product declaration is owner-level), case routes via
// the case's project (dismissing is owner-level), the list is scoped to the
// caller's projects, the sweep is instance-admin.
func (h *CaseHandler) Register(r fiber.Router) {
	r.Get("/projects/:projectID/cra", h.project)
	r.Put("/projects/:projectID/cra", h.setProduct)
	r.Post("/projects/:projectID/cra/cases", h.open)
	r.Get("/cra/cases", h.list)
	r.Post("/cra/sweep", h.sweep)
	r.Get("/cra/cases/:caseID", h.get)
	r.Patch("/cra/cases/:caseID", h.update)
	r.Get("/cra/cases/:caseID/report", h.report)
	r.Post("/cra/cases/:caseID/submit", h.submit)
	r.Post("/cra/cases/:caseID/dismiss", h.dismiss)
	r.Post("/cra/cases/:caseID/close", h.close)
}

func caseError(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	case errors.Is(err, ErrFindingNotFound):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	case errors.Is(err, ErrInvalid):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, ErrDuplicate), errors.Is(err, ErrNotInScope), errors.Is(err, ErrTransition):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	return err
}

func (h *CaseHandler) project(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	p, err := h.svc.Product(c.UserContext(), pid)
	if err != nil {
		return caseError(err)
	}
	cases, err := h.svc.List(c.UserContext(), CaseFilter{ProjectID: pid})
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"product": p, "manufacturer": h.svc.Manufacturer(), "cases": cases})
}

func (h *CaseHandler) setProduct(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var in Product
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	p, err := h.svc.SetProduct(c.UserContext(), pid, in)
	if err != nil {
		return caseError(err)
	}
	return c.JSON(p)
}

func (h *CaseHandler) open(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var in struct {
		FindingID string     `json:"finding_id"`
		AwareAt   *time.Time `json:"aware_at"`
		Note      string     `json:"note"`
	}
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	if in.FindingID == "" {
		return fiber.NewError(fiber.StatusBadRequest, "finding_id is required")
	}
	cs, err := h.svc.Open(c.UserContext(), pid, in.FindingID, auth.CurrentActor(c).UserID, strings.TrimSpace(in.Note), in.AwareAt)
	if err != nil {
		return caseError(err)
	}
	return c.Status(fiber.StatusCreated).JSON(cs)
}

func (h *CaseHandler) list(c *fiber.Ctx) error {
	page := httpx.ParsePage(c)
	f := CaseFilter{State: c.Query("state"), Limit: page.Limit + 1, Offset: page.Offset}
	switch State(f.State) {
	case "", "active", StateOpen, StateEarlyWarningSent, StateNotificationSent, StateFinalReportSent, StateClosed, StateDismissed:
	default:
		return fiber.NewError(fiber.StatusBadRequest, "invalid state")
	}
	if pid := c.Query("project_id"); pid != "" {
		if _, err := uuid.Parse(pid); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid project_id")
		}
		f.ProjectID = pid
	}
	if s := authz.VisibleScope(c); !s.AllAccess {
		f.ProjectIDs = append([]string{}, s.ProjectIDs...)
	}
	cases, err := h.svc.List(c.UserContext(), f)
	if err != nil {
		return err
	}
	more := len(cases) > page.Limit
	if more {
		cases = cases[:page.Limit]
	}
	return c.JSON(fiber.Map{"cases": cases, "pagination": httpx.Meta(page, len(cases), more)})
}

func (h *CaseHandler) get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "caseID")
	if err != nil {
		return err
	}
	cs, err := h.svc.Get(c.UserContext(), id)
	if err != nil {
		return caseError(err)
	}
	events, err := h.svc.Events(c.UserContext(), id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"case": cs, "events": events})
}

func (h *CaseHandler) update(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "caseID")
	if err != nil {
		return err
	}
	var in Edit
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	cs, err := h.svc.Update(c.UserContext(), id, auth.CurrentActor(c).UserID, in)
	if err != nil {
		return caseError(err)
	}
	return c.JSON(cs)
}

func (h *CaseHandler) report(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "caseID")
	if err != nil {
		return err
	}
	p, err := h.svc.Payload(c.UserContext(), id, Stage(c.Query("stage")))
	if err != nil {
		return caseError(err)
	}
	c.Set(fiber.HeaderCacheControl, "no-store")
	return c.JSON(p)
}

func (h *CaseHandler) submit(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "caseID")
	if err != nil {
		return err
	}
	var in struct {
		Stage     Stage  `json:"stage"`
		Reference string `json:"reference"`
		Note      string `json:"note"`
	}
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	cs, err := h.svc.Submit(c.UserContext(), id, auth.CurrentActor(c).UserID, in.Stage,
		strings.TrimSpace(in.Reference), strings.TrimSpace(in.Note))
	if err != nil {
		return caseError(err)
	}
	return c.JSON(cs)
}

func (h *CaseHandler) dismiss(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "caseID")
	if err != nil {
		return err
	}
	var in struct {
		Reason string `json:"reason"`
	}
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	cs, err := h.svc.Dismiss(c.UserContext(), id, auth.CurrentActor(c).UserID, in.Reason)
	if err != nil {
		return caseError(err)
	}
	return c.JSON(cs)
}

func (h *CaseHandler) close(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "caseID")
	if err != nil {
		return err
	}
	var in struct {
		Note string `json:"note"`
	}
	if len(c.Body()) > 0 {
		if err := httpx.Parse(c, &in); err != nil {
			return err
		}
	}
	cs, err := h.svc.Close(c.UserContext(), id, auth.CurrentActor(c).UserID, strings.TrimSpace(in.Note))
	if err != nil {
		return caseError(err)
	}
	return c.JSON(cs)
}

func (h *CaseHandler) sweep(c *fiber.Ctx) error {
	res, err := h.svc.Sweep(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(res)
}
