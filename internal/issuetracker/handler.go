package issuetracker

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/audit"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/secretbox"
)

// Handler exposes tracker config, finding↔issue links and the on-demand sync.
type Handler struct {
	svc   *Service
	audit auditWriter // optional: records webhook deliveries
}

// auditWriter records the webhook receiver's own audit entries
// (audit.Repository).
type auditWriter interface {
	Insert(ctx context.Context, e audit.Entry) error
}

// WithAudit records every webhook delivery in w.
func (h *Handler) WithAudit(w auditWriter) *Handler {
	h.audit = w
	return h
}

// NewHandler constructs a Handler.
func NewHandler(svc *Service) *Handler {
	return &Handler{svc: svc}
}

// Register mounts the routes. authz gates them: reading the config needs project
// viewer; changing or testing it needs project owner (it holds a credential and
// decides what gets filed in another system); creating an issue needs editor;
// /issue-trackers/* is instance-admin.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/projects/:projectID/issue-tracker", h.get)
	r.Put("/projects/:projectID/issue-tracker", h.put)
	r.Delete("/projects/:projectID/issue-tracker", h.delete)
	r.Post("/projects/:projectID/issue-tracker/test", h.test)
	r.Get("/findings/:findingID/issue", h.getLink)
	r.Post("/findings/:findingID/issue", h.createIssue)
	r.Post("/issue-trackers/sync", h.sync)
	r.Post("/projects/:projectID/issue-tracker/webhook-secret", h.rotateWebhookSecret)
	r.Delete("/projects/:projectID/issue-tracker/webhook-secret", h.clearWebhookSecret)
}

// RegisterPublic mounts the webhook receiver: unauthenticated, each delivery
// is verified with the tracker's own webhook secret instead.
func (h *Handler) RegisterPublic(r fiber.Router) {
	r.Post("/issue-trackers/:trackerID/webhook", h.webhook)
}

// maxWebhookBody bounds a delivery (the largest real ones, Jira's with the
// whole issue inside, are tens of KiB).
const maxWebhookBody = 1 << 20

func (h *Handler) webhook(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "trackerID")
	if err != nil {
		return err
	}
	if len(c.Body()) > maxWebhookBody {
		return fiber.NewError(fiber.StatusRequestEntityTooLarge, "webhook payload too large")
	}
	res, err := h.svc.HandleWebhook(c.UserContext(), id, func(k string) string { return c.Get(k) }, c.Body())
	defer h.auditDelivery(c, id, res, err)
	if err != nil {
		return mapWebhookErr(err)
	}
	return c.JSON(res)
}

// auditDelivery records a delivery: the secured group's recorder never sees
// this public route, and a delivery can resolve findings and add comments. A
// verified one is the tracker acting (system, "issue-tracker:<kind>"); one
// that failed verification proved nothing (anonymous).
func (h *Handler) auditDelivery(c *fiber.Ctx, trackerID string, res WebhookResult, err error) {
	if h.audit == nil {
		return
	}
	status := fiber.StatusOK
	var fe *fiber.Error
	switch {
	case errors.As(mapWebhookErr(err), &fe):
		status = fe.Code
	case err != nil:
		status = fiber.StatusInternalServerError
	}
	e := audit.Entry{
		ActorKind: audit.ActorSystem, ActorEmail: "issue-tracker:" + string(res.Kind),
		Action: "issue_trackers.webhook", ResourceType: "issue-trackers", ResourceID: trackerID,
		Method: c.Method(), Path: c.Path(), ClientIP: c.IP(), Status: status, Outcome: audit.OutcomeSuccess,
		RequestID: c.GetRespHeader(fiber.HeaderXRequestID),
	}
	if status >= 400 {
		e.Outcome = audit.OutcomeFailure
	}
	if errors.Is(err, ErrWebhookAuth) || res.Kind == "" {
		e.ActorKind, e.ActorEmail = audit.ActorAnonymous, ""
	}
	if res.ProjectID != "" {
		pid := res.ProjectID
		e.ProjectID = &pid
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(c.UserContext()), 5*time.Second)
	defer cancel()
	if err := h.audit.Insert(ctx, e); err != nil {
		slog.WarnContext(ctx, "issue webhook audit entry failed", "error", err)
	}
}

// mapWebhookErr is a delivery's error as the response it becomes.
func mapWebhookErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNoReceiver), errors.Is(err, secretbox.ErrNoKey):
		return fiber.NewError(fiber.StatusNotFound, "not found")
	case errors.Is(err, ErrWebhookAuth):
		return fiber.NewError(fiber.StatusUnauthorized, err.Error())
	case errors.Is(err, ErrWebhookPayload):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	return err
}

// rotateWebhookSecret turns the receiver on with a new secret, shown once:
// generated, or the tracker's own (Linear generates it) from the body.
func (h *Handler) rotateWebhookSecret(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var in struct {
		Secret string `json:"secret"`
	}
	if len(c.Body()) > 0 {
		if err := httpx.Parse(c, &in); err != nil {
			return err
		}
	}
	t, secret, err := h.svc.RotateWebhookSecret(c.UserContext(), id, in.Secret)
	if err != nil {
		return mapErr(err)
	}
	return c.JSON(fiber.Map{"secret": secret, "webhook_url": t.WebhookURL, "kind": t.Kind})
}

func (h *Handler) clearWebhookSecret(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	if err := h.svc.ClearWebhookSecret(c.UserContext(), id); err != nil {
		return mapErr(err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func mapErr(err error) error {
	var verr ValidationError
	switch {
	case errors.As(err, &verr), errors.Is(err, secretbox.ErrNoKey), errors.Is(err, ErrNoTracker):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrNoProject), errors.Is(err, ErrNoLink),
		errors.Is(err, finding.ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	return err
}

func (h *Handler) get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	t, err := h.svc.Get(c.UserContext(), id)
	if err != nil {
		return mapErr(err)
	}
	return c.JSON(t)
}

func (h *Handler) put(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var in Input
	if err := httpx.Parse(c, &in); err != nil {
		return err
	}
	t, err := h.svc.Put(c.UserContext(), id, in)
	if err != nil {
		return mapErr(err)
	}
	return c.JSON(t)
}

func (h *Handler) delete(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	if err := h.svc.Delete(c.UserContext(), id); err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// test reports whether the stored credentials can read the target. A tracker
// that rejects them is a 502 carrying the tracker's message.
func (h *Handler) test(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	if err := h.svc.Test(c.UserContext(), id); err != nil {
		if mapped := mapErr(err); mapped != err { //nolint:errorlint // identity check: did mapErr translate this error
			return mapped
		}
		return fiber.NewError(fiber.StatusBadGateway, "tracker check failed: "+remoteMessage(c, err))
	}
	return c.JSON(fiber.Map{"ok": true})
}

func (h *Handler) getLink(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	l, err := h.svc.Link(c.UserContext(), id)
	if err != nil {
		return mapErr(err)
	}
	return c.JSON(l)
}

// createIssue files the finding's issue now: 201 when created, 200 with the
// existing link when it already has one.
func (h *Handler) createIssue(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	l, created, err := h.svc.CreateIssue(c.UserContext(), id)
	if err != nil {
		if mapped := mapErr(err); mapped != err { //nolint:errorlint // identity check: did mapErr translate this error
			return mapped
		}
		return fiber.NewError(fiber.StatusBadGateway, "create issue failed: "+remoteMessage(c, err))
	}
	if created {
		return c.Status(fiber.StatusCreated).JSON(l)
	}
	return c.JSON(l)
}

func (h *Handler) sync(c *fiber.Ctx) error {
	res, err := h.svc.Sync(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(res)
}

// remoteMessage is err as shown to the caller: instance admins see what the
// tracker answered; anyone else (project owners can set the tracker URL) only
// the request and status, so the Test button can't read internal services.
func remoteMessage(c *fiber.Ctx, err error) string {
	var r RemoteError
	if !authz.VisibleScope(c).AllAccess && errors.As(err, &r) {
		return r.Public()
	}
	return err.Error()
}
