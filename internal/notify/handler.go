package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/secretbox"
)

// sender delivers to one channel (Service satisfies it).
type sender interface {
	SendTo(ctx context.Context, ch Channel, e Event) error
	SMTPConfigured() bool
	SealSecret(channelID, secret string) ([]byte, error)
}

// Handler exposes notification-channel CRUD and a test send.
type Handler struct {
	repo *Repository
	svc  sender
}

// NewHandler constructs a notify Handler.
func NewHandler(repo *Repository, svc sender) *Handler {
	return &Handler{repo: repo, svc: svc}
}

// Register mounts notification routes.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/notifications/channels", h.List)
	r.Post("/notifications/channels", h.Create)
	r.Patch("/notifications/channels/:channelID", h.Update)
	r.Delete("/notifications/channels/:channelID", h.Delete)
	r.Post("/notifications/channels/:channelID/test", h.Test)
	r.Get("/notifications/deliveries", h.Deliveries)
	r.Get("/notifications/pending", h.Pending)
}

// Pending lists queued deliveries not yet sent: new ones and failed ones
// awaiting a retry (with the last error).
func (h *Handler) Pending(c *fiber.Ctx) error {
	list, err := h.repo.ListPending(c.UserContext(), c.QueryInt("limit", 100))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"pending": list})
}

type createRequest struct {
	Name      string   `json:"name"`
	Type      string   `json:"type"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	ProjectID *string  `json:"project_id"`
	Enabled   *bool    `json:"enabled"`
	// SigningSecret (generic webhooks only) signs every delivery. Write-only.
	SigningSecret string `json:"signing_secret"`
	channelSettings
}

// channelSettings are the editable delivery rules of a channel.
type channelSettings struct {
	MinSeverity    string  `json:"min_severity"`
	Filter         *string `json:"filter"` // CEL over the event; "" clears, absent keeps
	Summary        string  `json:"summary"`
	SummaryHour    *int    `json:"summary_hour"`
	SummaryWeekday *int    `json:"summary_weekday"`
}

// apply validates s onto c (unset fields keep c's values).
func (s channelSettings) apply(c *Channel) error {
	switch strings.ToLower(s.MinSeverity) {
	case "", "critical", "high", "medium", "low", "info":
		c.MinSeverity = strings.ToLower(s.MinSeverity)
	default:
		return fmt.Errorf("min_severity must be critical, high, medium, low, info or empty")
	}
	if s.Filter != nil {
		f := strings.TrimSpace(*s.Filter)
		if err := CompileFilter(f); err != nil {
			return fmt.Errorf("filter: %w", err)
		}
		c.Filter = f
	}
	if s.Summary != "" {
		if !ValidSummary(s.Summary) {
			return fmt.Errorf("summary must be none, daily or weekly")
		}
		c.Summary = s.Summary
	}
	if c.Summary == "" {
		c.Summary = SummaryNone
	}
	if s.SummaryHour != nil {
		if *s.SummaryHour < 0 || *s.SummaryHour > 23 {
			return fmt.Errorf("summary_hour must be 0–23 (UTC)")
		}
		c.SummaryHour = *s.SummaryHour
	} else if c.CreatedAt.IsZero() {
		c.SummaryHour = 8
	}
	if s.SummaryWeekday != nil {
		if *s.SummaryWeekday < 0 || *s.SummaryWeekday > 6 {
			return fmt.Errorf("summary_weekday must be 0–6 (0 = Sunday)")
		}
		c.SummaryWeekday = *s.SummaryWeekday
	} else if c.CreatedAt.IsZero() {
		c.SummaryWeekday = 1
	}
	return nil
}

func (h *Handler) Create(c *fiber.Ctx) error {
	var body createRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	body.Name = strings.TrimSpace(body.Name)
	body.URL = strings.TrimSpace(body.URL)
	if body.Name == "" || body.URL == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name and url are required")
	}
	if err := ValidateTarget(body.Type, body.URL); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if body.Type == TypeEmail {
		if !h.svc.SMTPConfigured() {
			return fiber.NewError(fiber.StatusBadRequest, ErrSMTPNotConfigured.Error())
		}
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}

	ch := Channel{
		Name: body.Name, Type: body.Type, URL: body.URL, Events: body.Events,
		ProjectID: body.ProjectID, Enabled: enabled,
	}
	if err := body.channelSettings.apply(&ch); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if body.SigningSecret != "" {
		// The sealed secret is bound to the channel id, so pick it now.
		ch.ID = uuid.NewString()
		if err := h.setSecret(&ch, body.SigningSecret); err != nil {
			return err
		}
	}
	ch, err := h.repo.Create(c.UserContext(), ch)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(ch)
}

type updateRequest struct {
	Name    *string  `json:"name"`
	Events  []string `json:"events"`
	Enabled *bool    `json:"enabled"`
	// SigningSecret: absent keeps the secret, a value rotates it, "" removes it.
	SigningSecret *string `json:"signing_secret"`
	channelSettings
}

// setSecret seals secret onto a generic webhook channel (whose ID is set).
func (h *Handler) setSecret(ch *Channel, secret string) error {
	if ch.Type != TypeWebhook {
		return fiber.NewError(fiber.StatusBadRequest, "signing_secret is only for generic webhook channels")
	}
	if err := validSecret(secret); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	sealed, err := h.svc.SealSecret(ch.ID, secret)
	if errors.Is(err, secretbox.ErrNoKey) {
		return fiber.NewError(fiber.StatusBadRequest, "signing secrets need INTEGRATION_SECRET_KEY")
	}
	if err != nil {
		return err
	}
	ch.secretEnc, ch.HasSecret = sealed, true
	return nil
}

// Update handles PATCH /notifications/channels/{id}: name, events, enabled,
// minimum severity, summary schedule and signing secret. Type, target and
// scope are fixed — make a new channel to change where it goes.
func (h *Handler) Update(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "channelID")
	if err != nil {
		return err
	}
	var body updateRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	ch, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	if err != nil {
		return err
	}
	if body.Name != nil {
		if ch.Name = strings.TrimSpace(*body.Name); ch.Name == "" {
			return fiber.NewError(fiber.StatusBadRequest, "name is required")
		}
	}
	if body.Events != nil {
		ch.Events = body.Events
	}
	if body.Enabled != nil {
		ch.Enabled = *body.Enabled
	}
	if body.channelSettings.MinSeverity == "" && !hasKey(c.Body(), "min_severity") {
		body.channelSettings.MinSeverity = ch.MinSeverity // absent: keep it
	}
	if err := body.channelSettings.apply(&ch); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if body.SigningSecret != nil {
		if *body.SigningSecret == "" {
			ch.secretEnc, ch.HasSecret = nil, false
		} else if err := h.setSecret(&ch, *body.SigningSecret); err != nil {
			return err
		}
	}
	out, err := h.repo.Update(c.UserContext(), ch)
	if err != nil {
		return err
	}
	return c.JSON(out)
}

// hasKey reports whether a JSON object body names key at the top level.
func hasKey(body []byte, key string) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(body, &m) != nil {
		return false
	}
	_, ok := m[key]
	return ok
}

// Deliveries handles GET /notifications/deliveries (recent send attempts).
func (h *Handler) Deliveries(c *fiber.Ctx) error {
	deliveries, err := h.repo.ListDeliveries(c.UserContext(), 100)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"deliveries": deliveries})
}

func (h *Handler) List(c *fiber.Ctx) error {
	var (
		channels []Channel
		err      error
	)
	if pid := c.Query("project_id"); pid != "" {
		channels, err = h.repo.ListByProject(c.UserContext(), pid)
	} else {
		channels, err = h.repo.List(c.UserContext())
	}
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"channels": channels})
}

func (h *Handler) Delete(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "channelID")
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.UserContext(), id); errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "channel not found")
	} else if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Test sends a test event to one channel to verify it's wired up.
func (h *Handler) Test(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "channelID")
	if err != nil {
		return err
	}
	ch, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "channel not found")
	}
	if err != nil {
		return err
	}
	// Send synchronously, to this channel only, so the caller learns whether it
	// worked. The attempt is recorded in the delivery log like any other.
	err = h.svc.SendTo(c.UserContext(), ch, Event{
		Type:  EventTest,
		Title: "Xila test notification",
		Text:  "If you can see this, channel \"" + ch.Name + "\" is working.",
	})
	if err != nil {
		return fiber.NewError(fiber.StatusBadGateway, "delivery failed: "+err.Error())
	}
	return c.JSON(fiber.Map{"sent": true})
}
