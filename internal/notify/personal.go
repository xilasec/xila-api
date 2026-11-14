package notify

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/membership"
)

// Personal notifications: a person subscribes themselves to events on the
// findings assigned to them and on the projects they watch, delivered by
// email (their account address) and/or a personal Slack or Teams webhook.
// Each method is a personal channel row (owner_user_id), so delivery, retries
// and the delivery log are the outbox's. Two invariants:
//
//   - Access is checked when routing AND again when sending: someone who lost
//     access to the project (or was deactivated) in between gets nothing.
//   - A personal webhook URL is a secret: sealed with secretbox, write-only.

// PersonalTypes are the ways a person can be notified.
var PersonalTypes = []string{TypeEmail, "slack", "teams"}

// PersonalMethod is one way a person is notified.
type PersonalMethod struct {
	Enabled     bool     `json:"enabled"`
	Events      []string `json:"events"`       // event types, or "*"
	MinSeverity string   `json:"min_severity"` // "" = everything
	HasURL      bool     `json:"has_url"`      // webhook methods: a URL is set (write-only)
}

// PersonalPrefs is GET/PUT /me/notifications.
type PersonalPrefs struct {
	OnAssigned bool                      `json:"on_assigned"`
	OnWatched  bool                      `json:"on_watched"`
	Methods    map[string]PersonalMethod `json:"methods"`
	// Watching lists the projects the person watches (read-only here; watch
	// with PUT /projects/{id}/watch).
	Watching []WatchedProject `json:"watching"`
}

// WatchedProject is one watched project.
type WatchedProject struct {
	ProjectID   string `json:"project_id"`
	ProjectName string `json:"project_name"`
}

// personalAccessSQL holds for %[1]s being able to reach %[2]s: active,
// a person (not a service account), and an instance admin or a grant —
// membership.ProjectGrantsSQL, the same rows authorization uses. %[1]s must
// not reference an alias "u" (the subquery's own).
const personalAccessSQL = `EXISTS (SELECT 1 FROM users u WHERE u.id = %[1]s AND u.disabled_at IS NULL AND u.kind = 'user'
	AND (u.is_admin OR EXISTS (SELECT 1 FROM (` + membership.ProjectGrantsSQL + `) g
	                           WHERE g.user_id = u.id AND g.project_id = %[2]s)))`

// PersonalForEvent returns the personal channels an event reaches: the
// assignee of the finding it names (on_assigned) and the watchers of its
// project (on_watched), filtered by each channel's events and minimum
// severity, for people who can see the project.
func (r *Repository) PersonalForEvent(ctx context.Context, e Event) ([]Channel, error) {
	if e.ProjectID == "" {
		return []Channel{}, nil // a personal subscription is always about a project
	}
	q := `SELECT ` + channelColumns + ` FROM notification_channels c
		JOIN user_notification_prefs pr ON pr.user_id = c.owner_user_id
		WHERE c.enabled AND c.owner_user_id IS NOT NULL
		  AND (c.events @> ARRAY['*'] OR c.events @> ARRAY[$1])
		  AND (c.min_severity IS NULL OR $4 = '' OR ` + severityRank("$4") + ` >= ` + severityRank("c.min_severity") + `)
		  AND (
		        (pr.on_assigned AND $3 <> '' AND EXISTS (SELECT 1 FROM findings f
		              WHERE f.id = NULLIF($3, '')::uuid AND f.assignee_id = c.owner_user_id))
		     OR (pr.on_watched AND EXISTS (SELECT 1 FROM project_watches w
		              WHERE w.user_id = c.owner_user_id AND w.project_id = $2::uuid)))
		  AND ` + fmt.Sprintf(personalAccessSQL, "c.owner_user_id", "$2::uuid")
	rows, err := r.db.Query(ctx, q, e.Type, e.ProjectID, e.FindingID, strings.ToLower(e.Severity))
	if err != nil {
		return nil, fmt.Errorf("personal channels for event: %w", err)
	}
	defer rows.Close()
	out := []Channel{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, fmt.Errorf("scan channel: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// personalRecipient re-checks, at send time, that a personal channel's owner
// may still receive an event about projectID, and returns their current email
// address (for email channels).
func (r *Repository) personalRecipient(ctx context.Context, userID, projectID string) (email string, ok bool, err error) {
	// The outer alias must not be "u": personalAccessSQL's subquery uses it.
	q := `SELECT r.email, ` + fmt.Sprintf(personalAccessSQL, "r.id", "NULLIF($2, '')::uuid") + `
		FROM users r WHERE r.id = $1`
	err = r.db.QueryRow(ctx, q, userID, projectID).Scan(&email, &ok)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return email, ok, err
}

// personalStore is the Postgres repository's personal routing (the in-memory
// test fakes have none: they route to admin channels only).
type personalStore interface {
	PersonalForEvent(ctx context.Context, e Event) ([]Channel, error)
	personalRecipient(ctx context.Context, userID, projectID string) (string, bool, error)
}

// preparePersonal resolves a personal channel for sending: access re-checked,
// the email address current, the webhook URL unsealed. A refusal is final.
func (s *Service) preparePersonal(ctx context.Context, ch *Channel, e Event) error {
	ps, ok := s.channels.(personalStore)
	if !ok {
		return errors.New("personal channels need the database store")
	}
	email, allowed, err := ps.personalRecipient(ctx, *ch.OwnerUserID, e.ProjectID)
	if err != nil {
		return err
	}
	if !allowed {
		return errNoLongerAllowed
	}
	if ch.Type == TypeEmail {
		ch.URL = email
		return nil
	}
	if len(ch.urlEnc) == 0 || s.cipher == nil {
		return errors.New("no webhook URL is set (or INTEGRATION_SECRET_KEY is missing)")
	}
	url, err := s.cipher.Open(ch.urlEnc, ch.ID)
	if err != nil {
		return fmt.Errorf("unseal the webhook URL: %w", err)
	}
	ch.URL = url
	return nil
}

var errNoLongerAllowed = errors.New("the recipient can no longer see this project (access revoked or account deactivated)")

// --- preferences and watches ---

// PersonalPrefsOf returns a person's preferences (defaults when never saved).
func (r *Repository) PersonalPrefsOf(ctx context.Context, userID string) (PersonalPrefs, error) {
	p := PersonalPrefs{OnAssigned: true, OnWatched: true, Methods: map[string]PersonalMethod{}, Watching: []WatchedProject{}}
	err := r.db.QueryRow(ctx, `SELECT on_assigned, on_watched FROM user_notification_prefs WHERE user_id = $1`, userID).
		Scan(&p.OnAssigned, &p.OnWatched)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return p, fmt.Errorf("notification prefs: %w", err)
	}
	for _, t := range PersonalTypes {
		p.Methods[t] = PersonalMethod{Events: []string{"*"}}
	}
	rows, err := r.db.Query(ctx, `SELECT type, enabled, events, COALESCE(min_severity, ''), url_enc IS NOT NULL
		FROM notification_channels WHERE owner_user_id = $1`, userID)
	if err != nil {
		return p, fmt.Errorf("personal channels: %w", err)
	}
	for rows.Next() {
		var t string
		var m PersonalMethod
		if err := rows.Scan(&t, &m.Enabled, &m.Events, &m.MinSeverity, &m.HasURL); err != nil {
			rows.Close()
			return p, err
		}
		p.Methods[t] = m
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return p, err
	}
	w, err := r.db.Query(ctx, `SELECT w.project_id, p.name FROM project_watches w JOIN projects p ON p.id = w.project_id
		WHERE w.user_id = $1 ORDER BY p.name`, userID)
	if err != nil {
		return p, fmt.Errorf("watches: %w", err)
	}
	defer w.Close()
	for w.Next() {
		var x WatchedProject
		if err := w.Scan(&x.ProjectID, &x.ProjectName); err != nil {
			return p, err
		}
		p.Watching = append(p.Watching, x)
	}
	return p, w.Err()
}

// personalUpdate is one method's edit; URL nil keeps the stored one, "" removes it.
type personalUpdate struct {
	Enabled     *bool    `json:"enabled"`
	Events      []string `json:"events"`
	MinSeverity *string  `json:"min_severity"`
	URL         *string  `json:"url"`
}

// savePersonal writes a person's preferences and methods atomically.
func (r *Repository) savePersonal(ctx context.Context, userID string, onAssigned, onWatched *bool,
	methods map[string]personalUpdate, seal func(channelID, url string) ([]byte, error)) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_notification_prefs (user_id, on_assigned, on_watched) VALUES ($1, COALESCE($2, true), COALESCE($3, true))
		ON CONFLICT (user_id) DO UPDATE SET on_assigned = COALESCE($2, user_notification_prefs.on_assigned),
			on_watched = COALESCE($3, user_notification_prefs.on_watched), updated_at = now()`,
		userID, onAssigned, onWatched); err != nil {
		return fmt.Errorf("save prefs: %w", err)
	}
	for _, t := range PersonalTypes {
		m, ok := methods[t]
		if !ok {
			continue
		}
		var id string
		err := tx.QueryRow(ctx, `
			INSERT INTO notification_channels (name, type, url, events, enabled, owner_user_id)
			VALUES ('personal ' || $2, $2, '', '{*}', false, $1)
			ON CONFLICT (owner_user_id, type) WHERE owner_user_id IS NOT NULL DO UPDATE SET type = EXCLUDED.type
			RETURNING id`, userID, t).Scan(&id)
		if err != nil {
			return fmt.Errorf("personal channel: %w", err)
		}
		var urlEnc []byte
		setURL := m.URL != nil && t != TypeEmail
		if setURL && *m.URL != "" {
			if urlEnc, err = seal(id, *m.URL); err != nil {
				return err
			}
		}
		var events []string
		if m.Events != nil {
			events = m.Events
			if len(events) == 0 {
				events = []string{"*"}
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE notification_channels SET
				enabled = COALESCE($2, enabled), events = COALESCE($3, events),
				min_severity = CASE WHEN $4::text IS NULL THEN min_severity ELSE NULLIF($4, '') END,
				url_enc = CASE WHEN $5 THEN $6 ELSE url_enc END
			WHERE id = $1`, id, m.Enabled, events, m.MinSeverity, setURL, urlEnc); err != nil {
			return fmt.Errorf("save personal channel: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// Watch / Unwatch a project.
func (r *Repository) Watch(ctx context.Context, userID, projectID string, on bool) error {
	q := `INSERT INTO project_watches (user_id, project_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`
	if !on {
		q = `DELETE FROM project_watches WHERE user_id = $1 AND project_id = $2`
	}
	_, err := r.db.Exec(ctx, q, userID, projectID)
	return err
}

// Watching reports whether a user watches a project.
func (r *Repository) Watching(ctx context.Context, userID, projectID string) (bool, error) {
	var on bool
	err := r.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM project_watches WHERE user_id = $1 AND project_id = $2)`,
		userID, projectID).Scan(&on)
	return on, err
}

// PersonalDeliveries lists the delivery log of a person's own channels.
func (r *Repository) PersonalDeliveries(ctx context.Context, userID string, limit int) ([]Delivery, error) {
	return r.listDeliveries(ctx, `WHERE d.channel_id IN (SELECT id FROM notification_channels WHERE owner_user_id = $1)`,
		limit, userID)
}

// --- HTTP ---

// PersonalHandler serves /me/notifications and project watches. Any signed-in
// person may use it for themselves; service accounts can't subscribe.
type PersonalHandler struct {
	repo *Repository
	svc  *Service
}

// NewPersonalHandler constructs a PersonalHandler.
func NewPersonalHandler(repo *Repository, svc *Service) *PersonalHandler {
	return &PersonalHandler{repo: repo, svc: svc}
}

// Register mounts the routes.
func (h *PersonalHandler) Register(r fiber.Router) {
	r.Get("/me/notifications", h.get)
	r.Put("/me/notifications", h.put)
	r.Get("/me/notifications/deliveries", h.deliveries)
	r.Get("/projects/:projectID/watch", h.watching)
	r.Put("/projects/:projectID/watch", h.watch)
	r.Delete("/projects/:projectID/watch", h.unwatch)
}

func person(c *fiber.Ctx) (string, error) {
	a := auth.CurrentActor(c)
	if a.IsServiceAccount {
		return "", fiber.NewError(fiber.StatusForbidden, "service accounts can't subscribe to notifications")
	}
	return a.UserID, nil
}

func (h *PersonalHandler) get(c *fiber.Ctx) error {
	uid, err := person(c)
	if err != nil {
		return err
	}
	p, err := h.repo.PersonalPrefsOf(c.UserContext(), uid)
	if err != nil {
		return err
	}
	return c.JSON(p)
}

func (h *PersonalHandler) put(c *fiber.Ctx) error {
	uid, err := person(c)
	if err != nil {
		return err
	}
	var body struct {
		OnAssigned *bool                     `json:"on_assigned"`
		OnWatched  *bool                     `json:"on_watched"`
		Methods    map[string]personalUpdate `json:"methods"`
	}
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	for t, m := range body.Methods {
		if !slices.Contains(PersonalTypes, t) {
			return fiber.NewError(fiber.StatusBadRequest, "methods: want email, slack or teams")
		}
		if m.MinSeverity != nil {
			switch strings.ToLower(*m.MinSeverity) {
			case "", "critical", "high", "medium", "low", "info":
				*m.MinSeverity = strings.ToLower(*m.MinSeverity)
			default:
				return fiber.NewError(fiber.StatusBadRequest, "min_severity must be critical, high, medium, low, info or empty")
			}
		}
		if m.URL != nil && *m.URL != "" {
			if t == TypeEmail {
				return fiber.NewError(fiber.StatusBadRequest, "email goes to your account address; it takes no url")
			}
			if err := ValidateTarget(t, *m.URL); err != nil {
				return fiber.NewError(fiber.StatusBadRequest, err.Error())
			}
			if h.svc.cipher == nil {
				return fiber.NewError(fiber.StatusBadRequest, "personal webhooks need INTEGRATION_SECRET_KEY on the server")
			}
		}
		if t == TypeEmail && m.Enabled != nil && *m.Enabled && !h.svc.SMTPConfigured() {
			return fiber.NewError(fiber.StatusBadRequest, "SMTP is not configured")
		}
		body.Methods[t] = m
	}
	seal := func(id, url string) ([]byte, error) { return h.svc.cipher.Seal(url, id) }
	if err := h.repo.savePersonal(c.UserContext(), uid, body.OnAssigned, body.OnWatched, body.Methods, seal); err != nil {
		return err
	}
	return h.get(c)
}

func (h *PersonalHandler) deliveries(c *fiber.Ctx) error {
	uid, err := person(c)
	if err != nil {
		return err
	}
	list, err := h.repo.PersonalDeliveries(c.UserContext(), uid, 100)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"deliveries": list})
}

func (h *PersonalHandler) watching(c *fiber.Ctx) error {
	uid, err := person(c)
	if err != nil {
		return err
	}
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	on, err := h.repo.Watching(c.UserContext(), uid, id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"watching": on})
}

func (h *PersonalHandler) setWatch(c *fiber.Ctx, on bool) error {
	uid, err := person(c)
	if err != nil {
		return err
	}
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	if err := h.repo.Watch(c.UserContext(), uid, id, on); err != nil {
		return err
	}
	return c.JSON(fiber.Map{"watching": on})
}

func (h *PersonalHandler) watch(c *fiber.Ctx) error   { return h.setWatch(c, true) }
func (h *PersonalHandler) unwatch(c *fiber.Ctx) error { return h.setWatch(c, false) }
