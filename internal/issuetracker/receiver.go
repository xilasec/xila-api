package issuetracker

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/secretbox"
)

// webhookAAD binds a sealed webhook secret to its tracker row.
func webhookAAD(trackerID string) string { return "issue-webhook:" + trackerID }

// WebhookPath is where a tracker delivers its webhooks (under /api/v1).
func WebhookPath(trackerID string) string { return "/issue-trackers/" + trackerID + "/webhook" }

// minWebhookSecret is the shortest secret accepted from a tracker that
// generates its own (Linear, optionally Jira).
const minWebhookSecret = 16

// RotateWebhookSecret turns the project's webhook receiver on with a new
// secret, returned this once (it is write-only afterwards); the previous
// secret stops working. provided is the tracker's own secret, for trackers
// that generate it; empty generates one.
func (s *Service) RotateWebhookSecret(ctx context.Context, projectID, provided string) (Tracker, string, error) {
	if !s.cipher.Configured() {
		return Tracker{}, "", secretbox.ErrNoKey
	}
	t, err := s.store.GetByProject(ctx, projectID)
	if err != nil {
		return Tracker{}, "", err
	}
	secret := strings.TrimSpace(provided)
	switch {
	case secret == "":
		raw := make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return Tracker{}, "", err
		}
		secret = base64.RawURLEncoding.EncodeToString(raw)
	case len(secret) < minWebhookSecret || len(secret) > 512:
		return Tracker{}, "", invalid("secret must be %d to 512 characters", minWebhookSecret)
	}
	sealed, err := s.cipher.Seal(secret, webhookAAD(t.ID))
	if err != nil {
		return Tracker{}, "", err
	}
	if err := s.store.SetWebhookSecret(ctx, t.ID, sealed); err != nil {
		return Tracker{}, "", err
	}
	t.HasWebhookSecret = true
	return s.withWebhookURL(t), secret, nil
}

// ClearWebhookSecret turns the project's webhook receiver off.
func (s *Service) ClearWebhookSecret(ctx context.Context, projectID string) error {
	t, err := s.store.GetByProject(ctx, projectID)
	if err != nil {
		return err
	}
	return s.store.SetWebhookSecret(ctx, t.ID, nil)
}

// ErrNoReceiver answers a delivery for a tracker that does not exist, is
// disabled or has no webhook secret: indistinguishable, so the endpoint
// reveals nothing about which trackers exist.
var ErrNoReceiver = errors.New("no webhook receiver")

// webhookTimeout bounds the tracker calls one delivery makes (Linear, for
// one, gives up on a receiver after 5 s); what doesn't finish is picked up
// by the next sync run.
const webhookTimeout = 4 * time.Second

// WebhookResult is what a delivery did.
type WebhookResult struct {
	Ignored  bool `json:"ignored"` // an event Xila does not act on
	Links    int  `json:"links"`   // links reconciled
	Comments int  `json:"comments"`
	// The tracker the delivery reached, for its audit entry (zero when none).
	ProjectID string `json:"-"`
	Kind      Kind   `json:"-"`
}

// HandleWebhook verifies and applies one delivery to trackerID (M13 13.18).
// A state change reconciles the issue's links (re-reading the issue through
// the API); a comment, with comment sync on, is added to the finding once.
func (s *Service) HandleWebhook(ctx context.Context, trackerID string, header func(string) string, body []byte) (WebhookResult, error) {
	var res WebhookResult
	t, err := s.store.Get(ctx, trackerID)
	if errors.Is(err, ErrNotFound) || (err == nil && (!t.Enabled || !t.HasWebhookSecret)) {
		return res, ErrNoReceiver
	}
	if err != nil {
		return res, err
	}
	res.ProjectID, res.Kind = t.ProjectID, t.Kind
	secret, err := s.cipher.Open(t.webhookSecretEnc, webhookAAD(t.ID))
	if err != nil {
		return res, err
	}
	if err := VerifyWebhook(t.Kind, header, body, secret); err != nil {
		return res, err
	}
	ev, ok, err := ParseWebhook(t.Kind, header, body, time.Now())
	if err != nil || !ok {
		res.Ignored = err == nil
		return res, err
	}
	links, err := s.store.LinksByExternal(ctx, t.ID, ev.ExternalID)
	if err != nil {
		return res, err
	}
	if len(links) == 0 {
		res.Ignored = true
		return res, nil
	}
	if ev.Comment != nil {
		if t.SyncComments && !strings.Contains(ev.Comment.Body, pushedFooter) && strings.TrimSpace(ev.Comment.Body) != "" {
			author := string(t.Kind)
			if a := strings.TrimSpace(ev.Comment.Author); a != "" {
				author += ": " + a
			}
			for _, l := range links {
				created, err := s.store.AddInbound(ctx, l, ev.Comment.ID, author, truncateRunes(ev.Comment.Body, maxDescription))
				if err != nil {
					return res, err
				}
				if created {
					res.Comments++
				}
			}
		}
		return res, nil
	}
	c, err := s.client(t)
	if err != nil {
		return res, err
	}
	callCtx, cancel := context.WithTimeout(ctx, webhookTimeout)
	defer cancel()
	var sync SyncResult
	for _, l := range links {
		if err := s.syncLink(callCtx, t, c, l.ID, &sync); err != nil {
			// The delivery itself was fine; the next sync run retries.
			slog.WarnContext(ctx, "issue webhook reconcile failed", "tracker_id", t.ID, "issue", ev.ExternalID, "error", err)
			continue
		}
		res.Links++
	}
	return res, nil
}
