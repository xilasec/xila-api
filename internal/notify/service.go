package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/netguard"
	"github.com/xilasec/xila-api/internal/secretbox"
)

// channelLister is the slice of the repository the dispatcher needs.
type channelLister interface {
	ListForEvent(ctx context.Context, eventType, projectID, severity string) ([]Channel, error)
}

// deliveryLogger records send attempts (optional).
type deliveryLogger interface {
	LogDelivery(ctx context.Context, d Delivery) error
}

// Service dispatches events to matching channels and logs the outcome. Events
// go through the durable outbox (Notify → RunDispatcher); the channel Test
// button sends synchronously (SendTo).
type Service struct {
	channels    channelLister
	logger      deliveryLogger // may be nil
	outbox      outboxStore
	summaries   *Repository // summary schedules (nil in unit tests that don't use them)
	policy      DeliveryPolicy
	wake        chan struct{} // nudges this process's dispatcher after an enqueue
	client      *http.Client
	smtp        SMTPConfig
	maxAttempts int               // SendTo's in-request retries
	backoff     time.Duration     // SendTo's first retry wait
	cipher      *secretbox.Cipher // webhook signing secrets (nil: none can be stored or used)
	features    Features          // optional; nil = every feature on
}

// NewService wires the dispatcher against the repository. smtp may be the zero
// value, in which case email channels cannot be delivered (or created).
func NewService(repo *Repository, smtp SMTPConfig) *Service {
	return &Service{
		channels:    repo,
		logger:      repo,
		outbox:      repo,
		summaries:   repo,
		policy:      DefaultDeliveryPolicy,
		wake:        make(chan struct{}, 1),
		client:      netguard.NewClient(10 * time.Second),
		smtp:        smtp,
		maxAttempts: 3,
		backoff:     time.Second,
	}
}

// SetDeliveryPolicy sets the outbox retry/retention policy (NOTIFY_*).
func (s *Service) SetDeliveryPolicy(p DeliveryPolicy) { s.policy = p }

// SetSecretCipher sets the cipher sealing webhook signing secrets
// (INTEGRATION_SECRET_KEY). Without one, channels can't carry a secret.
func (s *Service) SetSecretCipher(c *secretbox.Cipher) { s.cipher = c }

// SealSecret encrypts a channel's signing secret, bound to its id.
func (s *Service) SealSecret(channelID, secret string) ([]byte, error) {
	return s.cipher.Seal(secret, channelID)
}

// Features reports runtime feature switches (feature.Store); people's own
// subscriptions are the "personal_notifications" feature.
type Features interface {
	Enabled(ctx context.Context, key string) bool
}

// WithFeatures stops routing events to personal channels (assignee, watchers)
// while "personal_notifications" is switched off. The admin-managed channels
// are unaffected; subscriptions are kept for when it is turned back on.
func (s *Service) WithFeatures(f Features) *Service {
	s.features = f
	return s
}

func (s *Service) personalOn(ctx context.Context) bool {
	return s.features == nil || s.features.Enabled(ctx, "personal_notifications")
}

// Notify queues an event for every subscribed channel in the durable outbox;
// the leader's dispatcher delivers it, retrying with backoff across restarts.
// Which channels get it is decided now, when the event happens. Cheap (one
// query + one insert); failures are logged, never returned — an alert must
// not fail the operation that raised it.
func (s *Service) Notify(ctx context.Context, e Event) {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	channels, err := s.channels.ListForEvent(ctx, e.Type, e.ProjectID, e.Severity)
	if err != nil {
		slog.WarnContext(ctx, "notify: list channels failed", "error", err, "event", e.Type)
		return
	}
	channels = s.applyFilters(ctx, e, channels)
	// People's own subscriptions: the finding's assignee, the project's watchers.
	if ps, ok := s.channels.(personalStore); ok && s.personalOn(ctx) {
		personal, err := ps.PersonalForEvent(ctx, e)
		if err != nil {
			slog.WarnContext(ctx, "notify: personal routing failed", "error", err, "event", e.Type)
		}
		channels = append(channels, personal...)
	}
	ids := make([]string, len(channels))
	for i, ch := range channels {
		ids[i] = ch.ID
	}
	if err := s.outbox.Enqueue(ctx, ids, e); err != nil {
		slog.ErrorContext(ctx, "notify: enqueue failed; event dropped", "error", err, "event", e.Type)
		return
	}
	if len(ids) > 0 {
		select {
		case s.wake <- struct{}{}:
		default:
		}
	}
}

// SendTo delivers an event to one channel (with retries) and logs the outcome,
// regardless of the channel's event subscription. Used by the test endpoint.
func (s *Service) SendTo(ctx context.Context, ch Channel, e Event) error {
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now()
	}
	attempts, status, err := s.deliver(ctx, ch, e, uuid.NewString(), s.maxAttempts)
	s.log(ctx, ch, e, attempts, status, err)
	return err
}

// SMTPConfigured reports whether email channels can be delivered.
func (s *Service) SMTPConfigured() bool { return s.smtp.Configured() }

// deliver sends to a channel, trying up to maxAttempts times with exponential
// backoff; deliveryID identifies the delivery to a generic webhook across
// attempts. It returns the number of attempts made, the last HTTP status (0 if
// none, and always 0 for SMTP), and the final error.
func (s *Service) deliver(ctx context.Context, ch Channel, e Event, deliveryID string, maxAttempts int) (int, int, error) {
	var sendOnce func() (int, error)
	switch {
	case ch.Type == TypeEmail:
		msg, rcpts, err := s.emailMessage(ch, e)
		if err != nil {
			return 0, 0, err
		}
		sendOnce = func() (int, error) { return 0, s.sendMail(ctx, rcpts, msg) }
	case ch.Type == TypeKafka:
		if ch.Kafka == nil {
			return 0, 0, fmt.Errorf("kafka channel %q has no config", ch.Name)
		}
		cfg := *ch.Kafka
		var password string
		if cfg.SASLMechanism != "" && ch.HasSecret {
			var err error
			// A password that can't be opened (key rotated away) fails the
			// delivery rather than connecting unauthenticated.
			if password, err = s.cipher.Open(ch.secretEnc, ch.ID); err != nil {
				return 0, 0, fmt.Errorf("kafka SASL password: %w", err)
			}
		}
		body := s.payload(ch, e)
		key := kafkaKey(cfg.KeyTemplate, e)
		sendOnce = func() (int, error) { return 0, s.sendKafka(ctx, ch, cfg, password, key, body) }
	default:
		body := s.payload(ch, e)
		var secret string
		if ch.Type == TypeWebhook && ch.HasSecret {
			var err error
			// A secret that can't be opened (key rotated away) fails the
			// delivery: sending it unsigned would teach receivers to accept
			// unsigned requests.
			if secret, err = s.cipher.Open(ch.secretEnc, ch.ID); err != nil {
				return 0, 0, fmt.Errorf("webhook signing secret: %w", err)
			}
		}
		sendOnce = func() (int, error) { return s.send(ctx, ch, body, deliveryID, secret) }
	}
	var lastErr error
	var lastStatus int
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		status, err := sendOnce()
		lastStatus = status
		if err == nil {
			return attempt, status, nil
		}
		lastErr = err
		if attempt < maxAttempts {
			select {
			case <-ctx.Done():
				return attempt, status, ctx.Err()
			case <-time.After(s.backoff * time.Duration(1<<(attempt-1))): // 1x, 2x, 4x…
			}
		}
	}
	return maxAttempts, lastStatus, lastErr
}

func (s *Service) payload(ch Channel, e Event) []byte {
	switch ch.Type {
	case TypeSlack:
		b, _ := json.Marshal(map[string]string{"text": slackText(e)})
		return b
	case TypeMattermost:
		b, _ := json.Marshal(map[string]string{"text": slackText(e), "username": "Xila"})
		return b
	case TypeTeams:
		b, _ := json.Marshal(teamsCard(e))
		return b
	}
	b, _ := json.Marshal(e) // webhook: the raw event
	return b
}

// send makes one POST, returning the HTTP status and an error for transport
// failures or non-2xx responses. A generic webhook carries the delivery id and
// timestamp, and — with a secret — the signature over this attempt's
// timestamp and body.
func (s *Service) send(ctx context.Context, ch Channel, body []byte, deliveryID, secret string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ch.URL, bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if ch.Type == TypeWebhook {
		ts := time.Now().Unix()
		req.Header.Set(HeaderDelivery, deliveryID)
		req.Header.Set(HeaderTimestamp, strconv.FormatInt(ts, 10))
		if secret != "" {
			req.Header.Set(HeaderSignature, Sign(secret, ts, body))
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("post: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return resp.StatusCode, fmt.Errorf("channel %q returned %d", ch.Name, resp.StatusCode)
	}
	return resp.StatusCode, nil
}

func (s *Service) log(ctx context.Context, ch Channel, e Event, attempts, status int, derr error) {
	if s.logger == nil {
		return
	}
	d := Delivery{
		ChannelID: &ch.ID, ChannelName: ch.Name, EventType: e.Type,
		Delivered: derr == nil, Attempts: attempts,
	}
	if status != 0 {
		d.StatusCode = &status
	}
	if derr != nil {
		d.Error = derr.Error()
	}
	if err := s.logger.LogDelivery(ctx, d); err != nil {
		slog.WarnContext(ctx, "notify: log delivery failed", "error", err)
	}
}

// slackText renders an event as a Slack message.
func slackText(e Event) string {
	var b strings.Builder
	if e.Severity != "" {
		fmt.Fprintf(&b, "[%s] ", strings.ToUpper(e.Severity))
	}
	b.WriteString("*" + e.Title + "*")
	if e.Text != "" {
		b.WriteString("\n" + e.Text)
	}
	for _, k := range sortedKeys(e.Fields) {
		fmt.Fprintf(&b, "\n• %s: %s", k, e.Fields[k])
	}
	return b.String()
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// teamsCard renders an event as an Office 365 connector MessageCard. This is
// the payload legacy Teams incoming webhooks take, and the one the Teams
// Workflows "Send webhook alerts to a channel" template (trigger "When a Teams
// webhook request is received") accepts from connector-style senders.
func teamsCard(e Event) map[string]any {
	facts := []map[string]string{}
	for _, k := range sortedKeys(e.Fields) {
		facts = append(facts, map[string]string{"name": k, "value": e.Fields[k]})
	}
	title := e.Title
	if e.Severity != "" {
		title = "[" + strings.ToUpper(e.Severity) + "] " + title
	}
	card := map[string]any{
		"@type":      "MessageCard",
		"@context":   "https://schema.org/extensions",
		"summary":    e.Title,
		"title":      title,
		"text":       e.Text,
		"themeColor": themeColor(e.Severity),
	}
	if len(facts) > 0 {
		card["sections"] = []map[string]any{{"facts": facts}}
	}
	return card
}

// themeColor maps a severity to the MessageCard accent colour (hex, no '#').
func themeColor(severity string) string {
	switch strings.ToLower(severity) {
	case "critical":
		return "B71C1C"
	case "high":
		return "E65100"
	case "medium":
		return "F9A825"
	case "low":
		return "1565C0"
	default:
		return "6E7781"
	}
}
