// Package notify delivers events to outbound channels: generic webhooks, Slack,
// Microsoft Teams and Mattermost incoming webhooks, email (SMTP) and Kafka topics.
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
)

// Event types.
const (
	// Risk acceptances (finding.RiskAcceptance): a request waiting for
	// approval, an approval (its findings become risk_accepted), one about to
	// lapse, and one that lapsed (its findings reopened).
	EventRiskAcceptanceRequested = "risk_acceptance.requested"
	EventRiskAcceptanceApproved  = "risk_acceptance.approved"
	EventRiskAcceptanceExpiring  = "risk_acceptance.expiring"
	EventRiskAcceptanceExpired   = "risk_acceptance.expired"
	// EventExceptionExpired: false positive / won't fix exceptions lapsed.
	EventExceptionExpired = "exception.expired"
	EventCriticalFinding  = "finding.critical"
	EventExploitable      = "finding.exploitable"
	EventSLABreach        = "finding.sla_breach"
	EventSLADueSoon       = "finding.sla_due_soon"
	// EventPolicyViolation: an evaluation introduced violations of fail-state
	// component policies (one event per project per evaluation).
	EventPolicyViolation = "policy.violation"
	// EventIngestionAnomaly: a project's intake looks broken (a scanner went
	// silent, an upload reported far fewer findings, scans or pulls failing).
	EventIngestionAnomaly = "ingestion.anomaly"
	// CRA Article 14 reporting (internal/cra): a case opened for an actively
	// exploited vulnerability in an in-scope product, and a reporting deadline
	// 6 h away or passed — each alerted once per case and stage.
	EventCRACaseOpened     = "cra.case_opened"
	EventCRADeadlineDue    = "cra.deadline_due_soon"
	EventCRADeadlineMissed = "cra.deadline_missed"
	// EventFindingAssigned: a finding got a (new) assignee — what personal
	// "assigned to me" subscriptions hear.
	EventFindingAssigned = "finding.assigned"
	// EventMention: a comment named a user with @email or @name. Carries
	// Event.UserIDs (already resolved against the project's members) instead
	// of a project-wide audience; only the in-app inbox (internal/inbox) and
	// an admin channel subscribed to it or "*" act on it.
	EventMention = "mention"
	// EventSummary is a channel's scheduled summary (Channel.Summary). It goes
	// to that channel alone, whatever its event subscription.
	EventSummary = "summary"
	EventTest    = "test"
)

// ErrNotFound is returned when a channel does not exist.
var ErrNotFound = errors.New("notification channel not found")

// Channel is an outbound notification destination.
type Channel struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`       // webhook | slack | teams | mattermost | email
	URL       string    `json:"url"`        // http(s) URL; for email, comma-separated recipients
	Events    []string  `json:"events"`     // event types, or "*" for all
	ProjectID *string   `json:"project_id"` // nil = all projects (global)
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	// MinSeverity skips events that carry a lower severity ("" = everything).
	// Events without a severity (summaries, policy violations) always pass.
	MinSeverity string `json:"min_severity"`
	// Filter is an optional CEL expression over the event (EventSchema); the
	// channel gets the event only when it holds. "" = none.
	Filter string `json:"filter"`
	// Summary schedules a summary of the channel's scope: "none", "daily" at
	// SummaryHour, or "weekly" on SummaryWeekday (0 = Sunday) at SummaryHour,
	// UTC.
	Summary        string     `json:"summary"`
	SummaryHour    int        `json:"summary_hour"`
	SummaryWeekday int        `json:"summary_weekday"`
	LastSummaryAt  *time.Time `json:"last_summary_at"`
	// HasSecret says a generic webhook signs its deliveries (X-Xila-Signature).
	// The secret itself is write-only: sealed with secretbox (AAD = the
	// channel id) in secretEnc and never serialized.
	HasSecret bool `json:"has_secret"`
	secretEnc []byte
	// OwnerUserID marks a personal channel (a user's own subscription, see
	// personal.go); nil for the admin-managed channels. A personal webhook's
	// URL is sealed in urlEnc, an email channel's address is the owner's.
	OwnerUserID *string `json:"-"`
	urlEnc      []byte
	// Kafka carries kafka channel settings (type == TypeKafka, nil for every
	// other type): brokers, TLS and SASL mechanism/username. The topic is the
	// channel's URL. The SASL password is never returned — HasSecret says
	// whether one is sealed, exactly like a generic webhook's signing secret.
	Kafka     *KafkaConfig `json:"kafka,omitempty"`
	configRaw []byte
}

// Delivery is an audit record of a single send attempt.
type Delivery struct {
	ID          string    `json:"id"`
	ChannelID   *string   `json:"channel_id"`
	ChannelName string    `json:"channel_name"`
	EventType   string    `json:"event_type"`
	Delivered   bool      `json:"delivered"`
	StatusCode  *int      `json:"status_code"`
	Attempts    int       `json:"attempts"`
	Error       string    `json:"error"`
	CreatedAt   time.Time `json:"created_at"`
}

// Event is a notification payload.
type Event struct {
	Type      string            `json:"type"`
	Title     string            `json:"title"`
	Text      string            `json:"text"`
	Severity  string            `json:"severity,omitempty"`
	ProjectID string            `json:"project_id,omitempty"`
	FindingID string            `json:"finding_id,omitempty"`
	Fields    map[string]string `json:"fields,omitempty"`
	Timestamp time.Time         `json:"timestamp"`
	// UserIDs targets an event at specific people instead of a project's
	// usual audience (EventMention: the comment's resolved @mentions). The
	// in-app inbox (internal/inbox) fans out to exactly these users; channels
	// and personal (assignee/watcher) routing ignore it.
	UserIDs []string `json:"user_ids,omitempty"`
}

// severityRank orders severities in SQL (critical 5 … info 1, unknown 0).
func severityRank(expr string) string {
	return `CASE ` + expr + ` WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END`
}

// Repository provides access to notification_channels.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

const channelColumns = `id, name, type, url, events, project_id, enabled, created_at,
	COALESCE(min_severity, ''), summary, summary_hour, summary_weekday, last_summary_at, signing_secret, filter,
	owner_user_id, url_enc, config`

// SetKafkaConfig stores cfg as the channel's config (brokers, TLS and SASL
// settings; the topic stays in URL).
func (c *Channel) SetKafkaConfig(cfg KafkaConfig) error {
	b, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	c.configRaw, c.Kafka = b, &cfg
	return nil
}

// decodeKafka unmarshals the config column into Kafka for a kafka channel.
func (c *Channel) decodeKafka(raw []byte) error {
	if len(raw) == 0 {
		return nil
	}
	var cfg KafkaConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("decode kafka config: %w", err)
	}
	c.Kafka = &cfg
	return nil
}

func scanChannel(row pgx.Row) (Channel, error) {
	var c Channel
	var cfgRaw []byte
	if err := row.Scan(&c.ID, &c.Name, &c.Type, &c.URL, &c.Events, &c.ProjectID, &c.Enabled, &c.CreatedAt,
		&c.MinSeverity, &c.Summary, &c.SummaryHour, &c.SummaryWeekday, &c.LastSummaryAt, &c.secretEnc, &c.Filter,
		&c.OwnerUserID, &c.urlEnc, &cfgRaw); err != nil {
		return Channel{}, err
	}
	c.HasSecret = len(c.secretEnc) > 0
	if c.Type == TypeKafka {
		if err := c.decodeKafka(cfgRaw); err != nil {
			return Channel{}, err
		}
	}
	return c, nil
}

// Create inserts a channel (with c.ID when set: a sealed signing secret is
// bound to it). A summary schedule starts from now: the first one goes out at
// the next slot, not immediately for a slot already past today.
func (r *Repository) Create(ctx context.Context, c Channel) (Channel, error) {
	const q = `INSERT INTO notification_channels
		(id, name, type, url, events, project_id, enabled, min_severity, summary, summary_hour, summary_weekday,
		 last_summary_at, signing_secret, filter, config)
		VALUES (COALESCE(NULLIF($11, '')::uuid, gen_random_uuid()), $1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8, $9, $10,
		        CASE WHEN $8 <> 'none' THEN now() END, $12, $13, COALESCE($14::jsonb, '{}'::jsonb))
		RETURNING ` + channelColumns
	events := c.Events
	if len(events) == 0 {
		events = []string{"*"}
	}
	if c.Summary == "" {
		c.Summary = SummaryNone
	}
	out, err := scanChannel(r.db.QueryRow(ctx, q, c.Name, c.Type, c.URL, events, c.ProjectID, c.Enabled,
		c.MinSeverity, c.Summary, c.SummaryHour, c.SummaryWeekday, c.ID, c.secretEnc, c.Filter, c.configRaw))
	if err != nil {
		return Channel{}, fmt.Errorf("insert channel: %w", err)
	}
	return out, nil
}

// Update rewrites a channel's settings and signing secret (not its type,
// target or scope). A schedule that changes restarts from now.
func (r *Repository) Update(ctx context.Context, c Channel) (Channel, error) {
	const q = `UPDATE notification_channels SET
			name = $2, events = $3, enabled = $4, min_severity = NULLIF($5, ''), signing_secret = $9, filter = $10,
			config = COALESCE($11::jsonb, config),
			last_summary_at = CASE
				WHEN $6 = 'none' THEN NULL
				WHEN (summary, summary_hour, summary_weekday) IS DISTINCT FROM ($6, $7, $8) THEN now()
				ELSE last_summary_at END,
			summary = $6, summary_hour = $7, summary_weekday = $8
		WHERE id = $1 RETURNING ` + channelColumns
	events := c.Events
	if len(events) == 0 {
		events = []string{"*"}
	}
	out, err := scanChannel(r.db.QueryRow(ctx, q, c.ID, c.Name, events, c.Enabled, c.MinSeverity,
		c.Summary, c.SummaryHour, c.SummaryWeekday, c.secretEnc, c.Filter, c.configRaw))
	if errors.Is(err, pgx.ErrNoRows) {
		return Channel{}, ErrNotFound
	}
	if err != nil {
		return Channel{}, fmt.Errorf("update channel: %w", err)
	}
	return out, nil
}

// List returns all channels.
func (r *Repository) List(ctx context.Context) ([]Channel, error) {
	const q = `SELECT ` + channelColumns + ` FROM notification_channels WHERE owner_user_id IS NULL ORDER BY created_at DESC`
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list channels: %w", err)
	}
	defer rows.Close()
	channels := []Channel{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, fmt.Errorf("scan channel: %w", err)
		}
		channels = append(channels, c)
	}
	return channels, rows.Err()
}

// ListByProject returns channels scoped to a specific project.
func (r *Repository) ListByProject(ctx context.Context, projectID string) ([]Channel, error) {
	const q = `SELECT ` + channelColumns + ` FROM notification_channels WHERE project_id = $1 AND owner_user_id IS NULL ORDER BY created_at DESC`
	rows, err := r.db.Query(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("list channels by project: %w", err)
	}
	defer rows.Close()
	channels := []Channel{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, fmt.Errorf("scan channel: %w", err)
		}
		channels = append(channels, c)
	}
	return channels, rows.Err()
}

// ListForEvent returns enabled channels subscribed to an event type (or "*").
// Global channels (project_id IS NULL) always match; project-scoped channels
// only match when the event carries that project id (empty projectID = none).
//
// A channel with a min_severity only gets events at or above it; an event with
// no severity always passes.
func (r *Repository) ListForEvent(ctx context.Context, eventType, projectID, severity string) ([]Channel, error) {
	q := `SELECT ` + channelColumns + ` FROM notification_channels
		WHERE enabled AND owner_user_id IS NULL
		  AND (events @> ARRAY['*'] OR events @> ARRAY[$1])
		  AND (project_id IS NULL OR project_id = $2::uuid)
		  AND (min_severity IS NULL OR $3 = '' OR ` + severityRank("$3") + ` >= ` + severityRank("min_severity") + `)
		  -- An archived project's events go nowhere.
		  AND ($2::uuid IS NULL OR NOT EXISTS (SELECT 1 FROM projects p WHERE p.id = $2::uuid AND NOT (` + strings.TrimSpace(archive.Project("p")) + `)))`
	var pid *string
	if projectID != "" {
		pid = &projectID
	}
	rows, err := r.db.Query(ctx, q, eventType, pid, strings.ToLower(severity))
	if err != nil {
		return nil, fmt.Errorf("list channels for event: %w", err)
	}
	defer rows.Close()
	channels := []Channel{}
	for rows.Next() {
		c, err := scanChannel(rows)
		if err != nil {
			return nil, fmt.Errorf("scan channel: %w", err)
		}
		channels = append(channels, c)
	}
	return channels, rows.Err()
}

// LogDelivery records a send attempt.
func (r *Repository) LogDelivery(ctx context.Context, d Delivery) error {
	const q = `INSERT INTO notification_deliveries
		(channel_id, channel_name, event_type, delivered, status_code, attempts, error)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := r.db.Exec(ctx, q, d.ChannelID, d.ChannelName, d.EventType, d.Delivered, d.StatusCode, d.Attempts, d.Error)
	if err != nil {
		return fmt.Errorf("log delivery: %w", err)
	}
	return nil
}

// ListDeliveries returns recent delivery attempts, newest first.
func (r *Repository) ListDeliveries(ctx context.Context, limit int) ([]Delivery, error) {
	return r.listDeliveries(ctx, "", limit)
}

// listDeliveries lists deliveries matching where (over alias d, with args as
// $1…), newest first.
func (r *Repository) listDeliveries(ctx context.Context, where string, limit int, args ...any) ([]Delivery, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	q := `SELECT d.id, d.channel_id, d.channel_name, d.event_type, d.delivered, d.status_code, d.attempts, d.error, d.created_at
		FROM notification_deliveries d ` + where + ` ORDER BY d.created_at DESC LIMIT $` + strconv.Itoa(len(args)+1)
	rows, err := r.db.Query(ctx, q, append(args, limit)...)
	if err != nil {
		return nil, fmt.Errorf("list deliveries: %w", err)
	}
	defer rows.Close()
	out := []Delivery{}
	for rows.Next() {
		var d Delivery
		if err := rows.Scan(&d.ID, &d.ChannelID, &d.ChannelName, &d.EventType, &d.Delivered,
			&d.StatusCode, &d.Attempts, &d.Error, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan delivery: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// Get returns a channel by id.
func (r *Repository) Get(ctx context.Context, id string) (Channel, error) {
	const q = `SELECT ` + channelColumns + ` FROM notification_channels WHERE id = $1 AND owner_user_id IS NULL`
	c, err := scanChannel(r.db.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Channel{}, ErrNotFound
	}
	if err != nil {
		return Channel{}, fmt.Errorf("get channel: %w", err)
	}
	return c, nil
}

// Delete removes a channel.
func (r *Repository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM notification_channels WHERE id = $1 AND owner_user_id IS NULL`, id)
	if err != nil {
		return fmt.Errorf("delete channel: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
