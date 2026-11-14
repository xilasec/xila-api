package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// DeliveryPolicy governs durable delivery through the outbox.
type DeliveryPolicy struct {
	MaxAttempts int           // NOTIFY_MAX_ATTEMPTS: give up after this many tries
	RetryBase   time.Duration // NOTIFY_RETRY_BASE: wait after the first failure; doubles each time
	RetryMax    time.Duration // NOTIFY_RETRY_MAX: cap on the wait
	Retention   time.Duration // NOTIFY_RETENTION: keep delivered / given-up rows this long
}

// DefaultDeliveryPolicy: eight tries over roughly three hours.
var DefaultDeliveryPolicy = DeliveryPolicy{MaxAttempts: 8, RetryBase: 30 * time.Second, RetryMax: time.Hour, Retention: 7 * 24 * time.Hour}

// retryAfter is the wait before attempt n+1, after n failed attempts.
func (p DeliveryPolicy) retryAfter(n int) time.Duration {
	d := p.RetryBase
	for i := 1; i < n && d < p.RetryMax; i++ {
		d *= 2
	}
	return min(d, p.RetryMax)
}

// OutboxItem is one claimed delivery: an event for one channel.
type OutboxItem struct {
	ID int64
	// DeliveryID identifies the row to receivers (X-Xila-Delivery); every
	// retry of the row sends the same one.
	DeliveryID string
	Channel    Channel
	Event      Event
	Attempts   int // including this one
}

// PendingDelivery is an undelivered outbox row, for the admin view.
type PendingDelivery struct {
	ID            int64     `json:"id"`
	ChannelID     string    `json:"channel_id"`
	ChannelName   string    `json:"channel_name"`
	EventType     string    `json:"event_type"`
	Title         string    `json:"title"`
	Attempts      int       `json:"attempts"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
	LastStatus    *int      `json:"last_status"`
	LastError     string    `json:"last_error"`
	CreatedAt     time.Time `json:"created_at"`
}

// outboxStore is the slice of the repository the dispatcher needs.
type outboxStore interface {
	Enqueue(ctx context.Context, channelIDs []string, e Event) error
	Claim(ctx context.Context, limit int, lease time.Duration) ([]OutboxItem, error)
	Finish(ctx context.Context, id int64, status int, errMsg string, delivered bool, retryAt *time.Time, refund bool) error
	PurgeOutbox(ctx context.Context, olderThan time.Duration) (int64, error)
}

// Enqueue stores one outbox row per channel.
func (r *Repository) Enqueue(ctx context.Context, channelIDs []string, e Event) error {
	if len(channelIDs) == 0 {
		return nil
	}
	ev, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("encode event: %w", err)
	}
	_, err = r.db.Exec(ctx, `INSERT INTO notification_outbox (channel_id, event)
		SELECT unnest($1::uuid[]), $2::jsonb`, channelIDs, ev)
	if err != nil {
		return fmt.Errorf("enqueue notification: %w", err)
	}
	return nil
}

// Claim leases up to limit due rows to this dispatcher. SKIP LOCKED keeps two
// dispatchers (a leader handover) off the same row; the lease hands a row back
// if its dispatcher dies before Finish.
func (r *Repository) Claim(ctx context.Context, limit int, lease time.Duration) ([]OutboxItem, error) {
	rows, err := r.db.Query(ctx, `
		WITH claimed AS (
			UPDATE notification_outbox o
			   SET locked_until = now() + make_interval(secs => $2), attempts = o.attempts + 1
			 WHERE o.id IN (
				SELECT id FROM notification_outbox
				 WHERE delivered_at IS NULL AND failed_at IS NULL AND next_attempt_at <= now()
				   AND (locked_until IS NULL OR locked_until < now())
				 ORDER BY next_attempt_at, id
				 LIMIT $1
				 FOR UPDATE SKIP LOCKED)
			RETURNING o.id, o.delivery_id, o.channel_id, o.event, o.attempts)
		SELECT claimed.id, claimed.delivery_id, claimed.event, claimed.attempts,
		       c.id, c.name, c.type, c.url, c.events, c.project_id, c.enabled, c.created_at, c.signing_secret,
		       c.owner_user_id, c.url_enc
		  FROM claimed JOIN notification_channels c ON c.id = claimed.channel_id
		 ORDER BY claimed.id`, limit, lease.Seconds())
	if err != nil {
		return nil, fmt.Errorf("claim notifications: %w", err)
	}
	defer rows.Close()
	var out []OutboxItem
	for rows.Next() {
		var it OutboxItem
		var ev []byte
		c := &it.Channel
		if err := rows.Scan(&it.ID, &it.DeliveryID, &ev, &it.Attempts,
			&c.ID, &c.Name, &c.Type, &c.URL, &c.Events, &c.ProjectID, &c.Enabled, &c.CreatedAt, &c.secretEnc,
			&c.OwnerUserID, &c.urlEnc); err != nil {
			return nil, fmt.Errorf("scan outbox row: %w", err)
		}
		c.HasSecret = len(c.secretEnc) > 0
		if err := json.Unmarshal(ev, &it.Event); err != nil {
			return nil, fmt.Errorf("decode outbox event %d: %w", it.ID, err)
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// Finish records an attempt's outcome: delivered, retry at retryAt, or (with
// retryAt nil and not delivered) given up. refund un-counts the attempt (one
// cut off by shutdown, not refused by the receiver).
func (r *Repository) Finish(ctx context.Context, id int64, status int, errMsg string, delivered bool, retryAt *time.Time, refund bool) error {
	var st *int
	if status != 0 {
		st = &status
	}
	_, err := r.db.Exec(ctx, `
		UPDATE notification_outbox SET
			locked_until    = NULL,
			last_status     = $2,
			last_error      = $3,
			delivered_at    = CASE WHEN $4 THEN now() END,
			failed_at       = CASE WHEN NOT $4 AND $5::timestamptz IS NULL THEN now() END,
			next_attempt_at = COALESCE($5, next_attempt_at),
			attempts        = attempts - CASE WHEN $6 THEN 1 ELSE 0 END
		WHERE id = $1`, id, st, errMsg, delivered, retryAt, refund)
	if err != nil {
		return fmt.Errorf("finish notification %d: %w", id, err)
	}
	return nil
}

// PurgeOutbox deletes delivered and given-up rows older than olderThan.
func (r *Repository) PurgeOutbox(ctx context.Context, olderThan time.Duration) (int64, error) {
	tag, err := r.db.Exec(ctx, `DELETE FROM notification_outbox
		WHERE (delivered_at IS NOT NULL OR failed_at IS NOT NULL) AND created_at < now() - make_interval(secs => $1)`,
		olderThan.Seconds())
	if err != nil {
		return 0, fmt.Errorf("purge outbox: %w", err)
	}
	return tag.RowsAffected(), nil
}

// ListPending returns undelivered rows (queued or awaiting a retry), oldest first.
func (r *Repository) ListPending(ctx context.Context, limit int) ([]PendingDelivery, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := r.db.Query(ctx, `
		SELECT o.id, o.channel_id, c.name, o.event->>'type', COALESCE(o.event->>'title', ''), o.attempts,
		       o.next_attempt_at, o.last_status, o.last_error, o.created_at
		  FROM notification_outbox o JOIN notification_channels c ON c.id = o.channel_id
		 WHERE o.delivered_at IS NULL AND o.failed_at IS NULL
		 ORDER BY o.created_at, o.id LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending notifications: %w", err)
	}
	defer rows.Close()
	out := []PendingDelivery{}
	for rows.Next() {
		var p PendingDelivery
		if err := rows.Scan(&p.ID, &p.ChannelID, &p.ChannelName, &p.EventType, &p.Title, &p.Attempts,
			&p.NextAttemptAt, &p.LastStatus, &p.LastError, &p.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan pending notification: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Dispatch tuning: rows per claim, concurrent sends, and the lease — longer
// than one send can take (HTTP 10s, SMTP 30s), so a live dispatcher never
// loses a row it is still working on.
const (
	dispatchBatch       = 50
	dispatchConcurrency = 8
	dispatchLease       = 2 * time.Minute
)

// DispatchDue delivers every due outbox row once, returning how many it
// handled. Run only on the leader (it is safe, just redundant, elsewhere).
func (s *Service) DispatchDue(ctx context.Context) (int, error) {
	total := 0
	for {
		items, err := s.outbox.Claim(ctx, dispatchBatch, dispatchLease)
		if err != nil {
			return total, err
		}
		if len(items) == 0 {
			return total, nil
		}
		var wg sync.WaitGroup
		sem := make(chan struct{}, dispatchConcurrency)
		for _, it := range items {
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer func() { <-sem; wg.Done() }()
				s.dispatchOne(ctx, it)
			}()
		}
		wg.Wait()
		total += len(items)
		if len(items) < dispatchBatch || ctx.Err() != nil {
			return total, ctx.Err()
		}
	}
}

func (s *Service) dispatchOne(ctx context.Context, it OutboxItem) {
	var status int
	var err error
	switch {
	case !it.Channel.Enabled:
		err = fmt.Errorf("channel %q is disabled", it.Channel.Name)
		it.Attempts = s.policy.MaxAttempts // no point retrying
	case it.Channel.OwnerUserID != nil:
		// A personal channel: access re-checked now, recipient resolved now.
		if err = s.preparePersonal(ctx, &it.Channel, it.Event); errors.Is(err, errNoLongerAllowed) {
			it.Attempts = s.policy.MaxAttempts // final: never send it
		} else if err == nil {
			_, status, err = s.deliver(ctx, it.Channel, it.Event, it.DeliveryID, 1)
		}
	default:
		_, status, err = s.deliver(ctx, it.Channel, it.Event, it.DeliveryID, 1)
	}
	var retryAt *time.Time
	msg, refund := "", false
	if err != nil {
		msg = err.Error()
		switch {
		case ctx.Err() != nil:
			// Shutting down mid-send: hand the row straight back rather than
			// let a cancelled attempt count toward giving up.
			retryAt, refund = new(time.Now()), true
		case it.Attempts < s.policy.MaxAttempts:
			retryAt = new(time.Now().Add(s.policy.retryAfter(it.Attempts)))
		}
		slog.WarnContext(ctx, "notify: delivery failed", "channel", it.Channel.Name, "event", it.Event.Type,
			"attempt", it.Attempts, "will_retry", retryAt != nil, "error", err)
	}
	// The outcome must land even if we're shutting down, or the row is resent.
	fctx := context.WithoutCancel(ctx)
	if ferr := s.outbox.Finish(fctx, it.ID, status, msg, err == nil, retryAt, refund); ferr != nil {
		slog.ErrorContext(ctx, "notify: record outcome", "error", ferr)
	}
	if retryAt == nil { // final: delivered or given up
		s.log(fctx, it.Channel, it.Event, it.Attempts, status, err)
	}
}

// RunDispatcher delivers the outbox until ctx ends: every interval, and at
// once when this process enqueues (Notify wakes it). Leader-only job. Old
// finished rows are purged hourly.
func (s *Service) RunDispatcher(ctx context.Context, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	lastPurge := time.Time{}
	var gauges outboxGauges
	for {
		if _, err := s.DispatchDue(ctx); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "notify: dispatch failed", "error", err)
		}
		gauges.sample(ctx, s.outbox)
		if time.Since(lastPurge) > time.Hour {
			if n, err := s.outbox.PurgeOutbox(ctx, s.policy.Retention); err != nil {
				slog.WarnContext(ctx, "notify: purge outbox failed", "error", err)
			} else if n > 0 {
				slog.InfoContext(ctx, "notify: purged outbox", "rows", n)
			}
			lastPurge = time.Now()
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		case <-s.wake:
		}
	}
}
