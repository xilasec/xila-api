package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeChannels struct {
	chans   []Channel
	gotPID  string
	gotType string
}

func (f *fakeChannels) ListForEvent(_ context.Context, eventType, projectID, _ string) ([]Channel, error) {
	f.gotType, f.gotPID = eventType, projectID
	return f.chans, nil
}

// memOutbox is an in-memory outbox: every row is due as soon as it's queued
// or rescheduled (the backoff schedule itself is tested on DeliveryPolicy).
type memOutbox struct {
	mu       sync.Mutex
	channels map[string]Channel
	rows     []*memRow
}

type memRow struct {
	it              OutboxItem
	done, delivered bool
	retryAt         *time.Time
}

func newMemOutbox(chans []Channel) *memOutbox {
	m := &memOutbox{channels: map[string]Channel{}}
	for _, c := range chans {
		m.channels[c.ID] = c
	}
	return m
}

func (m *memOutbox) Enqueue(_ context.Context, ids []string, e Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, id := range ids {
		m.rows = append(m.rows, &memRow{it: OutboxItem{ID: int64(len(m.rows) + 1), Channel: m.channels[id], Event: e}})
	}
	return nil
}

func (m *memOutbox) Claim(_ context.Context, limit int, _ time.Duration) ([]OutboxItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []OutboxItem
	for _, r := range m.rows {
		if !r.done && len(out) < limit && !r.claimed() {
			r.it.Attempts++
			r.retryAt = nil
			r.markClaimed()
			out = append(out, r.it)
		}
	}
	return out, nil
}

func (m *memOutbox) Finish(_ context.Context, id int64, _ int, _ string, delivered bool, retryAt *time.Time, refund bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.rows[id-1]
	if refund {
		r.it.Attempts--
	}
	r.unclaim()
	r.delivered, r.retryAt = delivered, retryAt
	r.done = delivered || retryAt == nil
	return nil
}

func (m *memOutbox) PurgeOutbox(context.Context, time.Duration) (int64, error) { return 0, nil }

func (r *memRow) claimed() bool { return r.retryAt != nil && r.retryAt.IsZero() }
func (r *memRow) markClaimed()  { r.retryAt = &time.Time{} }
func (r *memRow) unclaim()      { r.retryAt = nil }

// testService wires a Service to fake channels, an in-memory outbox and a log.
func testService(chans []Channel, client *http.Client) (*Service, *memOutbox, *fakeLog) {
	for i := range chans {
		if chans[i].ID == "" {
			chans[i].ID = fmt.Sprintf("c%d", i+1)
		}
	}
	ob, logs := newMemOutbox(chans), &fakeLog{}
	return &Service{
		channels: &fakeChannels{chans: chans}, outbox: ob, logger: logs, client: client,
		policy: DeliveryPolicy{MaxAttempts: 3, RetryBase: time.Millisecond, RetryMax: time.Millisecond},
		wake:   make(chan struct{}, 1), maxAttempts: 3, backoff: time.Millisecond,
	}, ob, logs
}

func TestNotifyDeliversWebhookAndSlack(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	svc, _, logs := testService([]Channel{
		{Name: "hook", Type: "webhook", URL: srv.URL, Enabled: true},
		{Name: "slack", Type: "slack", URL: srv.URL, Enabled: true},
	}, srv.Client())

	svc.Notify(context.Background(), Event{
		Type: EventRiskAcceptanceApproved, Title: "Risk accepted: x", Text: "because", Severity: "high",
	})
	if len(bodies) != 0 {
		t.Fatalf("Notify sent %d requests itself; it must only queue", len(bodies))
	}
	select {
	case <-svc.wake:
	default:
		t.Error("Notify didn't wake the local dispatcher")
	}
	if n, err := svc.DispatchDue(context.Background()); err != nil || n != 2 {
		t.Fatalf("DispatchDue = %d, %v; want 2", n, err)
	}

	if len(bodies) != 2 {
		t.Fatalf("deliveries = %d, want 2", len(bodies))
	}
	var sawWebhook, sawSlack bool
	for _, b := range bodies {
		var m map[string]any
		if err := json.Unmarshal([]byte(b), &m); err != nil {
			t.Fatalf("body not JSON: %v", err)
		}
		if m["type"] == EventRiskAcceptanceApproved {
			sawWebhook = true // raw event payload
		}
		if txt, ok := m["text"].(string); ok && strings.Contains(txt, "Risk accepted") {
			sawSlack = true // slack-shaped payload
		}
	}
	if !sawWebhook || !sawSlack {
		t.Errorf("webhook=%v slack=%v, want both", sawWebhook, sawSlack)
	}
	if len(logs.ds) != 2 || !logs.ds[0].Delivered || logs.ds[0].Attempts != 1 {
		t.Errorf("delivery log = %+v, want two delivered on attempt 1", logs.ds)
	}
}

// A failing channel is retried by later dispatch passes (one send per pass,
// not a burst), and given up after MaxAttempts with one final log entry.
func TestNotifyRetriesThenGivesUp(t *testing.T) {
	var mu sync.Mutex
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(http.StatusInternalServerError) // always fails
	}))
	defer srv.Close()

	svc, _, logs := testService([]Channel{{Name: "flaky", Type: "webhook", URL: srv.URL, Enabled: true}}, srv.Client())
	svc.Notify(context.Background(), Event{Type: EventTest, Title: "t"})

	for pass := 1; pass <= 5; pass++ {
		if _, err := svc.DispatchDue(context.Background()); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		got := hits
		mu.Unlock()
		if want := min(pass, 3); got != want {
			t.Fatalf("after pass %d: %d sends, want %d", pass, got, want)
		}
		if pass < 3 && len(logs.ds) != 0 {
			t.Fatalf("logged before giving up: %+v", logs.ds)
		}
	}
	if len(logs.ds) != 1 || logs.ds[0].Delivered || logs.ds[0].Attempts != 3 || *logs.ds[0].StatusCode != 500 {
		t.Errorf("final log = %+v, want one undelivered entry, 3 attempts, status 500", logs.ds)
	}
}

func TestNotifyPassesProjectScope(t *testing.T) {
	svc, _, _ := testService(nil, &http.Client{})
	fake := svc.channels.(*fakeChannels)
	svc.Notify(context.Background(), Event{Type: EventRiskAcceptanceApproved, ProjectID: "proj-9"})
	if fake.gotType != EventRiskAcceptanceApproved || fake.gotPID != "proj-9" {
		t.Errorf("ListForEvent got (%q,%q), want (risk_accepted, proj-9)", fake.gotType, fake.gotPID)
	}
}

func TestRetryBackoff(t *testing.T) {
	p := DeliveryPolicy{RetryBase: 30 * time.Second, RetryMax: time.Hour}
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 16 * time.Minute, 32 * time.Minute, time.Hour, time.Hour}
	for i, w := range want {
		if got := p.retryAfter(i + 1); got != w {
			t.Errorf("wait after %d failures = %v, want %v", i+1, got, w)
		}
	}
}

// A send cut off by shutdown goes straight back to the queue and doesn't count
// toward giving up — restarts must not eat a notification's retries.
func TestDispatchInterruptedByShutdownIsNotCounted(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body) // lets the server notice the client hanging up
		cancel()                           // the process starts shutting down mid-request
		<-r.Context().Done()
	}))
	defer srv.Close()
	svc, ob, logs := testService([]Channel{{Name: "hook", Type: "webhook", URL: srv.URL, Enabled: true}}, srv.Client())
	svc.Notify(context.Background(), Event{Type: EventTest, Title: "t"})
	_, _ = svc.DispatchDue(ctx)

	r := ob.rows[0]
	if r.done || r.it.Attempts != 0 || r.retryAt == nil || time.Until(*r.retryAt) > 0 {
		t.Errorf("after an interrupted send: done=%v attempts=%d retryAt=%v; want queued, uncounted, due now", r.done, r.it.Attempts, r.retryAt)
	}
	if len(logs.ds) != 0 {
		t.Errorf("an interrupted send was logged as final: %+v", logs.ds)
	}
}
