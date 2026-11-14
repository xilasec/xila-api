package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/secretbox"
)

// A signed webhook: the receiver verifies every attempt with the shared
// secret, a retry of the same outbox row keeps its X-Xila-Delivery id while a
// new event gets a new one, and the secret never leaves the server.
func TestSignedWebhookDeliveries(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := NewRepository(pool)
	cipher, err := secretbox.New([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	const secret = "whsec-receiver-shared-secret"

	type hit struct {
		delivery string
		verify   error
		title    string
	}
	var (
		mu   sync.Mutex
		hits []hit
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var e Event
		_ = json.Unmarshal(body, &e)
		mu.Lock()
		hits = append(hits, hit{r.Header.Get(HeaderDelivery), VerifySignature(secret, r.Header, body, time.Now()), e.Title})
		first := len(hits) == 1
		mu.Unlock()
		if first {
			w.WriteHeader(http.StatusBadGateway) // down the first time: the row is retried
		}
	}))
	defer srv.Close()

	svc := NewService(repo, SMTPConfig{})
	svc.SetSecretCipher(cipher)
	svc.SetDeliveryPolicy(DeliveryPolicy{MaxAttempts: 5, RetryBase: 30 * time.Millisecond, RetryMax: time.Second, Retention: time.Hour})

	id := uuid.NewString()
	sealed, err := svc.SealSecret(id, secret)
	if err != nil {
		t.Fatal(err)
	}
	ch, err := repo.Create(ctx, Channel{ID: id, Name: "signed", Type: TypeWebhook, URL: srv.URL,
		Events: []string{"*"}, Enabled: true, secretEnc: sealed})
	if err != nil {
		t.Fatal(err)
	}
	if ch.ID != id || !ch.HasSecret {
		t.Fatalf("created = %+v, want id %s with has_secret", ch, id)
	}
	out, _ := json.Marshal(ch)
	if strings.Contains(string(out), secret) || strings.Contains(string(out), "secretEnc") || !strings.Contains(string(out), `"has_secret":true`) {
		t.Errorf("channel JSON = %s: must say has_secret and never carry the secret", out)
	}

	svc.Notify(ctx, Event{Type: EventCriticalFinding, Title: "first"})
	if _, err := svc.DispatchDue(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if _, err := svc.DispatchDue(ctx); err != nil {
		t.Fatal(err)
	}
	svc.Notify(ctx, Event{Type: EventCriticalFinding, Title: "second"})
	if _, err := svc.DispatchDue(ctx); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(hits) != 3 {
		t.Fatalf("receiver hits = %d, want 3 (a failed attempt, its retry, a new event)", len(hits))
	}
	for i, h := range hits {
		if h.verify != nil {
			t.Errorf("attempt %d (%s): receiver verification failed: %v", i+1, h.title, h.verify)
		}
		if _, err := uuid.Parse(h.delivery); err != nil {
			t.Errorf("attempt %d: X-Xila-Delivery = %q, want a UUID", i+1, h.delivery)
		}
	}
	if hits[0].delivery != hits[1].delivery || hits[0].title != "first" || hits[1].title != "first" {
		t.Errorf("retry delivery ids = %q / %q, want the same for one outbox row", hits[0].delivery, hits[1].delivery)
	}
	if hits[2].delivery == hits[0].delivery {
		t.Errorf("a new event reused delivery id %q", hits[2].delivery)
	}
}

// A secret sealed for another channel (a copied row) can't be opened: the
// delivery fails rather than going out unsigned.
func TestSignedWebhookNeverFallsBackToUnsigned(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := NewRepository(pool)
	cipher, _ := secretbox.New([]byte("0123456789abcdef0123456789abcdef"))
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer srv.Close()

	svc := NewService(repo, SMTPConfig{})
	svc.SetSecretCipher(cipher)
	svc.maxAttempts = 1
	stolen, _ := svc.SealSecret(uuid.NewString(), "whsec-receiver-shared-secret")
	ch, err := repo.Create(ctx, Channel{Name: "copied", Type: TypeWebhook, URL: srv.URL, Events: []string{"*"},
		Enabled: true, secretEnc: stolen})
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.SendTo(ctx, ch, Event{Type: EventTest, Title: "t"}); err == nil || !strings.Contains(err.Error(), "signing secret") {
		t.Errorf("SendTo = %v, want a signing-secret error", err)
	}
	if hits != 0 {
		t.Errorf("receiver hit %d time(s): an undecryptable secret must not send unsigned", hits)
	}
}
