package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/notify"
)

// Signed webhooks over HTTP: an admin sets a write-only signing secret on a
// generic webhook, the receiver verifies the test delivery with it, rotation
// switches the key, clearing stops signing, and only admins touch channels.
func TestWebhookSigningSecret(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "owner@xila.io")
	member := rbacUser(t, app, "member@xila.io")

	var (
		mu   sync.Mutex
		last http.Header
		body []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		last = r.Header.Clone()
		body, _ = io.ReadAll(r.Body)
	}))
	defer srv.Close()
	verify := func(secret string) error {
		mu.Lock()
		defer mu.Unlock()
		return notify.VerifySignature(secret, last, body, time.Now())
	}
	leaks := func(v any, secret string) bool {
		b, _ := json.Marshal(v)
		return strings.Contains(string(b), secret)
	}

	const s1, s2 = "first-signing-secret-123", "second-signing-secret-456" // gitleaks:allow -- fake test secrets
	create := `{"name":"siem","type":"webhook","url":"` + srv.URL + `","events":["*"],"signing_secret":"` + s1 + `"}`
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/notifications/channels", member, create); resp.StatusCode != http.StatusForbidden {
		t.Errorf("member creating a channel = %d, want 403", resp.StatusCode)
	}
	resp, ch := req(t, app, http.MethodPost, "/api/v1/notifications/channels", admin, create)
	if resp.StatusCode != http.StatusCreated || ch["has_secret"] != true || leaks(ch, s1) {
		t.Fatalf("create = %d %v: want has_secret and no secret", resp.StatusCode, ch)
	}
	id, _ := ch["id"].(string)
	if _, list := req(t, app, http.MethodGet, "/api/v1/notifications/channels", admin, ""); leaks(list, s1) {
		t.Error("channel list leaks the signing secret")
	}

	test := func() {
		t.Helper()
		if resp, b := req(t, app, http.MethodPost, "/api/v1/notifications/channels/"+id+"/test", admin, ""); resp.StatusCode != http.StatusOK {
			t.Fatalf("test send = %d %v", resp.StatusCode, b)
		}
	}
	test()
	if err := verify(s1); err != nil {
		t.Errorf("receiver verification with the secret: %v", err)
	}
	if last.Get(notify.HeaderDelivery) == "" {
		t.Error("no X-Xila-Delivery header")
	}

	// Rotate: the new secret verifies, the old one no longer does.
	resp, ch = req(t, app, http.MethodPatch, "/api/v1/notifications/channels/"+id, admin, `{"signing_secret":"`+s2+`"}`)
	if resp.StatusCode != http.StatusOK || ch["has_secret"] != true || leaks(ch, s2) {
		t.Fatalf("rotate = %d %v", resp.StatusCode, ch)
	}
	test()
	if err := verify(s2); err != nil {
		t.Errorf("after rotation, new secret: %v", err)
	}
	if err := verify(s1); err == nil {
		t.Error("after rotation the old secret still verifies")
	}

	// A PATCH that doesn't mention the secret keeps it.
	if _, ch = req(t, app, http.MethodPatch, "/api/v1/notifications/channels/"+id, admin, `{"name":"siem-2"}`); ch["has_secret"] != true {
		t.Errorf("rename dropped the secret: %v", ch)
	}
	// Clearing it stops signing.
	if _, ch = req(t, app, http.MethodPatch, "/api/v1/notifications/channels/"+id, admin, `{"signing_secret":""}`); ch["has_secret"] != false {
		t.Errorf("clear = %v", ch)
	}
	test()
	if last.Get(notify.HeaderSignature) != "" {
		t.Error("a channel without a secret still signs")
	}

	for name, body := range map[string]string{
		"slack":        `{"name":"s","type":"slack","url":"https://hooks.slack.test/x","signing_secret":"` + s1 + `"}`,
		"short secret": `{"name":"w","type":"webhook","url":"https://hook.test/x","signing_secret":"short"}`,
	} {
		if resp, _ := req(t, app, http.MethodPost, "/api/v1/notifications/channels", admin, body); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", name, resp.StatusCode)
		}
	}
}
