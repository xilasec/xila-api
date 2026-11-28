package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// M13 13.16: a browser session ends after SESSION_IDLE_TIMEOUT without a
// request, and stays ended: a refused request must not reset the clock.
func TestSessionIdleTimeout(t *testing.T) {
	pool := pgtest.Pool(t)
	app := newTestAppOn(t, pool, func(c *config.Config) {
		c.JWT.IdleTimeout = 30 * time.Minute
		c.JWT.ReauthWindow = 10 * time.Minute
	})
	token := rbacUser(t, app, "dana@xila.io")
	ctx := t.Context()

	me := func(tok string) (*http.Response, string) {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		resp, err := app.Test(r, -1)
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		buf := make([]byte, 512)
		n, _ := resp.Body.Read(buf)
		b.Write(buf[:n])
		return resp, b.String()
	}
	resp, _ := me(token)
	if resp.StatusCode != http.StatusOK || resp.Header.Get(auth.HeaderIdleTimeout) != "1800" {
		t.Fatalf("fresh session = %d, %s %q; want 200 and 1800", resp.StatusCode, auth.HeaderIdleTimeout, resp.Header.Get(auth.HeaderIdleTimeout))
	}

	// "Sign out everywhere" reissues a session without new credentials: its
	// lifetime still runs from the sign-in.
	var before time.Time
	if err := pool.QueryRow(ctx, `SELECT min(created_at) FROM user_sessions`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	_, out := req(t, app, http.MethodPost, "/api/v1/me/sessions/revoke", token, "")
	token, _ = out["token"].(string)
	var newest time.Time
	if err := pool.QueryRow(ctx, `SELECT max(created_at) FROM user_sessions`).Scan(&newest); err != nil {
		t.Fatal(err)
	}
	if newest.Sub(before).Abs() > time.Second {
		t.Errorf("reissued session starts at %v, want the sign-in's %v", newest, before)
	}

	// The UI's polling is not activity: it is checked but leaves the clock.
	lastSeen := func() time.Time {
		t.Helper()
		var at time.Time
		if err := pool.QueryRow(ctx, `SELECT max(last_seen_at) FROM user_sessions`).Scan(&at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	if _, err := pool.Exec(ctx, `UPDATE user_sessions SET last_seen_at = now() - interval '10 minutes'`); err != nil {
		t.Fatal(err)
	}
	stale := lastSeen()
	poll := httptest.NewRequest(http.MethodGet, "/api/v1/me/inbox/count", nil)
	poll.Header.Set("Authorization", "Bearer "+token)
	poll.Header.Set(auth.HeaderBackground, "true")
	if resp, err := app.Test(poll, -1); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("background poll: %v %v", resp, err)
	}
	if !lastSeen().Equal(stale) {
		t.Error("a background request restarted the idle clock")
	}
	me(token)
	if !lastSeen().After(stale) {
		t.Error("a user request did not restart the idle clock")
	}

	// Idle for an hour: refused, and still refused on retry.
	if _, err := pool.Exec(ctx, `UPDATE user_sessions SET last_seen_at = now() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	if resp, body := me(token); resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "idle") {
		t.Errorf("idle session = %d %s, want 401 idle", resp.StatusCode, body)
	}
	if resp, _ := me(token); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("retry of an idle session = %d, want 401: a refused request must not revive it", resp.StatusCode)
	}

	// API tokens have no browser session: never idle-checked, no header.
	fresh := rbacUser(t, app, "erin@xila.io")
	_, tok := req(t, app, http.MethodPost, "/api/v1/tokens", fresh, `{"name":"ci"}`)
	secret, _ := tok["secret"].(string)
	if _, err := pool.Exec(ctx, `DELETE FROM user_sessions`); err != nil {
		t.Fatal(err)
	}
	if resp, _ := me(secret); resp.StatusCode != http.StatusOK || resp.Header.Get(auth.HeaderIdleTimeout) != "" {
		t.Errorf("API token = %d %q, want 200 and no idle header", resp.StatusCode, resp.Header.Get(auth.HeaderIdleTimeout))
	}

	// The purge drops exactly what can no longer be used.
	rbacUser(t, app, "finn@xila.io")
	if _, err := pool.Exec(ctx, `INSERT INTO user_sessions (id, user_id, last_seen_at)
		SELECT gen_random_uuid(), id, now() - interval '2 hours' FROM users WHERE email = 'finn@xila.io'`); err != nil {
		t.Fatal(err)
	}
	n, err := auth.NewSessionStore(pool).Purge(ctx, 30*time.Minute, 24*time.Hour)
	if err != nil || n != 1 {
		t.Errorf("purged %d (err %v), want the one idle session", n, err)
	}
}
