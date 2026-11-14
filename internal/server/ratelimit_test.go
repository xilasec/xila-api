package server

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/ratelimit"
)

// authLimiterFor builds the password-endpoint limiter a test asked for through
// cfg.AuthRateLimit; nil (no throttling) otherwise.
func authLimiterFor(pool *pgxpool.Pool, cfg config.Config) *ratelimit.Limiter {
	rl := cfg.AuthRateLimit
	if rl.IPPerMinute == 0 && rl.Account == 0 {
		return nil
	}
	return ratelimit.New(pool, ratelimit.Limits{
		IPMax: rl.IPPerMinute, IPWindow: time.Minute,
		AccountMax: rl.Account, AccountWindow: rl.AccountWindow,
	})
}

// Throttling targets password guessing only: the public config endpoint the SPA
// fetches on every page load is never limited (that used to lock whole offices
// behind one NAT out of SSO); one account is locked after its budget no matter
// the address; another account from the same address still gets in; and two
// replicas sharing the database share the counts.
func TestPasswordThrottling(t *testing.T) {
	pool := pgtest.Pool(t)
	limits := func(c *config.Config) {
		c.AuthRateLimit = config.AuthRateLimit{IPPerMinute: 1000, Account: 5, AccountWindow: 15 * time.Minute}
	}
	replicaA := newTestAppOn(t, pool, limits)
	replicaB := newTestAppOn(t, pool, limits)

	for i := range 100 {
		if resp, _ := req(t, replicaA, http.MethodGet, "/api/v1/auth/config", "", ""); resp.StatusCode != http.StatusOK {
			t.Fatalf("/auth/config call %d = %d, want 200 (never throttled)", i, resp.StatusCode)
		}
	}

	req(t, replicaA, http.MethodPost, "/api/v1/auth/register", "", `{"email":"victim@xila.io","password":"correct-horse"}`)
	req(t, replicaA, http.MethodPost, "/api/v1/auth/register", "", `{"email":"bystander@xila.io","password":"correct-horse"}`)

	bad := `{"email":"Victim@xila.io","password":"wrong-guess"}`
	// Spread the guesses over both replicas: the budget is shared.
	for i := range 4 {
		app := replicaA
		if i%2 == 1 {
			app = replicaB
		}
		if resp, _ := req(t, app, http.MethodPost, "/api/v1/auth/login", "", bad); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("guess %d = %d, want 401", i+1, resp.StatusCode)
		}
	}
	resp, _ := req(t, replicaB, http.MethodPost, "/api/v1/auth/login", "", strings.ToLower(bad))
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("5th guess = %d, want 401 (still within the budget)", resp.StatusCode)
	}
	resp, _ = req(t, replicaA, http.MethodPost, "/api/v1/auth/login", "", `{"email":"victim@xila.io","password":"correct-horse"}`)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Fatalf("6th attempt = %d (Retry-After %q), want 429 with Retry-After — even with the right password", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	if resp, _ := req(t, replicaA, http.MethodPost, "/api/v1/auth/login", "", `{"email":"bystander@xila.io","password":"correct-horse"}`); resp.StatusCode != http.StatusOK {
		t.Errorf("another account from the same address = %d, want 200", resp.StatusCode)
	}
}

// A successful sign-in clears the account's count, so a user who mistyped a few
// times isn't one typo away from a lockout for the rest of the window.
func TestSuccessfulLoginClearsAccountBudget(t *testing.T) {
	pool := pgtest.Pool(t)
	app := newTestAppOn(t, pool, func(c *config.Config) {
		c.AuthRateLimit = config.AuthRateLimit{IPPerMinute: 1000, Account: 3, AccountWindow: 15 * time.Minute}
	})
	req(t, app, http.MethodPost, "/api/v1/auth/register", "", `{"email":"typo@xila.io","password":"correct-horse"}`)
	login := func(pw string) int {
		resp, _ := req(t, app, http.MethodPost, "/api/v1/auth/login", "", `{"email":"typo@xila.io","password":"`+pw+`"}`)
		return resp.StatusCode
	}
	login("nope-1")
	login("nope-2")
	if got := login("correct-horse"); got != http.StatusOK {
		t.Fatalf("login = %d", got)
	}
	login("nope-3")
	login("nope-4")
	if got := login("correct-horse"); got != http.StatusOK {
		t.Errorf("after a success, two more typos then the right password = %d, want 200", got)
	}
}

// The per-address bucket still stops a spray across many accounts.
func TestPerAddressBudget(t *testing.T) {
	pool := pgtest.Pool(t)
	app := newTestAppOn(t, pool, func(c *config.Config) {
		c.AuthRateLimit = config.AuthRateLimit{IPPerMinute: 3}
	})
	for i := range 3 {
		body := `{"email":"user` + string(rune('a'+i)) + `@xila.io","password":"x"}`
		if resp, _ := req(t, app, http.MethodPost, "/api/v1/auth/login", "", body); resp.StatusCode == http.StatusTooManyRequests {
			t.Fatalf("attempt %d throttled early", i+1)
		}
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/auth/login", "", `{"email":"userz@xila.io","password":"x"}`); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("4th attempt from one address = %d, want 429", resp.StatusCode)
	}
}
