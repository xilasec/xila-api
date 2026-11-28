// Package ratelimit throttles password sign-in attempts with fixed-window
// counters stored in Postgres, so every replica shares one budget.
//
// Two buckets guard each attempt:
//   - per client IP, generous — an office behind one NAT shares an address;
//   - per account (normalized email), strict — stops brute force against one
//     account no matter how many addresses the attacker uses.
//
// Only the password endpoints are limited. The public /auth/config (fetched on
// every page load) and the SSO redirects/callbacks are not: the IdP does its
// own throttling, and limiting them locked whole offices out of SSO.
package ratelimit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2" // nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used -- cleanup sampling, not a secret
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Limits configures the two buckets. A zero Max disables that bucket.
type Limits struct {
	IPMax         int
	IPWindow      time.Duration
	AccountMax    int
	AccountWindow time.Duration
}

// Limiter counts attempts per key in Postgres.
type Limiter struct {
	db     *pgxpool.Pool
	limits Limits
}

// New constructs a Limiter.
func New(db *pgxpool.Pool, limits Limits) *Limiter {
	if limits.IPWindow <= 0 {
		limits.IPWindow = time.Minute
	}
	if limits.AccountWindow <= 0 {
		limits.AccountWindow = 15 * time.Minute
	}
	return &Limiter{db: db, limits: limits}
}

// Hit records one attempt against key and reports whether it is within limit
// attempts per window; when it isn't, retryAfter says when the window resets.
func (l *Limiter) Hit(ctx context.Context, key string, limit int, window time.Duration) (allowed bool, retryAfter time.Duration, err error) {
	var (
		count int
		start time.Time
	)
	err = l.db.QueryRow(ctx, `
		INSERT INTO auth_rate_limits AS r (key, window_start, count) VALUES ($1, now(), 1)
		ON CONFLICT (key) DO UPDATE SET
			count        = CASE WHEN r.window_start <= now() - make_interval(secs => $2) THEN 1 ELSE r.count + 1 END,
			window_start = CASE WHEN r.window_start <= now() - make_interval(secs => $2) THEN now() ELSE r.window_start END
		RETURNING count, window_start`, key, window.Seconds()).Scan(&count, &start)
	if err != nil {
		return false, 0, fmt.Errorf("rate limit hit: %w", err)
	}
	// Opportunistic cleanup of long-dead windows (cheap, indexed). A sampling
	// decision, not a secret: math/rand is right here.
	if rand.IntN(200) == 0 { //nolint:gosec // G404: samples when to prune expired buckets, not a security decision
		if _, err := l.db.Exec(ctx, `DELETE FROM auth_rate_limits WHERE window_start < now() - interval '1 day'`); err != nil {
			slog.WarnContext(ctx, "rate limit cleanup failed", "error", err)
		}
	}
	if count <= limit {
		return true, 0, nil
	}
	return false, max(time.Until(start.Add(window)), time.Second), nil
}

// Reset clears key's counter (a successful sign-in clears its account bucket).
func (l *Limiter) Reset(ctx context.Context, key string) error {
	_, err := l.db.Exec(ctx, `DELETE FROM auth_rate_limits WHERE key = $1`, key)
	return err
}

// IPKey and AccountKey name the buckets.
func IPKey(ip string) string { return "ip:" + ip }

// AccountKey normalizes the email the same way sign-in does.
func AccountKey(email string) string { return "acct:" + strings.ToLower(strings.TrimSpace(email)) }

// Middleware limits a password endpoint whose JSON body carries "email". On a
// 2xx response the account bucket is cleared, so a user who mistyped a few
// times isn't still counted after getting in. A database error fails open:
// throttling must not become the outage.
func (l *Limiter) Middleware() fiber.Handler { return l.middleware("", true) }

// ResetMiddleware throttles the password-reset request: the same per-address
// budget, but in its own account buckets ("reset:" + email) that a success
// never clears — the request always answers 202, and clearing would let anyone
// mail-bomb an address through Xila.
func (l *Limiter) ResetMiddleware() fiber.Handler { return l.middleware("reset:", false) }

func (l *Limiter) middleware(prefix string, clearOnSuccess bool) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx := c.UserContext()
		if l.limits.IPMax > 0 {
			ok, wait, err := l.Hit(ctx, IPKey(c.IP()), l.limits.IPMax, l.limits.IPWindow)
			if err != nil {
				slog.WarnContext(ctx, "rate limiter unavailable; allowing", "error", err)
			} else if !ok {
				return tooMany(c, wait)
			}
		}
		account := ""
		if l.limits.AccountMax > 0 {
			var body struct {
				Email string `json:"email"`
			}
			if json.Unmarshal(c.Body(), &body) == nil && strings.TrimSpace(body.Email) != "" {
				account = prefix + AccountKey(body.Email)
				ok, wait, err := l.Hit(ctx, account, l.limits.AccountMax, l.limits.AccountWindow)
				if err != nil {
					slog.WarnContext(ctx, "rate limiter unavailable; allowing", "error", err)
				} else if !ok {
					return tooMany(c, wait)
				}
			}
		}
		err := c.Next()
		if clearOnSuccess && err == nil && account != "" && c.Response().StatusCode() < 300 {
			if rerr := l.Reset(ctx, account); rerr != nil {
				slog.WarnContext(ctx, "rate limit reset failed", "error", rerr)
			}
		}
		return err
	}
}

func tooMany(c *fiber.Ctx, wait time.Duration) error {
	c.Set(fiber.HeaderRetryAfter, strconv.Itoa(int(math.Ceil(wait.Seconds()))))
	return fiber.NewError(fiber.StatusTooManyRequests, "too many attempts — try again later")
}
