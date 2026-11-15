package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand/v2" // nosemgrep: go.lang.security.audit.crypto.math_random.math-random-used -- retry jitter, not a secret
	"net/http"
	"os"
	"strconv"
	"time"
)

// When thousands of CI jobs upload at once the server sheds load with 429
// (and a proxy or restart can answer 502/503/504). The client retries those,
// and connection errors, until the retry budget is spent: waiting as long as
// Retry-After asks, otherwise backing off exponentially with full jitter so the
// retries of many clients spread out instead of arriving together.
//
// Re-sending an upload after a 502, 504 or a dropped connection can record the
// same report twice if the first attempt did get through. That is harmless:
// findings are matched by fingerprint, so the second scan only refreshes them.

const (
	retryBase    = time.Second      // first backoff ceiling
	retryMaxWait = 60 * time.Second // cap on any single wait, Retry-After included
)

// retryFlag registers --retry-for (env XILA_RETRY_FOR) on a flag set.
func retryFlag(fs *flag.FlagSet) *time.Duration {
	def := 10 * time.Minute
	if v := os.Getenv("XILA_RETRY_FOR"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			def = d
		}
	}
	return fs.Duration("retry-for", def, "keep retrying 429/502/503/504 and connection errors for this long (0 disables)")
}

// retryable reports whether a response status is worth retrying.
func retryable(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryAfter parses a Retry-After header: delay-seconds or an HTTP date.
// ok is false when absent or unparseable.
func retryAfter(h string, now time.Time) (time.Duration, bool) {
	if h == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(h); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(h); err == nil {
		return max(t.Sub(now), 0), true
	}
	return 0, false
}

// backoff is the wait before retry number attempt (1-based): a random
// duration up to retryBase·2^(attempt-1), capped at retryMaxWait.
func backoff(attempt int, rnd func(int64) int64) time.Duration {
	ceiling := retryMaxWait
	if attempt < 7 { // 2^6 s already exceeds the cap
		ceiling = min(retryBase<<(attempt-1), retryMaxWait)
	}
	return time.Duration(rnd(int64(ceiling)) + 1)
}

// errRetryBudget wraps the last failure once the retry budget is spent.
var errRetryBudget = errors.New("gave up retrying")

// send issues one request per attempt (newReq builds a fresh one, so the body
// can be re-sent) and retries per the rules above. It returns the final status
// and body; a retryable status that outlived the budget is returned as is, so
// callers report the server's own message.
func (c *client) send(newReq func() (*http.Request, error)) (int, []byte, error) {
	deadline := c.now().Add(c.retryFor)
	for attempt := 1; ; attempt++ {
		req, err := newReq()
		if err != nil {
			return 0, nil, err
		}
		status, body, header, err := c.once(req)
		if err == nil && !retryable(status) {
			return status, body, nil
		}
		wait := backoff(attempt, c.rnd)
		if err == nil {
			if d, ok := retryAfter(header.Get("Retry-After"), c.now()); ok {
				wait = d
			}
		}
		wait = min(wait, retryMaxWait)
		if c.retryFor <= 0 || c.now().Add(wait).After(deadline) {
			if err != nil {
				return 0, nil, fmt.Errorf("%w after %d attempt(s): %v", errRetryBudget, attempt, err)
			}
			return status, body, nil
		}
		what := fmt.Sprintf("HTTP %d", status)
		if err != nil {
			what = err.Error()
		}
		fmt.Fprintf(c.log, "retrying %s %s in %s (%s)\n", req.Method, req.URL.Path, wait.Round(100*time.Millisecond), what)
		c.sleep(wait)
	}
}

// once sends a single request and reads the whole response.
func (c *client) once(req *http.Request) (int, []byte, http.Header, error) {
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, nil, err
	}
	return resp.StatusCode, b, resp.Header, nil
}

// defaultRand is the jitter source in production.
func defaultRand(n int64) int64 { return rand.Int64N(n) }
