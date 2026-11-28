package config

import (
	"context"
	"errors"
	"log/slog"
	"maps"
	"strings"
	"sync"
	"time"
)

// Secrets is a live store of rotatable secret settings: ones whose value came
// from a reference (secretref) or a NAME_FILE, so an operator's secrets
// manager or Kubernetes/Docker secret can change it without a restart. A
// literal NAME value can't change, so it is seeded here too (Get always
// answers for any secret setting) but never refreshed.
//
// Every process runs its own Secrets.Run (not only the leader): each node
// holds its own DB connections, SMTP client, HTTP clients, etc., and every
// one of them needs to pick up a rotated value.
type Secrets struct {
	mu    sync.RWMutex
	value map[string]string

	refs     map[string]func(time.Duration) (string, error)
	hooks    map[string][]func(string)
	timeout  time.Duration
	interval time.Duration
}

// newSecrets builds the store from secretReader's tracked settings: every
// secret setting is seeded (so Get always answers), but only the ones that
// came from a reference or NAME_FILE (t.read != nil) are re-read on refresh
// — a literal value can't change. interval is SECRETS_REFRESH_INTERVAL
// (0 disables Run); timeout is SECRETS_TIMEOUT, applied to each refresh read.
func newSecrets(tracked []trackedSecret, timeout, interval time.Duration) *Secrets {
	s := &Secrets{
		value:    make(map[string]string, len(tracked)),
		refs:     make(map[string]func(time.Duration) (string, error), len(tracked)),
		hooks:    make(map[string][]func(string)),
		timeout:  timeout,
		interval: interval,
	}
	for _, t := range tracked {
		s.value[t.name] = t.value
		if t.read != nil {
			s.refs[t.name] = t.read
		}
	}
	return s
}

// Get returns name's current value. name is a setting name (e.g.
// "DB_PASSWORD"), not an environment-variable form like "DB_PASSWORD_FILE".
// A nil Secrets (a Config not built by Load, e.g. in a unit test) answers "".
func (s *Secrets) Get(name string) string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.value[name]
}

// Getter returns a func() string that always reads name's current value —
// the form consumers should hold instead of the whole store, so a client
// built once at startup (an HTTP header, a DB password callback) still sees
// a later rotation.
func (s *Secrets) Getter(name string) func() string {
	return func() string { return s.Get(name) }
}

// OnChange registers fn to run (with the new value) whenever name's value
// changes on a refresh tick. Called synchronously from the refresh loop, one
// setting at a time — keep fn fast. A nil Secrets never calls fn.
func (s *Secrets) OnChange(name string, fn func(string)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hooks[name] = append(s.hooks[name], fn)
}

// Run refreshes every tracked secret on Interval until ctx is done. Interval
// zero (or no tracked secrets) disables refreshing; Run then simply blocks
// until ctx is done, so `go cfg.Secrets.Run(ctx)` is always safe to call.
func (s *Secrets) Run(ctx context.Context) {
	if s == nil || s.interval <= 0 || len(s.refs) == 0 {
		<-ctx.Done()
		return
	}
	t := time.NewTicker(s.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.refreshAll(ctx)
		}
	}
}

// refreshAll re-reads every tracked secret once. A failed read keeps the
// last good value (logged as a warning, never with the value); a changed
// value is logged by setting name only and fires its OnChange hooks.
func (s *Secrets) refreshAll(ctx context.Context) {
	s.mu.RLock()
	refs := make(map[string]func(time.Duration) (string, error), len(s.refs))
	maps.Copy(refs, s.refs)
	s.mu.RUnlock()

	for name, read := range refs {
		newVal, err := read(s.timeout)
		if err != nil {
			slog.WarnContext(ctx, "secret refresh failed, keeping last good value", "setting", name, "error", err)
			continue
		}
		s.mu.Lock()
		changed := s.value[name] != newVal
		if changed {
			s.value[name] = newVal
		}
		hooks := append([]func(string){}, s.hooks[name]...)
		s.mu.Unlock()
		if changed {
			slog.InfoContext(ctx, "secret rotated", "setting", name)
			for _, h := range hooks {
				h(newVal)
			}
		}
	}
}

// Refreshed returns c with its rotatable secret fields (JWT_SECRET,
// JWT_PREVIOUS_SECRETS, INTEGRATION_SECRET_KEY, INTEGRATION_SECRET_KEY_PREVIOUS,
// OIDC_CLIENT_SECRET) replaced by the store's current values, checked by the
// same rules boot applies. A refresh hook applies the result only when err is
// nil, so a bad rotated value is refused and the running keys stay.
func (c Config) Refreshed() (Config, error) {
	if c.Secrets == nil {
		return c, nil
	}
	c.JWT.Secret = c.Secrets.Get("JWT_SECRET")
	c.JWT.Previous = splitSecretList(c.Secrets.Get("JWT_PREVIOUS_SECRETS"))
	c.IntegrationSecretKey = strings.TrimSpace(c.Secrets.Get("INTEGRATION_SECRET_KEY"))
	c.IntegrationSecretKeyPrevious = c.Secrets.Get("INTEGRATION_SECRET_KEY_PREVIOUS")
	c.OIDC.ClientSecret = c.Secrets.Get("OIDC_CLIENT_SECRET")
	if c.JWT.Secret == "" || (c.IsProduction() && c.JWT.Secret == insecureDevSecret) {
		return c, errors.New("JWT_SECRET must be set to a strong, unique value")
	}
	if err := c.validateJWTKeys(); err != nil {
		return c, err
	}
	if _, err := c.IntegrationKey(); err != nil {
		return c, err
	}
	if _, err := c.IntegrationPreviousKeys(); err != nil {
		return c, err
	}
	return c, nil
}
