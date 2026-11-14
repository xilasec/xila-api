// Package feature holds the runtime feature switches: an instance admin turns a
// feature off or on without a restart, and every replica follows within
// CacheTTL.
//
// A feature is off in three places at once, all keyed by the same Key:
//   - its HTTP routes answer 404 (Middleware on the authenticated API, after
//     sign-in and the audit log; PublicMiddleware ahead of the public routes),
//   - its background work and ingest side effects skip (the owning service asks
//     Store.Enabled — cra, remediation, notify, auth),
//   - the UI hides it (GET /features).
//
// Turning a feature off never deletes its data; turning it back on restores it.
package feature

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/config"
)

// Keys. Services that can't import this package (it imports auth) use the same
// string literal through their own small Enabled interface.
const (
	MFA                   = "mfa"
	CRA                   = "cra"
	PSIRT                 = "psirt"
	AITriage              = "ai_triage"
	MCP                   = "mcp"
	Badges                = "badges"
	CustomFields          = "custom_fields"
	PersonalNotifications = "personal_notifications"
	Remediation           = "remediation"
	Engagements           = "engagements"
)

// CacheTTL bounds how long a replica may serve a stale switch after another
// replica changed it. The replica that made the change sees it at once.
const CacheTTL = 5 * time.Second

// Def describes one switchable feature.
type Def struct {
	Key string
	// Routes are the authenticated API paths the feature owns, and Public its
	// unauthenticated ones, as case-insensitive regular expressions over the
	// full path (Fiber routes case-insensitively and ignores a trailing slash,
	// so the patterns must too).
	Routes []string
	Public []string
	// OwnerOnly features can only be switched by the instance owner, from a
	// signed-in session: turning them off weakens security for everyone.
	OwnerOnly bool
}

// Defs is every switchable feature, in display order. All default to on, so
// an instance that never touches the switches behaves as before they existed.
var Defs = []Def{
	{Key: MFA, OwnerOnly: true, Routes: []string{`^/api/v1/(me/mfa|users/[^/]+/mfa)(/|$)`}, Public: []string{`^/api/v1/auth/mfa/?$`}},
	{Key: CRA, Routes: []string{`^/api/v1/(cra|projects/[^/]+/cra)(/|$)`}},
	{Key: PSIRT, Routes: []string{`^/api/v1/psirt(/|$)`}, Public: []string{`^/\.well-known/csaf(/|$)`, `^/csaf(/|$)`}},
	{Key: AITriage, Routes: []string{`^/api/v1/findings/[^/]+/ai-proposals(/|$)`}},
	{Key: MCP, Routes: []string{`^/api/v1/mcp/?$`}},
	{Key: Badges, Routes: []string{`^/api/v1/projects/[^/]+/badge-token(/|$)`}, Public: []string{`^/api/v1/badges(/|$)`}},
	{Key: CustomFields, Routes: []string{`^/api/v1/(custom-fields|(assets|findings|projects)/[^/]+/custom)(/|$)`}},
	{Key: PersonalNotifications, Routes: []string{`^/api/v1/(me/notifications|projects/[^/]+/watch)(/|$)`}},
	{Key: Remediation, Routes: []string{`^/api/v1/(remediation|projects/[^/]+/remediation)(/|$)`}},
	{Key: Engagements, Routes: []string{`^/api/v1/(engagements|projects/[^/]+/engagements)(/|$)`}},
}

// ErrUnknown is returned for a key that isn't in Defs.
var ErrUnknown = errors.New("unknown feature")

// ErrUnavailable is returned when turning on a feature the server isn't
// configured for (MCP_ENABLED off, no AI provider).
var ErrUnavailable = errors.New("feature not configured on this server")

// State is one feature's switch as the API reports it.
type State struct {
	Key     string `json:"key"`
	Enabled bool   `json:"enabled"`
	// Available is false when the server's configuration rules the feature out
	// (then Enabled is false too, and the switch can't turn it on).
	Available bool       `json:"available"`
	OwnerOnly bool       `json:"owner_only"`
	UpdatedAt *time.Time `json:"updated_at"`
	UpdatedBy *string    `json:"updated_by"`
}

type route struct {
	key    string
	re     *regexp.Regexp
	public bool
}

// Store reads and writes the switches, caching them for CacheTTL.
type Store struct {
	db          *pgxpool.Pool
	unavailable map[string]bool
	routes      []route

	mu      sync.Mutex
	loaded  time.Time
	enabled map[string]bool
	rows    map[string]State
	now     func() time.Time
}

// NewStore builds the store. unavailable lists features the server's own
// configuration rules out; they read as off whatever the switch says.
func NewStore(db *pgxpool.Pool, unavailable ...string) *Store {
	s := &Store{db: db, unavailable: map[string]bool{}, now: time.Now}
	for _, k := range unavailable {
		s.unavailable[k] = true
	}
	for _, d := range Defs {
		for _, p := range d.Routes {
			s.routes = append(s.routes, route{key: d.Key, re: regexp.MustCompile(`(?i)` + p)})
		}
		for _, p := range d.Public {
			s.routes = append(s.routes, route{key: d.Key, re: regexp.MustCompile(`(?i)` + p), public: true})
		}
	}
	return s
}

// SetClock replaces the store's clock (tests: cache expiry without sleeping).
func (s *Store) SetClock(now func() time.Time) { s.now = now }

func lookup(key string) (Def, bool) {
	for _, d := range Defs {
		if d.Key == key {
			return d, true
		}
	}
	return Def{}, false
}

// FeatureFor returns the feature owning a request path (API or public), or "".
func (s *Store) FeatureFor(path string) string {
	for _, r := range s.routes {
		if r.re.MatchString(path) {
			return r.key
		}
	}
	return ""
}

func (s *Store) featureFor(path string, public bool) string {
	for _, r := range s.routes {
		if r.public == public && r.re.MatchString(path) {
			return r.key
		}
	}
	return ""
}

// Enabled reports whether a feature is on. An unknown key is on (callers only
// pass constants; a typo must not silently switch something off). When the
// switches can't be read, the last values read stay in force.
func (s *Store) Enabled(ctx context.Context, key string) bool {
	if s.unavailable[key] {
		return false
	}
	if _, ok := lookup(key); !ok {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.enabled == nil || s.now().Sub(s.loaded) >= CacheTTL {
		if err := s.reload(ctx); err != nil {
			slog.WarnContext(ctx, "feature: reading switches failed; keeping the last values", "error", err)
			s.loaded = s.now() // retry after CacheTTL, not on every request
		}
	}
	on, ok := s.enabled[key]
	return !ok || on
}

// reload reads every row; called with mu held.
func (s *Store) reload(ctx context.Context) error {
	rows, err := s.db.Query(ctx, `SELECT key, enabled, updated_at, updated_by::text FROM feature_flags`)
	if err != nil {
		return err
	}
	defer rows.Close()
	enabled, states := map[string]bool{}, map[string]State{}
	for rows.Next() {
		var st State
		var at time.Time
		if err := rows.Scan(&st.Key, &st.Enabled, &at, &st.UpdatedBy); err != nil {
			return err
		}
		st.UpdatedAt = &at
		enabled[st.Key] = st.Enabled
		states[st.Key] = st
	}
	if err := rows.Err(); err != nil {
		return err
	}
	s.enabled, s.rows, s.loaded = enabled, states, s.now()
	return nil
}

// List returns every feature's state, read fresh.
func (s *Store) List(ctx context.Context) ([]State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.reload(ctx); err != nil {
		return nil, err
	}
	out := make([]State, 0, len(Defs))
	for _, d := range Defs {
		st := State{Key: d.Key, Enabled: true, Available: !s.unavailable[d.Key], OwnerOnly: d.OwnerOnly}
		if row, ok := s.rows[d.Key]; ok {
			st.Enabled, st.UpdatedAt, st.UpdatedBy = row.Enabled, row.UpdatedAt, row.UpdatedBy
		}
		if !st.Available {
			st.Enabled = false
		}
		out = append(out, st)
	}
	return out, nil
}

// Set switches a feature and returns its new state. This replica sees the
// change immediately; the others within CacheTTL.
func (s *Store) Set(ctx context.Context, key string, enabled bool, actorID string) (State, error) {
	if _, ok := lookup(key); !ok {
		return State{}, fmt.Errorf("%w: %q", ErrUnknown, key)
	}
	if enabled && s.unavailable[key] {
		return State{}, ErrUnavailable
	}
	var by *string
	if actorID != "" {
		by = &actorID
	}
	if _, err := s.db.Exec(ctx, `
		INSERT INTO feature_flags (key, enabled, updated_by) VALUES ($1, $2, $3)
		ON CONFLICT (key) DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = now(), updated_by = EXCLUDED.updated_by`,
		key, enabled, by); err != nil {
		return State{}, err
	}
	states, err := s.List(ctx) // also refreshes the cache
	if err != nil {
		return State{}, err
	}
	for _, st := range states {
		if st.Key == key {
			return st, nil
		}
	}
	return State{}, fmt.Errorf("%w: %q", ErrUnknown, key)
}

// Unavailable lists the features cfg rules out: they read as off, and their
// switch can't turn them on until the server is configured for them.
func Unavailable(cfg config.Config) []string {
	var out []string
	if !cfg.MCPEnabled {
		out = append(out, MCP)
	}
	if !cfg.AI.Enabled {
		out = append(out, AITriage)
	}
	// Two-factor secrets are sealed with INTEGRATION_SECRET_KEY.
	if cfg.IntegrationSecretKey == "" {
		out = append(out, MFA)
	}
	return out
}
