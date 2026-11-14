package sso

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"sync"
	"time"
)

// Protocol builds a ready-to-use client for one kind of provider: OIDC
// discovery, SAML IdP metadata + SP key. Implemented by internal/oidc and
// internal/saml (which this package cannot import).
type Protocol interface {
	Build(ctx context.Context, p Provider) (Client, error)
}

// Client is a built protocol client. The protocol package's handlers type-
// assert it back to their own type.
type Client interface {
	// Report describes what the IdP published (endpoints, certificates), for
	// the admin page's dry-run test.
	Report() Report
}

// Report is what a provider's IdP publishes, as found by a build.
type Report struct {
	Details      []Setting     `json:"details"`
	Certificates []Certificate `json:"certificates,omitempty"`
	Warnings     []string      `json:"warnings,omitempty"`
}

// Setting is one labelled value.
type Setting struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

// Certificate is an IdP signing certificate from SAML metadata.
type Certificate struct {
	Subject  string    `json:"subject"`
	NotAfter time.Time `json:"not_after"`
	Expired  bool      `json:"expired"`
}

// ProviderStore is where the admin-managed providers live (ProviderRepository).
type ProviderStore interface {
	List(ctx context.Context) ([]Provider, error)
	Get(ctx context.Context, id string) (Provider, error)
	GetBySlug(ctx context.Context, slug string) (Provider, error)
	Unseal(p *Provider) error
}

// Registry resolves providers — the environment ones plus the database ones —
// and caches each one's built client.
//
// Propagation: every login request re-reads its provider row (one indexed
// query), so disabling, deleting or editing a provider applies on every
// replica at the next request — no restart, no delay. The expensive part, the
// client (discovery, metadata fetch), is cached per provider *version*
// (updated_at): an edit rebuilds it on each replica's next use. Built clients
// are refreshed after refreshAfter (IdP certificate rotation); a failed build
// is retried after retryAfter, and a failed refresh keeps serving the last
// good client. A provider whose build fails is reported with its error on the
// admin page and left off the login page; it never affects the others.
type Registry struct {
	store     ProviderStore
	env       []Provider
	protocols map[string]Protocol

	mu    sync.Mutex
	cache map[string]*entry // by provider id
}

const (
	refreshAfter = time.Hour
	retryAfter   = time.Minute
	buildTimeout = 20 * time.Second
	// loginPageWait bounds how long the public login page waits for a
	// provider that is still being built; it is left off until ready.
	loginPageWait = 3 * time.Second
	// adminWait bounds the same for the admin page, which shows "pending".
	adminWait = 10 * time.Second
)

// ErrUnavailable means the provider is configured and enabled but its client
// could not be built (IdP unreachable, bad metadata…).
var ErrUnavailable = errors.New("sso provider unavailable")

// NewRegistry constructs a Registry over the environment providers and the
// store, with a Protocol per kind.
func NewRegistry(store ProviderStore, env []Provider, protocols map[string]Protocol) *Registry {
	return &Registry{store: store, env: env, protocols: protocols, cache: map[string]*entry{}}
}

// entry is one build of one provider version.
type entry struct {
	version string
	done    chan struct{} // closed when the build finished
	prev    Client        // last good client of the same version, served during a refresh
	client  Client        // after done: the new client, or prev if the build failed
	err     error         // after done: the build error
	at      time.Time     // after done
}

func (e *entry) finished() bool {
	select {
	case <-e.done:
		return true
	default:
		return false
	}
}

func (e *entry) stale(now time.Time) bool {
	if e.err != nil {
		return now.Sub(e.at) > retryAfter
	}
	return now.Sub(e.at) > refreshAfter
}

// wait returns the usable client (nil if none) and the last build error, or
// a nil client and ctx's error if the build is still running.
func (e *entry) wait(ctx context.Context) (Client, error) {
	if e.prev != nil && !e.finished() {
		return e.prev, nil
	}
	select {
	case <-e.done:
		return e.client, e.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func version(p Provider) string {
	if p.Env() {
		return "env"
	}
	return strconv.FormatInt(p.UpdatedAt.UnixNano(), 10)
}

// entryFor returns the current build of p, starting one if there is none for
// this version, or the last one is due for a refresh/retry.
func (r *Registry) entryFor(p Provider) *entry {
	v := version(p)
	r.mu.Lock()
	defer r.mu.Unlock()
	e := r.cache[p.ID]
	if e != nil && e.version == v && (!e.finished() || !e.stale(time.Now())) {
		return e
	}
	next := &entry{version: v, done: make(chan struct{})}
	if e != nil && e.version == v && e.finished() {
		next.prev = e.client
	}
	r.cache[p.ID] = next
	go r.build(next, p)
	return next
}

func (r *Registry) build(e *entry, p Provider) {
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()
	client, err := r.buildClient(ctx, p)
	if err != nil {
		slog.Warn("sso provider unavailable", "provider", p.Slug, "kind", p.Kind, "source", p.Source, "error", err)
		client = e.prev
	}
	e.client, e.err, e.at = client, err, time.Now()
	close(e.done)
}

func (r *Registry) buildClient(ctx context.Context, p Provider) (Client, error) {
	proto, ok := r.protocols[p.Kind]
	if !ok {
		return nil, fmt.Errorf("no protocol for kind %q", p.Kind)
	}
	if !p.Env() {
		if err := r.store.Unseal(&p); err != nil {
			return nil, err
		}
	}
	client, err := proto.Build(ctx, p)
	if err == nil && client == nil {
		err = errors.New("no client built")
	}
	return client, err
}

// Invalidate drops a provider's cached client (after a test or a delete).
func (r *Registry) Invalidate(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.cache, id)
}

// Resolved is a provider ready to sign someone in.
type Resolved struct {
	Provider Provider
	Client   Client
}

// Resolve returns the enabled provider of this kind and slug with its client.
// ErrProviderNotFound for an unknown or disabled one (its routes 404);
// ErrUnavailable when its client cannot be built.
func (r *Registry) Resolve(ctx context.Context, kind, slug string) (Resolved, error) {
	p, err := r.bySlug(ctx, slug)
	if err != nil {
		return Resolved{}, err
	}
	if p.Kind != kind || !p.Enabled {
		return Resolved{}, ErrProviderNotFound
	}
	wctx, cancel := context.WithTimeout(ctx, buildTimeout)
	defer cancel()
	client, err := r.entryFor(p).wait(wctx)
	if client == nil {
		return Resolved{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return Resolved{Provider: p, Client: client}, nil
}

func (r *Registry) bySlug(ctx context.Context, slug string) (Provider, error) {
	for _, p := range r.env {
		if p.Slug == slug {
			return p, nil
		}
	}
	if ReservedSlug(slug) {
		return Provider{}, ErrProviderNotFound
	}
	return r.store.GetBySlug(ctx, slug)
}

// Get returns a provider by id: an environment one by its kind, a database
// one by uuid.
func (r *Registry) Get(ctx context.Context, id string) (Provider, error) {
	for _, p := range r.env {
		if p.ID == id {
			return p, nil
		}
	}
	return r.store.Get(ctx, id)
}

// Environment returns the environment providers.
func (r *Registry) Environment() []Provider { return r.env }

// All returns every provider, environment and database, in login-page order:
// sort order, environment first, then name. If the database cannot be read,
// the environment providers are still returned, with the error.
func (r *Registry) All(ctx context.Context) ([]Provider, error) {
	stored, err := r.store.List(ctx)
	all := append(slices.Clone(r.env), stored...)
	slices.SortStableFunc(all, func(a, b Provider) int {
		return cmp.Or(cmp.Compare(a.SortOrder, b.SortOrder), cmp.Compare(b.Source, a.Source), cmp.Compare(a.Name, b.Name))
	})
	if err == nil {
		r.prune(all)
	}
	return all, err
}

// prune drops cache entries of providers that no longer exist.
func (r *Registry) prune(all []Provider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for id := range r.cache {
		if !slices.ContainsFunc(all, func(p Provider) bool { return p.ID == id }) {
			delete(r.cache, id)
		}
	}
}

// Provider statuses on the admin page.
const (
	StatusOK       = "ok"       // client built; login works
	StatusError    = "error"    // client could not be built; hidden from the login page
	StatusPending  = "pending"  // still building
	StatusDisabled = "disabled" // switched off; its routes 404
)

// Status is a provider's health: whether a login can work right now.
type Status struct {
	Status    string `json:"status"`
	LastError string `json:"last_error,omitempty"`
}

// Statuses builds (or reuses) every enabled provider's client concurrently and
// reports each one's health, waiting at most wait.
func (r *Registry) Statuses(ctx context.Context, providers []Provider, wait time.Duration) []Status {
	entries := make([]*entry, len(providers))
	for i, p := range providers {
		if p.Enabled {
			entries[i] = r.entryFor(p)
		}
	}
	wctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	out := make([]Status, len(providers))
	for i, e := range entries {
		if e == nil {
			out[i] = Status{Status: StatusDisabled}
			continue
		}
		client, err := e.wait(wctx)
		if e.finished() {
			client, err = e.client, e.err
		}
		switch {
		case client != nil && err != nil:
			out[i] = Status{Status: StatusOK, LastError: "refresh failed (serving the last good configuration): " + err.Error()}
		case client != nil:
			out[i] = Status{Status: StatusOK}
		case e.finished():
			out[i] = Status{Status: StatusError, LastError: err.Error()}
		default:
			out[i] = Status{Status: StatusPending}
		}
	}
	return out
}

// LoginOption is one login-page button.
type LoginOption struct {
	Kind     string `json:"kind"`
	Name     string `json:"name"`
	LoginURL string `json:"login_url"`
}

// LoginOptions are the enabled providers whose client works, in order — the
// login page's buttons. A provider still being built after loginPageWait is
// left off this time.
func (r *Registry) LoginOptions(ctx context.Context) ([]LoginOption, error) {
	all, err := r.All(ctx)
	statuses := r.Statuses(ctx, all, loginPageWait)
	out := []LoginOption{}
	for i, p := range all {
		if statuses[i].Status == StatusOK {
			out = append(out, LoginOption{Kind: p.Kind, Name: p.Name, LoginURL: p.Endpoints.LoginURL})
		}
	}
	return out, err
}

// Test builds a client for p from scratch — nothing cached — and reports
// what the IdP published, or why it failed.
func (r *Registry) Test(ctx context.Context, p Provider) TestResult {
	ctx, cancel := context.WithTimeout(ctx, buildTimeout)
	defer cancel()
	client, err := r.buildClient(ctx, p)
	if err != nil {
		return TestResult{OK: false, Error: err.Error()}
	}
	return TestResult{OK: true, Report: client.Report()}
}

// TestResult is a dry run's outcome.
type TestResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
	Report
}
