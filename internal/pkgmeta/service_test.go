package pkgmeta

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"
)

// memStore is an in-memory store with the Repository's semantics.
type memStore struct {
	mu         sync.Mutex
	purls      []string
	metas      map[string]Meta
	statuses   map[string]status
	components []componentHashes
	integrity  map[string]string // component id → verdict
}

func newMemStore(purls ...string) *memStore {
	return &memStore{purls: purls, metas: map[string]Meta{}, statuses: map[string]status{}, integrity: map[string]string{}}
}

func (m *memStore) InventoryPurls(context.Context, string) ([]string, error) { return m.purls, nil }

func (m *memStore) Due(_ context.Context, bases []string, now time.Time) ([]due, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []due
	for _, b := range bases {
		meta, ok := m.metas[b]
		if !ok || !meta.NextFetchAt.After(now) {
			out = append(out, due{Base: b, ErrorCount: meta.ErrorCount})
		}
	}
	return out, nil
}

func (m *memStore) Unknown(_ context.Context, bases []string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, b := range bases {
		if _, ok := m.metas[b]; !ok {
			out = append(out, b)
		}
	}
	return out, nil
}

func (m *memStore) SaveFetched(_ context.Context, meta Meta) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metas[meta.BasePurl] = meta
	return nil
}

func (m *memStore) SaveFailed(_ context.Context, base, eco, msg string, n int, next time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	meta := m.metas[base]
	meta.BasePurl, meta.Ecosystem, meta.LastError, meta.ErrorCount, meta.NextFetchAt = base, eco, msg, n, next
	m.metas[base] = meta
	return nil
}

func (m *memStore) Metas(_ context.Context, bases []string) (map[string]Meta, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]Meta{}
	for _, b := range bases {
		if meta, ok := m.metas[b]; ok && meta.FetchedAt != nil {
			out[b] = meta
		}
	}
	return out, nil
}

func (m *memStore) PurlsNeedingStatus(context.Context, []string, string) ([]string, error) {
	return m.purls, nil
}

func (m *memStore) SaveStatuses(_ context.Context, upserts []status, deletes []string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, s := range upserts {
		m.statuses[s.Purl] = s
	}
	for _, d := range deletes {
		delete(m.statuses, d)
	}
	return len(upserts) + len(deletes), nil
}

func (m *memStore) ComponentHashes(_ context.Context, purls []string) ([]componentHashes, error) {
	var out []componentHashes
	for _, c := range m.components {
		if slices.Contains(purls, c.Purl) {
			out = append(out, c)
		}
	}
	return out, nil
}

func (m *memStore) SaveIntegrity(_ context.Context, ids, verdicts []string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, id := range ids {
		m.integrity[id] = verdicts[i]
	}
	return len(ids), nil
}

// stubRegistry answers from a map; a missing package is ErrNotFound and an
// error value fails the fetch.
type stubRegistry struct {
	eco   string
	mu    sync.Mutex
	pkgs  map[string]Package
	fail  error
	calls int
}

func (s *stubRegistry) Ecosystem() string { return s.eco }

func (s *stubRegistry) Fetch(_ context.Context, p PURL) (Package, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	if s.fail != nil {
		return Package{}, s.fail
	}
	pkg, ok := s.pkgs[p.Base()]
	if !ok {
		return Package{}, ErrNotFound
	}
	return pkg, nil
}

func TestSweepSchedulesAndBacksOff(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	st := newMemStore("pkg:npm/a@1.0.0", "pkg:npm/private@1.0.0", "pkg:deb/debian/curl@7.0", "not a purl")
	reg := &stubRegistry{eco: NPM, pkgs: map[string]Package{
		"pkg:npm/a": {Latest: "2.0.0", Versions: []Version{v("1.0.0"), v("2.0.0")}},
	}}
	svc := NewService(st, map[string]Registry{NPM: reg}, Options{TTL: 24 * time.Hour, Now: clock})

	res, err := svc.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Unsupported ecosystems and garbage are ignored, not fetched.
	if res.Packages != 2 || res.Due != 2 || res.Fetched != 1 || res.Failed != 1 {
		t.Fatalf("first sweep = %+v", res)
	}
	if s, ok := st.statuses["pkg:npm/a@1.0.0"]; !ok || !s.Outdated || s.Latest != "2.0.0" {
		t.Errorf("status of a = %+v", s)
	}
	if _, ok := st.statuses["pkg:npm/private@1.0.0"]; ok {
		t.Error("a package the registry doesn't know got a status")
	}
	priv := st.metas["pkg:npm/private"]
	if priv.ErrorCount != 1 || priv.NextFetchAt != now.Add(24*time.Hour) || priv.FetchedAt != nil {
		t.Errorf("404 backoff = %+v", priv)
	}

	// Fresh entries aren't refetched until the TTL passes.
	reg.calls = 0
	if res, _ = svc.Sweep(context.Background()); res.Due != 0 || reg.calls != 0 {
		t.Errorf("sweep within TTL fetched: %+v, %d calls", res, reg.calls)
	}
	now = now.Add(25 * time.Hour)
	if res, _ = svc.Sweep(context.Background()); res.Due != 2 || res.Fetched != 1 {
		t.Errorf("sweep after TTL = %+v", res)
	}
	if got := st.metas["pkg:npm/private"]; got.ErrorCount != 2 || got.NextFetchAt != now.Add(48*time.Hour) {
		t.Errorf("second 404 backoff = %+v", got)
	}

	// A transient failure keeps the stale data (stale beats unknown) and
	// retries sooner than the TTL.
	now = now.Add(25 * time.Hour)
	reg.fail = errors.New("connection reset")
	if _, err := svc.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	a := st.metas["pkg:npm/a"]
	if a.FetchedAt == nil || a.LatestVersion != "2.0.0" || a.ErrorCount != 1 || a.NextFetchAt != now.Add(time.Hour) {
		t.Errorf("transient failure state = %+v", a)
	}
	if _, ok := st.statuses["pkg:npm/a@1.0.0"]; !ok {
		t.Error("a transient failure dropped the existing status")
	}
	// Recovery clears the error state.
	reg.fail = nil
	now = now.Add(time.Hour)
	if _, err := svc.Sweep(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a := st.metas["pkg:npm/a"]; a.ErrorCount != 0 || a.LastError != "" {
		t.Errorf("recovered state = %+v", a)
	}
}

func TestSweepTripsFailingRegistry(t *testing.T) {
	var purls []string
	for i := range 30 {
		purls = append(purls, fmt.Sprintf("pkg:cargo/c%d@1.0.0", i))
	}
	st := newMemStore(purls...)
	reg := &stubRegistry{eco: Cargo, fail: errors.New("status 503")}
	svc := NewService(st, map[string]Registry{Cargo: reg}, Options{Concurrency: 1})
	res, err := svc.Sweep(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if reg.calls != tripAfter || res.Failed != tripAfter || res.Skipped != 30-tripAfter {
		t.Errorf("a down registry got %d calls (%+v), want %d", reg.calls, res, tripAfter)
	}
}

func TestRefreshProjectFetchesOnlyNewPackages(t *testing.T) {
	st := newMemStore("pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0")
	reg := &stubRegistry{eco: NPM, pkgs: map[string]Package{
		"pkg:npm/a": {Latest: "1.0.0", Versions: []Version{v("1.0.0")}},
		"pkg:npm/b": {Latest: "1.1.0", Versions: []Version{v("1.0.0"), v("1.1.0")}},
	}}
	now := time.Now()
	st.metas["pkg:npm/a"] = Meta{BasePurl: "pkg:npm/a", Ecosystem: NPM, FetchedAt: &now, NextFetchAt: now.Add(-time.Hour),
		LatestVersion: "1.0.0", Versions: []Version{v("1.0.0")}}
	svc := NewService(st, map[string]Registry{NPM: reg}, Options{})
	if err := svc.RefreshProject(context.Background(), "p"); err != nil {
		t.Fatal(err)
	}
	if reg.calls != 1 {
		t.Errorf("upload refresh made %d calls, want 1 (only the never-seen package)", reg.calls)
	}
	if s := st.statuses["pkg:npm/b@1.0.0"]; !s.Outdated {
		t.Errorf("status of b = %+v", s)
	}
	if s, ok := st.statuses["pkg:npm/a@1.0.0"]; !ok || s.Outdated {
		t.Errorf("status of a (from cache) = %+v", s)
	}
}

func TestTrySweepRejectsConcurrentRun(t *testing.T) {
	svc := NewService(newMemStore(), nil, Options{})
	svc.sweeping.Lock()
	defer svc.sweeping.Unlock()
	if _, err := svc.TrySweep(context.Background()); !errors.Is(err, ErrSweepRunning) {
		t.Errorf("err = %v, want ErrSweepRunning", err)
	}
	if err := svc.StartSweep(time.Second); !errors.Is(err, ErrSweepRunning) {
		t.Errorf("StartSweep err = %v, want ErrSweepRunning", err)
	}
}
