package pkgmeta

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"
)

// ErrSweepRunning is returned when a sweep is requested while one runs.
var ErrSweepRunning = errors.New("a package metadata sweep is already running")

// store is the persistence the service needs (Repository).
type store interface {
	InventoryPurls(ctx context.Context, projectID string) ([]string, error)
	Due(ctx context.Context, bases []string, now time.Time) ([]due, error)
	Unknown(ctx context.Context, bases []string) ([]string, error)
	SaveFetched(ctx context.Context, m Meta) error
	SaveFailed(ctx context.Context, base, ecosystem, msg string, errorCount int, next time.Time) error
	Metas(ctx context.Context, bases []string) (map[string]Meta, error)
	PurlsNeedingStatus(ctx context.Context, refreshed []string, projectID string) ([]string, error)
	SaveStatuses(ctx context.Context, upserts []status, deletes []string) (int, error)
	ComponentHashes(ctx context.Context, purls []string) ([]componentHashes, error)
	SaveIntegrity(ctx context.Context, ids []string, verdicts []string) (int, error)
}

// Options tunes fetching.
type Options struct {
	// TTL is how long fetched metadata stays fresh (default 24h).
	TTL time.Duration
	// Concurrency is the number of packages fetched in parallel per registry
	// (default 4); each registry's client also rate-limits its requests.
	Concurrency int
	// Now is the clock (tests); nil = time.Now.
	Now func() time.Time
}

// Backoff bounds. A failed fetch retries after an hour, doubling per
// consecutive failure; a package the registry doesn't have (404) starts at the
// TTL, since it rarely appears overnight. Both cap at maxBackoff.
const (
	retryAfter = time.Hour
	maxBackoff = 7 * 24 * time.Hour
	// tripAfter consecutive transient failures from one registry abandon the
	// rest of that registry's packages for this sweep — when it is down,
	// don't hit it once per package.
	tripAfter = 5
	maxErrLen = 500
)

// SweepResult summarizes one run.
type SweepResult struct {
	Packages int `json:"packages"` // distinct supported packages in scope
	Due      int `json:"due"`      // never fetched, or stale
	Fetched  int `json:"fetched"`
	Failed   int `json:"failed"`
	Skipped  int `json:"skipped"`  // not attempted: registry tripped or run cancelled
	Statuses int `json:"statuses"` // component status rows written
}

// Service keeps package metadata fresh for current SBOM inventory.
type Service struct {
	store      store
	registries map[string]Registry
	ttl        time.Duration
	conc       int
	now        func() time.Time
	sweeping   sync.Mutex
}

// NewService constructs the service over registries keyed by ecosystem.
func NewService(st store, registries map[string]Registry, opts Options) *Service {
	s := &Service{store: st, registries: registries, ttl: opts.TTL, conc: opts.Concurrency, now: opts.Now}
	if s.ttl <= 0 {
		s.ttl = 24 * time.Hour
	}
	if s.conc <= 0 {
		s.conc = 4
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s
}

// Sweep refreshes the stale metadata of every package in current inventory
// and recomputes component statuses. Runs wait for each other.
func (s *Service) Sweep(ctx context.Context) (SweepResult, error) {
	s.sweeping.Lock()
	defer s.sweeping.Unlock()
	return s.run(ctx, "", false)
}

// TrySweep is Sweep, unless one is already running (ErrSweepRunning).
func (s *Service) TrySweep(ctx context.Context) (SweepResult, error) {
	if !s.sweeping.TryLock() {
		return SweepResult{}, ErrSweepRunning
	}
	defer s.sweeping.Unlock()
	return s.run(ctx, "", false)
}

// StartSweep runs Sweep in the background, bounded by timeout, unless one is
// already running (ErrSweepRunning). The outcome is logged.
func (s *Service) StartSweep(timeout time.Duration) error {
	if !s.sweeping.TryLock() {
		return ErrSweepRunning
	}
	go func() {
		defer s.sweeping.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		res, err := s.run(ctx, "", false)
		LogSweep(ctx, res, err)
	}()
	return nil
}

// LogSweep logs a sweep's outcome.
func LogSweep(ctx context.Context, res SweepResult, err error) {
	if err != nil {
		slog.WarnContext(ctx, "package metadata sweep failed", "error", err)
		return
	}
	slog.InfoContext(ctx, "package metadata sweep complete", "packages", res.Packages, "due", res.Due,
		"fetched", res.Fetched, "failed", res.Failed, "skipped", res.Skipped, "statuses", res.Statuses)
}

// RefreshProject looks up the packages of a project's current inventory that
// were never fetched and fills in its components' statuses — run after an
// SBOM upload so new packages don't wait for the next sweep (stale ones do).
func (s *Service) RefreshProject(ctx context.Context, projectID string) error {
	_, err := s.run(ctx, projectID, true)
	return err
}

func (s *Service) run(ctx context.Context, projectID string, newOnly bool) (SweepResult, error) {
	var res SweepResult
	purls, err := s.store.InventoryPurls(ctx, projectID)
	if err != nil {
		return res, err
	}
	pkgs := map[string]PURL{}
	for _, raw := range purls {
		p, err := ParsePURL(raw)
		if err != nil || !Supported(p.Type) {
			continue
		}
		p.Version = ""
		pkgs[p.Base()] = p
	}
	res.Packages = len(pkgs)
	bases := make([]string, 0, len(pkgs))
	for b := range pkgs {
		bases = append(bases, b)
	}

	var todo []due
	if newOnly {
		unknown, err := s.store.Unknown(ctx, bases)
		if err != nil {
			return res, err
		}
		for _, b := range unknown {
			todo = append(todo, due{Base: b})
		}
	} else if todo, err = s.store.Due(ctx, bases, s.now()); err != nil {
		return res, err
	}
	res.Due = len(todo)

	refreshed := s.fetch(ctx, pkgs, todo, &res)
	if err := ctx.Err(); err != nil {
		return res, err
	}
	n, changed, err := s.recompute(ctx, refreshed, projectID)
	res.Statuses = n
	if err != nil {
		return res, err
	}
	// Integrity: the purls whose status was just (re)computed — and, for one
	// project's refresh (an SBOM upload), its whole inventory: a new snapshot's
	// component can share a purl that already has a status, but its hashes
	// were never checked.
	if projectID != "" {
		changed = append(changed, purls...)
	}
	m, err := s.verify(ctx, changed)
	res.Statuses += m
	return res, err
}

// fetch looks up the due packages, each registry in parallel with a bounded
// number of packages in flight, recording success or backoff for each.
// Returns the packages fetched successfully.
func (s *Service) fetch(ctx context.Context, pkgs map[string]PURL, todo []due, res *SweepResult) []string {
	byEco := map[string][]due{}
	for _, d := range todo {
		eco := pkgs[d.Base].Type
		byEco[eco] = append(byEco[eco], d)
	}
	var (
		mu        sync.Mutex
		refreshed []string
		fetched   atomic.Int64
		failed    atomic.Int64
		skipped   atomic.Int64
		wg        sync.WaitGroup
	)
	for eco, list := range byEco {
		reg := s.registries[eco]
		if reg == nil {
			skipped.Add(int64(len(list)))
			continue
		}
		wg.Go(func() {
			var inflight sync.WaitGroup
			var streak atomic.Int64 // consecutive transient failures
			sem := make(chan struct{}, s.conc)
			for i, d := range list {
				// Take a slot first: the streak is only current once the
				// fetches before this one have finished.
				select {
				case <-ctx.Done():
				case sem <- struct{}{}:
				}
				if ctx.Err() != nil {
					skipped.Add(int64(len(list) - i))
					break
				}
				if streak.Load() >= tripAfter {
					<-sem
					slog.WarnContext(ctx, "package registry keeps failing; skipping it for this sweep",
						"ecosystem", eco, "skipped", len(list)-i)
					skipped.Add(int64(len(list) - i))
					break
				}
				inflight.Go(func() {
					defer func() { <-sem }()
					switch ok, transient := s.fetchOne(ctx, reg, pkgs[d.Base], d); {
					case ok:
						streak.Store(0)
						fetched.Add(1)
						mu.Lock()
						refreshed = append(refreshed, d.Base)
						mu.Unlock()
					case ctx.Err() != nil:
						skipped.Add(1)
					default:
						if transient {
							streak.Add(1)
						}
						failed.Add(1)
					}
				})
			}
			inflight.Wait()
		})
	}
	wg.Wait()
	res.Fetched, res.Failed, res.Skipped = int(fetched.Load()), int(failed.Load()), int(skipped.Load())
	return refreshed
}

// fetchOne fetches and stores one package. transient reports a failure that
// isn't "not found" (network, 5xx, 429), which counts toward tripping the
// registry.
func (s *Service) fetchOne(ctx context.Context, reg Registry, p PURL, d due) (ok, transient bool) {
	eco := reg.Ecosystem()
	pkg, err := reg.Fetch(ctx, p)
	now := s.now().UTC()
	if err != nil {
		if ctx.Err() != nil {
			return false, false // shutting down: not the package's fault
		}
		notFound := errors.Is(err, ErrNotFound)
		msg := err.Error()
		if len(msg) > maxErrLen {
			msg = msg[:maxErrLen]
		}
		n := d.ErrorCount + 1
		if serr := s.store.SaveFailed(ctx, d.Base, eco, msg, n, nextAfterFailure(now, s.ttl, n, notFound)); serr != nil {
			slog.WarnContext(ctx, "record package metadata failure", "error", serr, "purl", d.Base)
		}
		return false, !notFound
	}
	if err := s.store.SaveFetched(ctx, newMeta(d.Base, eco, pkg, now, s.ttl)); err != nil {
		slog.WarnContext(ctx, "store package metadata", "error", err, "purl", d.Base)
		return false, false
	}
	return true, false
}

// newMeta turns a registry answer into the cached metadata: versions newest
// first, the latest stable release resolved, fresh for ttl.
func newMeta(base, ecosystem string, pkg Package, now time.Time, ttl time.Duration) Meta {
	sch := schemeFor(ecosystem)
	versions := slices.Clone(pkg.Versions)
	if versions == nil {
		versions = []Version{}
	}
	slices.SortStableFunc(versions, func(a, b Version) int {
		return cmp.Or(-sch.compare(a.Version, b.Version), -cmp.Compare(a.Version, b.Version))
	})
	pkg.Versions = versions
	m := Meta{
		BasePurl: base, Ecosystem: ecosystem, Versions: versions,
		LatestVersion: latestStable(ecosystem, pkg), FetchedAt: &now, NextFetchAt: now.Add(ttl),
	}
	if m.LatestVersion != "" {
		m.LatestPublished = publishedAt(sch, versions, m.LatestVersion)
	}
	return m
}

// nextAfterFailure is when to retry after the n-th consecutive failure.
func nextAfterFailure(now time.Time, ttl time.Duration, n int, notFound bool) time.Time {
	d := retryAfter
	if notFound {
		d = max(ttl, retryAfter)
	}
	for i := 1; i < n && d < maxBackoff; i++ {
		d *= 2
	}
	return now.Add(min(d, maxBackoff))
}

// recompute writes the statuses of component purls that have none yet (in
// projectID, or anywhere) and of every purl of the refreshed packages.
func (s *Service) recompute(ctx context.Context, refreshed []string, projectID string) (int, []string, error) {
	purls, err := s.store.PurlsNeedingStatus(ctx, refreshed, projectID)
	if err != nil || len(purls) == 0 {
		return 0, purls, err
	}
	parsed := make(map[string]PURL, len(purls))
	baseSet := map[string]bool{}
	for _, raw := range purls {
		p, err := ParsePURL(raw)
		if err != nil || !Supported(p.Type) {
			continue
		}
		parsed[raw] = p
		baseSet[p.Base()] = true
	}
	bases := make([]string, 0, len(baseSet))
	for b := range baseSet {
		bases = append(bases, b)
	}
	metas, err := s.store.Metas(ctx, bases)
	if err != nil {
		return 0, purls, err
	}
	wasRefreshed := map[string]bool{}
	for _, b := range refreshed {
		wasRefreshed[b] = true
	}
	var upserts []status
	var deletes []string
	for raw, p := range parsed {
		base := p.Base()
		m, ok := metas[base]
		var info Info
		if ok {
			info, ok = evaluate(p.Type, m, p.Version)
		}
		switch {
		case ok:
			upserts = append(upserts, status{Purl: raw, Base: base, Version: p.Version, Info: info})
		case wasRefreshed[base]:
			deletes = append(deletes, raw) // had a status; the new metadata can't judge it
		}
	}
	n, err := s.store.SaveStatuses(ctx, upserts, deletes)
	return n, purls, err
}

// verify records the integrity of every hashed component among purls: its
// SBOM hashes against the digests the registry publishes for that version.
func (s *Service) verify(ctx context.Context, purls []string) (int, error) {
	if len(purls) == 0 {
		return 0, nil
	}
	comps, err := s.store.ComponentHashes(ctx, purls)
	if err != nil || len(comps) == 0 {
		return 0, err
	}
	parsed := map[string]PURL{}
	baseSet := map[string]bool{}
	for _, c := range comps {
		if p, err := ParsePURL(c.Purl); err == nil && Supported(p.Type) {
			parsed[c.Purl] = p
			baseSet[p.Base()] = true
		}
	}
	bases := make([]string, 0, len(baseSet))
	for b := range baseSet {
		bases = append(bases, b)
	}
	metas, err := s.store.Metas(ctx, bases)
	if err != nil {
		return 0, err
	}
	var ids, verdicts []string
	for _, c := range comps {
		verdict := IntegrityUnknown
		if p, ok := parsed[c.Purl]; ok {
			if m, ok := metas[p.Base()]; ok {
				for _, v := range m.Versions {
					if v.Version == p.Version {
						verdict = VerifyIntegrity(c.Hashes, v.Hashes)
						break
					}
				}
			}
		}
		ids, verdicts = append(ids, c.ID), append(verdicts, string(verdict))
	}
	return s.store.SaveIntegrity(ctx, ids, verdicts)
}
