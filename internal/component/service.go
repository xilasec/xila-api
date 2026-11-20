package component

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// recomputer applies the computed internal flag to SBOM inventory
// (sbom.Repository.Recompute).
type recomputer interface {
	Recompute(ctx context.Context, match func(ecosystem, group, name string) bool) (int, error)
}

// Service manages internal-component patterns and keeps a compiled matcher
// cached, so Match — called once per component on every SBOM upload — never
// hits the database.
type Service struct {
	repo  *Repository
	sboms recomputer // optional: nil skips the recompute (component rows still get checked on ingest)

	mu      sync.RWMutex
	matcher *Matcher
}

// NewService constructs the Service with no patterns cached; call Warm once
// at startup to load the stored ones.
func NewService(repo *Repository, sboms recomputer) *Service {
	return &Service{repo: repo, sboms: sboms, matcher: &Matcher{}}
}

// Warm loads the current patterns into the cache. Call once at startup.
func (s *Service) Warm(ctx context.Context) error {
	return s.reload(ctx)
}

func (s *Service) reload(ctx context.Context) error {
	patterns, err := s.repo.List(ctx)
	if err != nil {
		return err
	}
	m, err := Compile(patterns)
	if err != nil {
		// Patterns are validated on save; a compile failure here means a
		// stored row went bad some other way. Keep the previous matcher
		// rather than silently treating everything as external.
		return err
	}
	s.mu.Lock()
	s.matcher = m
	s.mu.Unlock()
	return nil
}

// Match is sbom.InternalMatcher: whether a component with this ecosystem,
// group and name is internal, per the cached compiled patterns.
func (s *Service) Match(ecosystem, group, name string) bool {
	s.mu.RLock()
	m := s.matcher
	s.mu.RUnlock()
	return m.Match(ecosystem, group, name)
}

// List returns every pattern.
func (s *Service) List(ctx context.Context) ([]Pattern, error) {
	return s.repo.List(ctx)
}

// Get returns one pattern.
func (s *Service) Get(ctx context.Context, id string) (Pattern, error) {
	return s.repo.Get(ctx, id)
}

// Create validates and stores a pattern, then reloads the cache and
// recomputes existing inventory in the background.
func (s *Service) Create(ctx context.Context, p Pattern, actor *string) (Pattern, error) {
	if err := p.Validate(); err != nil {
		return Pattern{}, err
	}
	created, err := s.repo.Create(ctx, p, actor)
	if err != nil {
		return Pattern{}, err
	}
	s.changed(ctx)
	return created, nil
}

// Update validates and replaces a pattern, then reloads the cache and
// recomputes existing inventory in the background.
func (s *Service) Update(ctx context.Context, p Pattern) (Pattern, error) {
	if err := p.Validate(); err != nil {
		return Pattern{}, err
	}
	updated, err := s.repo.Update(ctx, p)
	if err != nil {
		return Pattern{}, err
	}
	s.changed(ctx)
	return updated, nil
}

// Delete removes a pattern, then reloads the cache and recomputes existing
// inventory in the background.
func (s *Service) Delete(ctx context.Context, id string) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	s.changed(ctx)
	return nil
}

// recomputeTimeout bounds a background recompute after a pattern change.
const recomputeTimeout = 30 * time.Minute

// changed reloads the matcher cache synchronously (so the very next upload
// sees it) and recomputes existing inventory's flag in the background (a
// full-table pass, too slow to hold the API request on).
func (s *Service) changed(ctx context.Context) {
	if err := s.reload(ctx); err != nil {
		slog.ErrorContext(ctx, "component: reloading pattern cache failed; it keeps the previous set", "error", err)
	}
	if s.sboms == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), recomputeTimeout)
		defer cancel()
		n, err := s.sboms.Recompute(ctx, s.Match)
		if err != nil {
			slog.WarnContext(ctx, "component: recomputing internal flags failed", "error", err)
			return
		}
		slog.InfoContext(ctx, "component: internal flags recomputed", "changed", n)
	}()
}
