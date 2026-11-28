package customparser

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/xilasec/xila-api/internal/scanner"
)

// builtinNames lists the registered built-in scanner names (scanner.Registry
// satisfies it), so a custom parser can't take one of their identifiers.
type builtinNames interface {
	Supported() []string
}

// cacheEntry is one compiled custom parser, valid as long as its definition's
// updated_at hasn't moved.
type cacheEntry struct {
	updatedAt time.Time
	parser    *scanner.CustomParser
}

// Service validates, compiles and resolves custom parser definitions.
type Service struct {
	repo     *Repository
	builtins builtinNames
	cache    sync.Map // name -> cacheEntry
}

// NewService constructs a Service.
func NewService(repo *Repository, builtins builtinNames) *Service {
	return &Service{repo: repo, builtins: builtins}
}

// Validate checks a definition's shape (ValidateCustomDefinition) and that
// its name doesn't collide with a built-in parser. A collision with another
// custom parser's name is enforced by the database's unique constraint
// (ErrDuplicate), since only the database can see every stored name
// consistently across replicas.
func (s *Service) Validate(def scanner.CustomDefinition) error {
	if err := scanner.ValidateCustomDefinition(def); err != nil {
		return err
	}
	if slices.Contains(s.builtins.Supported(), def.Name) {
		return fmt.Errorf("%q is already a built-in scanner name", def.Name)
	}
	return nil
}

// List returns every stored custom parser.
func (s *Service) List(ctx context.Context) ([]Definition, error) {
	return s.repo.List(ctx)
}

// Get fetches one custom parser.
func (s *Service) Get(ctx context.Context, id string) (Definition, error) {
	return s.repo.Get(ctx, id)
}

// Create validates and stores a new custom parser.
func (s *Service) Create(ctx context.Context, def scanner.CustomDefinition, actor string) (Definition, error) {
	if err := s.Validate(def); err != nil {
		return Definition{}, &ValidationError{err}
	}
	return s.repo.Create(ctx, Definition{CustomDefinition: def}, actor)
}

// Update validates and replaces a custom parser's mapping, invalidating the
// resolve cache so the next upload picks up the change immediately on this
// node (other nodes re-read on updated_at the next time they resolve it).
func (s *Service) Update(ctx context.Context, id string, def scanner.CustomDefinition) (Definition, error) {
	if err := s.Validate(def); err != nil {
		return Definition{}, &ValidationError{err}
	}
	out, err := s.repo.Update(ctx, Definition{ID: id, CustomDefinition: def})
	if err != nil {
		return Definition{}, err
	}
	s.cache.Delete(out.Name)
	return out, nil
}

// Delete removes a custom parser. Its findings keep their scanner name as
// history (Repository.Delete never touches findings).
func (s *Service) Delete(ctx context.Context, id string) error {
	def, err := s.repo.Get(ctx, id)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, id); err != nil {
		return err
	}
	s.cache.Delete(def.Name)
	return nil
}

// DryRun validates def, compiles it, and parses sample without persisting
// anything: the findings it would create, plus any per-record mapping
// errors, for the admin mapping editor's live preview.
func (s *Service) DryRun(def scanner.CustomDefinition, sample []byte) ([]scanner.ParsedFinding, []scanner.RecordError, error) {
	if err := s.Validate(def); err != nil {
		return nil, nil, &ValidationError{err}
	}
	p, err := scanner.NewCustomParser(def)
	if err != nil {
		return nil, nil, &ValidationError{err}
	}
	return p.ParseDetailed(bytes.NewReader(sample))
}

// ValidationError marks a definition rejected by Validate (a bad mapping),
// as opposed to a storage failure — the handler maps it to 400 rather than
// the catch-all 500 a wrapped database error gets.
type ValidationError struct{ err error }

func (e *ValidationError) Error() string { return e.err.Error() }
func (e *ValidationError) Unwrap() error { return e.err }

// Resolve looks up a custom parser by scanner name for the upload path
// (scan.Service falls back to this when the static registry has no built-in
// match). Every call re-reads the definition's row by name — one indexed
// lookup — and compares its updated_at against the cached compiled parser,
// so an edit on another replica is picked up on this node's very next
// upload rather than waiting for a restart.
func (s *Service) Resolve(ctx context.Context, name string) (scanner.Parser, bool, error) {
	def, err := s.repo.GetByName(ctx, name)
	if errors.Is(err, ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if cached, ok := s.cache.Load(name); ok {
		if entry, ok := cached.(cacheEntry); ok && entry.updatedAt.Equal(def.UpdatedAt) {
			return entry.parser, true, nil
		}
	}
	p, err := scanner.NewCustomParser(def.CustomDefinition)
	if err != nil {
		// A stored definition was validated on save, so this should not
		// happen; refuse the upload rather than silently dropping it.
		return nil, false, fmt.Errorf("compile custom parser %q: %w", name, err)
	}
	s.cache.Store(name, cacheEntry{updatedAt: def.UpdatedAt, parser: p})
	return p, true, nil
}
