package psirt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/vulnmatch"
)

// Config is the PSIRT_* configuration.
type Config struct {
	Public    bool
	Prefix    string
	Publisher Publisher
	// BaseURL is where the provider directory is served (PUBLIC_URL).
	BaseURL string
}

// privateAdvisories reads the private advisory database a draft can start
// from (vulnmatch.AdvisoryRepository).
type privateAdvisories interface {
	Get(ctx context.Context, id string) (vulnmatch.Advisory, error)
}

// Service is the advisory lifecycle.
type Service struct {
	repo    *Repository
	private privateAdvisories
	cfg     Config
	now     func() time.Time
}

// NewService constructs the service; private may be nil.
func NewService(repo *Repository, private privateAdvisories, cfg Config) *Service {
	if cfg.Prefix == "" {
		cfg.Prefix = "XILA-SA"
	}
	return &Service{repo: repo, private: private, cfg: cfg, now: time.Now}
}

// Config returns the configuration (for the UI and the public handler).
func (s *Service) Config() Config { return s.cfg }

// ErrNoSourceAdvisory is returned for an unknown source_advisory_id.
var ErrNoSourceAdvisory = errors.New("source advisory not found")

// Create stores a draft. With source_advisory_id the private advisory fills
// whatever the draft leaves empty (title, summary, details, CVSS, CVE).
func (s *Service) Create(ctx context.Context, a Advisory, actor *string) (Advisory, error) {
	if a.SourceAdvisoryID != nil && *a.SourceAdvisoryID != "" {
		if s.private == nil {
			return Advisory{}, ErrNoSourceAdvisory
		}
		src, err := s.private.Get(ctx, *a.SourceAdvisoryID)
		if errors.Is(err, vulnmatch.ErrAdvisoryNotFound) {
			return Advisory{}, ErrNoSourceAdvisory
		}
		if err != nil {
			return Advisory{}, err
		}
		fill := func(dst *string, v string) {
			if strings.TrimSpace(*dst) == "" {
				*dst = v
			}
		}
		fill(&a.Title, src.Summary)
		fill(&a.Summary, src.Summary)
		fill(&a.Details, src.Details)
		if strings.HasPrefix(src.CVSSVector, "CVSS:3.") {
			fill(&a.CVSSVector, src.CVSSVector)
		}
		for _, al := range src.Aliases {
			if cveRe.MatchString(al) {
				fill(&a.CVE, al)
			}
		}
	} else {
		a.SourceAdvisoryID = nil
	}
	if err := a.Validate(); err != nil {
		return Advisory{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	return s.repo.Create(ctx, a, s.cfg.Prefix, actor)
}

// Preview renders the document the next publish would freeze (status draft,
// the pending revision appended), without storing anything.
func (s *Service) Preview(ctx context.Context, id string) (json.RawMessage, error) {
	a, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC().Truncate(time.Second)
	a.Version++
	if a.InitialReleaseAt == nil {
		a.InitialReleaseAt = &now
	}
	a.CurrentReleaseAt = &now
	a.Revisions = append(a.Revisions, Revision{Number: a.Version, Date: now, Summary: "Preview of the next release."})
	d, err := Render(a, s.cfg.Publisher, s.cfg.BaseURL, "draft", now)
	if err != nil {
		return nil, err
	}
	return Marshal(d)
}

// Publish releases the advisory: the first time with the note (default
// "Initial release."), afterwards as a republish that needs a note.
func (s *Service) Publish(ctx context.Context, id, note string, actor *string) (Advisory, error) {
	if !s.cfg.Publisher.Configured() {
		return Advisory{}, ErrPublisher
	}
	note = strings.TrimSpace(note)
	return s.repo.release(ctx, id, StatePublished, actor,
		func(st State) bool { return st == StateDraft || st == StatePublished },
		func(version int) (string, error) {
			switch {
			case note != "":
				return note, nil
			case version == 1:
				return "Initial release.", nil
			}
			return "", ErrNoteRequired
		}, s.render)
}

// Withdraw retracts a published advisory with a final revision; the document
// stays distributed so consumers learn of the withdrawal.
func (s *Service) Withdraw(ctx context.Context, id, note string, actor *string) (Advisory, error) {
	if !s.cfg.Publisher.Configured() {
		return Advisory{}, ErrPublisher
	}
	note = strings.TrimSpace(note)
	if note == "" {
		return Advisory{}, ErrNoteRequired
	}
	return s.repo.release(ctx, id, StateWithdrawn, actor,
		func(st State) bool { return st == StatePublished },
		func(int) (string, error) { return "Withdrawn: " + note, nil }, s.render)
}

func (s *Service) render(a Advisory) (json.RawMessage, error) {
	d, err := Render(a, s.cfg.Publisher, s.cfg.BaseURL, "final", s.now())
	if err != nil {
		return nil, err
	}
	return Marshal(d)
}
