package sbom

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"
)

// maxSbomBytes caps how much of an upload we buffer for parsing.
const maxSbomBytes = 64 << 20 // 64 MiB

// ErrProjectNotFound is returned when uploading against a missing project.
var ErrProjectNotFound = errors.New("project not found")

// projectChecker verifies a project exists before ingestion.
type projectChecker interface {
	Exists(ctx context.Context, id string) (bool, error)
}

// sbomStore persists a parsed SBOM, its components, services and dependency
// edges.
type sbomStore interface {
	Ingest(ctx context.Context, s Sbom, components []Component, services []BomService, edges []Edge) (Sbom, error)
}

// ComponentEvaluator is an optional post-ingest hook run once a snapshot is
// stored (policy.Service: component-policy evaluation of the snapshot's
// version). Implemented outside this package to avoid coupling SBOM storage to
// findings.
type ComponentEvaluator interface {
	Evaluate(ctx context.Context, projectID, versionID string, components []Component) error
}

// ProjectRescorer re-applies SBOM-derived reachability to a project's findings
// (correlation.Reacher satisfies it). Optional.
type ProjectRescorer interface {
	ApplyToProject(ctx context.Context, projectID string) (int, error)
}

// AdvisoryMatcher matches a project's snapshots against the advisory feed right
// away (vulnmatch.Service satisfies it), so a fresh upload shows its
// vulnerabilities without waiting for the next scheduled run. Optional.
type AdvisoryMatcher interface {
	MatchProject(ctx context.Context, projectID string) (int, error)
}

// PackageRefresher looks up registry metadata for a project's packages that
// were never fetched (pkgmeta.Service satisfies it), so a fresh upload shows
// which components are outdated without waiting for the next sweep. Optional.
type PackageRefresher interface {
	RefreshProject(ctx context.Context, projectID string) error
}

// IngestRequest carries the metadata accompanying an SBOM upload.
type IngestRequest struct {
	ProjectID string
	Artifact  string // optional override of the SBOM's own subject name
	Version   string // optional override of the subject version
	// Branch or Release names the project version the snapshot belongs to (at
	// most one; neither = the project's default version).
	Branch  string
	Release string
	// Strict opts this upload into strict CycloneDX schema validation
	// (?strict=true), in addition to the service-wide default
	// (SBOM_STRICT_VALIDATION, see WithStrictValidation).
	Strict bool
}

// Service parses uploaded SBOM documents and stores them as snapshots.
type Service struct {
	store         sbomStore
	projects      projectChecker
	evaluator     ComponentEvaluator // optional
	rescorer      ProjectRescorer    // optional
	matcher       AdvisoryMatcher    // optional
	packages      PackageRefresher   // optional
	licenses      LicenseResolver    // optional: nil leaves license_resolved NULL for the backfill
	internal      InternalMatcher    // optional: nil leaves every component external
	strictDefault bool               // SBOM_STRICT_VALIDATION: every upload is strict, not only ?strict=true ones
}

// NewService wires the ingestion dependencies. evaluator and rescorer may be nil.
func NewService(store sbomStore, projects projectChecker, evaluator ComponentEvaluator, rescorer ProjectRescorer) *Service {
	return &Service{store: store, projects: projects, evaluator: evaluator, rescorer: rescorer}
}

// WithMatcher makes every upload trigger an advisory match for its project, in
// the background: the feed is a network call, and an upload must not wait on —
// or fail because of — it. The scheduled run catches anything this misses.
func (s *Service) WithMatcher(m AdvisoryMatcher) *Service {
	s.matcher = m
	return s
}

// WithStrictValidation makes every upload strict (SBOM_STRICT_VALIDATION),
// not only ones that opt in with ?strict=true.
func (s *Service) WithStrictValidation(strict bool) *Service {
	s.strictDefault = strict
	return s
}

// WithPackageMeta makes every upload look up its new packages' registry
// metadata in the background — best-effort like the advisory match: the
// scheduled sweep catches anything this misses.
func (s *Service) WithPackageMeta(p PackageRefresher) *Service {
	s.packages = p
	return s
}

// matchTimeout bounds the background advisory match an upload starts.
const matchTimeout = 2 * time.Minute

// packageMetaTimeout bounds the background registry lookup an upload starts.
const packageMetaTimeout = 10 * time.Minute

// Ingest parses a CycloneDX document and stores it as a new snapshot. Request
// metadata takes precedence over the document's own subject fields.
func (s *Service) Ingest(ctx context.Context, req IngestRequest, raw io.Reader) (Sbom, error) {
	data, err := io.ReadAll(io.LimitReader(raw, maxSbomBytes))
	if err != nil {
		return Sbom{}, fmt.Errorf("read sbom: %w", err)
	}
	doc, err := Parse(data)
	if err != nil {
		return Sbom{}, fmt.Errorf("parse sbom: %w", err)
	}
	if req.Strict || s.strictDefault {
		if err := validateStrict(doc, data); err != nil {
			return Sbom{}, err
		}
	}

	exists, err := s.projects.Exists(ctx, req.ProjectID)
	if err != nil {
		return Sbom{}, err
	}
	if !exists {
		return Sbom{}, ErrProjectNotFound
	}

	record := Sbom{
		ProjectID:    req.ProjectID,
		Artifact:     firstNonEmpty(req.Artifact, doc.Artifact),
		Version:      firstNonEmpty(req.Version, doc.Version),
		Format:       doc.Format,
		SpecVersion:  doc.SpecVersion,
		SerialNumber: doc.SerialNumber,
		Source:       "upload",
		RootRef:      doc.RootRef,
		VersionName:  req.Branch,
		VersionKind:  "branch",
	}
	if req.Release != "" {
		record.VersionName, record.VersionKind = req.Release, "release"
	}
	if s.licenses != nil {
		resolveLicenses(s.licenses, doc.Components)
	}
	if s.internal != nil {
		markInternal(s.internal, doc.Components)
	}
	stored, err := s.store.Ingest(ctx, record, doc.Components, doc.Services, doc.Edges)
	if err != nil {
		return Sbom{}, err
	}

	// Run policy evaluation (e.g. license) as a best-effort side effect: the SBOM
	// is already persisted, so a policy error is logged, not surfaced.
	if s.evaluator != nil {
		if err := s.evaluator.Evaluate(ctx, req.ProjectID, stored.VersionID, doc.Components); err != nil {
			slog.WarnContext(ctx, "sbom policy evaluation failed", "error", err, "sbom_id", stored.ID)
		}
	}

	// A new SBOM rewrites the dependency graph: a package can go from direct to
	// transitive, or from runtime to dev-only, which changes what its existing
	// findings are worth. Re-score the project's backlog against the new
	// inventory. Best-effort, same as above.
	if s.rescorer != nil {
		if n, err := s.rescorer.ApplyToProject(ctx, req.ProjectID); err != nil {
			slog.WarnContext(ctx, "reachability rescore failed", "error", err, "sbom_id", stored.ID)
		} else if n > 0 {
			slog.InfoContext(ctx, "rescored findings against new SBOM",
				"count", n, "project_id", req.ProjectID, "sbom_id", stored.ID)
		}
	}
	if s.matcher != nil {
		go func(projectID, sbomID string) {
			ctx, cancel := context.WithTimeout(context.Background(), matchTimeout)
			defer cancel()
			if _, err := s.matcher.MatchProject(ctx, projectID); err != nil {
				slog.WarnContext(ctx, "advisory match after upload failed", "error", err, "sbom_id", sbomID)
			}
		}(req.ProjectID, stored.ID)
	}
	if s.packages != nil {
		go func(projectID, sbomID string) {
			ctx, cancel := context.WithTimeout(context.Background(), packageMetaTimeout)
			defer cancel()
			if err := s.packages.RefreshProject(ctx, projectID); err != nil {
				slog.WarnContext(ctx, "package metadata refresh after upload failed", "error", err, "sbom_id", sbomID)
			}
		}(req.ProjectID, stored.ID)
	}
	return stored, nil
}
