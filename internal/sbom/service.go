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

// ErrStrictXMLUnsupported is returned when strict validation (?strict=true or
// SBOM_STRICT_VALIDATION) is requested for a CycloneDX XML upload: the
// official schema validator (internal/sbom/schema) only checks JSON.
var ErrStrictXMLUnsupported = errors.New("strict validation is JSON-only: upload this CycloneDX XML document without ?strict=true (and without SBOM_STRICT_VALIDATION)")

// projectChecker verifies a project exists before ingestion.
type projectChecker interface {
	Exists(ctx context.Context, id string) (bool, error)
}

// sbomStore persists a parsed SBOM, its components, services and dependency
// edges, and tracks each upload's background-processing status (M13 13.3).
type sbomStore interface {
	Ingest(ctx context.Context, s Sbom, components []Component, services []BomService, edges []Edge) (Sbom, error)
	CreateProcessing(ctx context.Context, sbomID string, steps []string) (ProcessingStatus, error)
	MarkStep(ctx context.Context, sbomID, step, status, errMsg string) (ProcessingStatus, error)
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
	evaluator     ComponentEvaluator                                        // optional
	rescorer      ProjectRescorer                                           // optional
	matcher       AdvisoryMatcher                                           // optional
	packages      PackageRefresher                                          // optional
	licenses      LicenseResolver                                           // optional: nil leaves license_resolved NULL for the backfill
	loadOverrides func(ctx context.Context) (LicenseOverrideMatcher, error) // optional: a project's curated concluded licenses
	strictDefault bool                                                      // SBOM_STRICT_VALIDATION: every upload is strict, not only ?strict=true ones
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

// WithLicenseOverrides applies a project's curated concluded licenses
// (M13 13.12) after the SBOM's own license is resolved, on every upload.
// matcher is re-fetched fresh by the caller for each call (license overrides
// change rarely and the set is small; see license.NewMatcher).
func (s *Service) WithLicenseOverrides(matcher func(ctx context.Context) (LicenseOverrideMatcher, error)) *Service {
	s.loadOverrides = matcher
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
		if doc.XML {
			return Sbom{}, ErrStrictXMLUnsupported
		}
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
	if s.loadOverrides != nil {
		overrides, err := s.loadOverrides(ctx)
		if err != nil {
			return Sbom{}, fmt.Errorf("load license overrides: %w", err)
		}
		applyLicenseOverrides(overrides, req.ProjectID, doc.Components)
	}
	stored, err := s.store.Ingest(ctx, record, doc.Components, doc.Services, doc.Edges)
	if err != nil {
		return Sbom{}, err
	}

	// Track every enabled post-ingest step (M13 13.3) so a gate run right
	// after upload can wait for them (GET /sboms/{id}/status) instead of
	// seeing stale advisory/policy/reachability state. A disabled feature's
	// step is never added, so it can't block "completed".
	var steps []string
	if s.evaluator != nil {
		steps = append(steps, StepPolicy)
	}
	if s.rescorer != nil {
		steps = append(steps, StepReachability)
	}
	if s.matcher != nil {
		steps = append(steps, StepVulnMatch)
	}
	if s.packages != nil {
		steps = append(steps, StepPkgMeta)
	}
	processing, err := s.store.CreateProcessing(ctx, stored.ID, steps)
	if err != nil {
		slog.WarnContext(ctx, "sbom processing record failed", "error", err, "sbom_id", stored.ID)
	} else {
		stored.Processing = &processing
	}

	// Run policy evaluation (e.g. license) as a best-effort side effect: the SBOM
	// is already persisted, so a policy error is logged, not surfaced.
	if s.evaluator != nil {
		if err := s.evaluator.Evaluate(ctx, req.ProjectID, stored.VersionID, doc.Components); err != nil {
			slog.WarnContext(ctx, "sbom policy evaluation failed", "error", err, "sbom_id", stored.ID)
			s.markStep(ctx, stored.ID, StepPolicy, StepFailed, "policy evaluation failed")
		} else {
			s.markStep(ctx, stored.ID, StepPolicy, StepCompleted, "")
		}
	}

	// A new SBOM rewrites the dependency graph: a package can go from direct to
	// transitive, or from runtime to dev-only, which changes what its existing
	// findings are worth. Re-score the project's backlog against the new
	// inventory. Best-effort, same as above.
	if s.rescorer != nil {
		if n, err := s.rescorer.ApplyToProject(ctx, req.ProjectID); err != nil {
			slog.WarnContext(ctx, "reachability rescore failed", "error", err, "sbom_id", stored.ID)
			s.markStep(ctx, stored.ID, StepReachability, StepFailed, "reachability rescoring failed")
		} else {
			if n > 0 {
				slog.InfoContext(ctx, "rescored findings against new SBOM",
					"count", n, "project_id", req.ProjectID, "sbom_id", stored.ID)
			}
			s.markStep(ctx, stored.ID, StepReachability, StepCompleted, "")
		}
	}
	// The matcher and registry refresh outlive the upload request but keep its
	// trace and log values.
	detached := ctx
	if s.matcher != nil {
		go func(projectID, sbomID string) {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(detached), matchTimeout)
			defer cancel()
			s.markStep(ctx, sbomID, StepVulnMatch, StepRunning, "")
			if _, err := s.matcher.MatchProject(ctx, projectID); err != nil {
				slog.WarnContext(ctx, "advisory match after upload failed", "error", err, "sbom_id", sbomID)
				s.markStep(ctx, sbomID, StepVulnMatch, StepFailed, "advisory match failed")
				return
			}
			s.markStep(ctx, sbomID, StepVulnMatch, StepCompleted, "")
		}(req.ProjectID, stored.ID)
	}
	if s.packages != nil {
		go func(projectID, sbomID string) {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(detached), packageMetaTimeout)
			defer cancel()
			s.markStep(ctx, sbomID, StepPkgMeta, StepRunning, "")
			if err := s.packages.RefreshProject(ctx, projectID); err != nil {
				slog.WarnContext(ctx, "package metadata refresh after upload failed", "error", err, "sbom_id", sbomID)
				s.markStep(ctx, sbomID, StepPkgMeta, StepFailed, "package metadata refresh failed")
				return
			}
			s.markStep(ctx, sbomID, StepPkgMeta, StepCompleted, "")
		}(req.ProjectID, stored.ID)
	}
	return stored, nil
}

// markStepTimeout bounds recording one processing step.
const markStepTimeout = 10 * time.Second

// markStep updates a processing step, logging (not surfacing) a storage
// failure: the step's real outcome already happened, and a status-tracking
// hiccup must not turn that into an upload failure.
//
// The write gets its own deadline, detached from the step's: a step that
// failed because its timeout expired must still be recorded as failed, or the
// upload would read "running" forever and CI waiting on it would hang.
func (s *Service) markStep(ctx context.Context, sbomID, step, status, errMsg string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), markStepTimeout)
	defer cancel()
	if _, err := s.store.MarkStep(ctx, sbomID, step, status, errMsg); err != nil {
		slog.WarnContext(ctx, "sbom processing step update failed", "error", err, "sbom_id", sbomID, "step", step)
	}
}
