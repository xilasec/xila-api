package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/scanner"
)

// ErrProjectNotFound is returned when ingesting against a missing project.
var ErrProjectNotFound = errors.New("project not found")

// ErrUnknownScanner is returned when no parser is registered for the scanner.
var ErrUnknownScanner = errors.New("unknown scanner")

// projectChecker verifies a project exists before ingestion.
type projectChecker interface {
	Exists(ctx context.Context, id string) (bool, error)
}

// findingWriter deduplicates/persists findings and can auto-close ones a
// scanner no longer reports.
type findingWriter interface {
	UpsertBatch(ctx context.Context, fs []finding.Finding, actor string) error
	CloseMissing(ctx context.Context, projectID, scanner, scanID string) ([]string, error)
	ListNewHighSeverity(ctx context.Context, scanID string) ([]finding.Finding, error)
	DeduplicateScan(ctx context.Context, projectID, scanID string, closedIDs []string) (int, error)
}

// eventNotifier dispatches events (notify.Service satisfies it). Optional.
type eventNotifier interface {
	Notify(ctx context.Context, e notify.Event)
}

// scanStore records and finalizes scans. *Repository satisfies it; tests use a fake.
type scanStore interface {
	Create(ctx context.Context, s Scan) (Scan, error)
	Get(ctx context.Context, id string) (Scan, error)
	Finalize(ctx context.Context, id string, status domain.ScanStatus, summary map[string]int, errMsg string) (Scan, error)
}

// IngestRequest carries the metadata accompanying a raw scan upload.
type IngestRequest struct {
	ProjectID string
	AssetID   string // optional: attribute the scan + its findings to an asset
	Scanner   string
	// Format selects the parser (e.g. "sarif") when the wire format differs from
	// the tool. Empty means the parser is keyed by Scanner (native formats).
	Format    string
	CommitSHA string
	// Branch or Release names the project version the scan belongs to (at most
	// one; neither = the project's default version).
	Branch  string
	Release string
	// EngagementID files the scan as a test of one of the project's
	// engagements (optional).
	EngagementID string
	// CloseMissing auto-remediates this scanner's findings that were not seen in
	// this scan (treating the scan as the scanner's complete current view).
	CloseMissing bool
}

// parserKey selects the parser: an explicit format wins, else the scanner name.
func (r IngestRequest) parserKey() string {
	if r.Format != "" {
		return r.Format
	}
	return r.Scanner
}

// Service orchestrates ingestion: parse -> fingerprint -> dedup -> finalize.
type Service struct {
	scans    scanStore
	findings findingWriter
	projects projectChecker
	parsers  *scanner.Registry
	notifier eventNotifier // optional
	appliers []Applier     // optional, run in order after ingest
	// followUps run after dedup, on the scan's final findings (see WithFollowUps).
	followUps []Applier
	jobs      jobStore // optional (required for async Enqueue)
}

// Applier is a post-ingest pass over the findings a scan just reported: auto-
// triage rules, VEX suppression, reachability. They all have the same shape, so
// the pipeline takes an ordered list instead of growing a constructor parameter
// per feature. Order matters — see finish.
type Applier interface {
	// Name identifies the pass in logs.
	Name() string
	// ApplyToScan mutates the scan's findings and reports how many changed.
	ApplyToScan(ctx context.Context, projectID, scanID string) (int, error)
}

// jobStore persists queued ingest jobs (scan.Repository satisfies it). Only used
// by the async Enqueue path.
type jobStore interface {
	EnqueueJob(ctx context.Context, scanID string, payload []byte, format string, closeMissing bool) error
}

// NewService wires the ingestion dependencies. notifier, appliers and jobs may be nil.
func NewService(scans scanStore, findings findingWriter, projects projectChecker, parsers *scanner.Registry, notifier eventNotifier, appliers []Applier, jobs jobStore) *Service {
	return &Service{scans: scans, findings: findings, projects: projects, parsers: parsers, notifier: notifier, appliers: appliers, jobs: jobs}
}

// WithFollowUps adds passes that run after dedup, over the scan's settled
// findings — for consumers of the backlog's final shape (which findings are
// duplicates, their final priority) rather than passes that change it.
// Like appliers they're best-effort: a failure is logged, never fatal.
func (s *Service) WithFollowUps(p ...Applier) *Service {
	s.followUps = append(s.followUps, p...)
	return s
}

// Ingest synchronously parses + processes a scan and returns the finalized scan.
func (s *Service) Ingest(ctx context.Context, req IngestRequest, raw io.Reader) (Scan, error) {
	sc, err := s.createScan(ctx, req)
	if err != nil {
		return Scan{}, err
	}
	return s.runPipeline(ctx, sc, raw, req.Format, req.CloseMissing)
}

// Enqueue persists the raw payload + a scan row and returns immediately; a worker
// processes it later via ProcessJob. Used when async ingestion is enabled so
// uploads don't hold a request (or a DB connection) for the whole pipeline.
func (s *Service) Enqueue(ctx context.Context, req IngestRequest, payload []byte) (Scan, error) {
	sc, err := s.createScan(ctx, req)
	if err != nil {
		return Scan{}, err
	}
	if err := s.jobs.EnqueueJob(ctx, sc.ID, payload, req.Format, req.CloseMissing); err != nil {
		_, _ = s.scans.Finalize(ctx, sc.ID, domain.ScanFailed, nil, err.Error())
		return Scan{}, err
	}
	return sc, nil
}

// ProcessJob runs a queued job through the pipeline. Called by worker goroutines.
func (s *Service) ProcessJob(ctx context.Context, job Job) (err error) {
	defer func(start time.Time) { observeJob(ctx, start, err) }(time.Now())

	sc, err := s.scans.Get(ctx, job.ScanID)
	if err != nil {
		return err
	}
	_, err = s.runPipeline(ctx, sc, bytes.NewReader(job.Payload), job.Format, job.CloseMissing)
	return err
}

// createScan validates the scanner + project and inserts the scan row.
func (s *Service) createScan(ctx context.Context, req IngestRequest) (Scan, error) {
	parser, ok := s.parsers.Get(req.parserKey())
	if !ok {
		return Scan{}, fmt.Errorf("%w: %q", ErrUnknownScanner, req.parserKey())
	}
	exists, err := s.projects.Exists(ctx, req.ProjectID)
	if err != nil {
		return Scan{}, err
	}
	if !exists {
		return Scan{}, ErrProjectNotFound
	}
	var assetID *string
	if req.AssetID != "" {
		assetID = &req.AssetID
	}
	name, kind := req.Branch, "branch"
	if req.Release != "" {
		name, kind = req.Release, "release"
	}
	var engagementID *string
	if req.EngagementID != "" {
		engagementID = &req.EngagementID
	}
	return s.scans.Create(ctx, Scan{
		ProjectID:    req.ProjectID,
		AssetID:      assetID,
		Scanner:      req.Scanner,
		Category:     parser.PrimaryCategory(),
		CommitSHA:    req.CommitSHA,
		Branch:       name,
		Kind:         kind,
		EngagementID: engagementID,
	})
}

// runPipeline parses the payload, upserts findings, auto-closes/triages/dedups,
// finalizes the scan and fires alerts. Shared by the sync and async paths.
func (s *Service) runPipeline(ctx context.Context, sc Scan, raw io.Reader, format string, closeMissing bool) (Scan, error) {
	parser, ok := s.parsers.Get(IngestRequest{Scanner: sc.Scanner, Format: format}.parserKey())
	if !ok {
		_, _ = s.scans.Finalize(ctx, sc.ID, domain.ScanFailed, nil, "unknown scanner")
		return Scan{}, fmt.Errorf("%w: %q", ErrUnknownScanner, sc.Scanner)
	}

	parsed, err := parser.Parse(raw)
	if err != nil {
		if _, ferr := s.scans.Finalize(ctx, sc.ID, domain.ScanFailed, nil, err.Error()); ferr != nil {
			return Scan{}, errors.Join(err, ferr)
		}
		return Scan{}, fmt.Errorf("parse scan: %w", err)
	}

	summary := map[string]int{}
	findings := make([]finding.Finding, 0, len(parsed))
	for _, pf := range parsed {
		findings = append(findings, toFinding(sc.ProjectID, sc.Scanner, sc.ID, sc.AssetID, pf))
		summary[string(pf.Severity)]++
	}
	if err := s.findings.UpsertBatch(ctx, findings, ""); err != nil {
		_, _ = s.scans.Finalize(ctx, sc.ID, domain.ScanFailed, summary, err.Error())
		return Scan{}, err
	}

	return s.finish(ctx, sc, summary, closeMissing)
}

// ApplyFindings records findings produced *without* a raw scanner report — e.g.
// the OSV matcher re-evaluating stored SBOM inventory as new advisories land — as
// a scan by scannerName on one project version. It runs the same pipeline as a
// normal ingest: upsert, auto-close what's no longer affected, auto-triage,
// dedup, finalize and alert.
func (s *Service) ApplyFindings(ctx context.Context, projectID, versionID, scannerName string, category domain.Category, findings []finding.Finding) (Scan, error) {
	// This run is the complete current view for this producer, so anything it no
	// longer reports (dependency upgraded/removed) is auto-remediated.
	return s.applyFindings(ctx, Target{ProjectID: projectID, VersionID: versionID}, scannerName, category, findings, true)
}

// AddFindings is ApplyFindings for a producer that knows its view is
// incomplete — e.g. the advisory matcher when one of several sources failed:
// the findings are upserted and run through the whole pipeline, but nothing
// the producer didn't report is auto-closed.
func (s *Service) AddFindings(ctx context.Context, projectID, versionID, scannerName string, category domain.Category, findings []finding.Finding) (Scan, error) {
	return s.applyFindings(ctx, Target{ProjectID: projectID, VersionID: versionID}, scannerName, category, findings, false)
}

// Target is where AddFindingsTo records findings: a project, optionally one
// of its versions (empty = the default) and one of its engagements.
type Target struct {
	ProjectID    string
	VersionID    string
	EngagementID string
	// Actor is the user the findings' history attributes them to ("" = system).
	Actor string
}

// AddFindingsTo is AddFindings into an explicit target — how manual findings
// are filed under an engagement. Nothing is auto-closed.
func (s *Service) AddFindingsTo(ctx context.Context, t Target, scannerName string, category domain.Category, findings []finding.Finding) (Scan, error) {
	return s.applyFindings(ctx, t, scannerName, category, findings, false)
}

func (s *Service) applyFindings(ctx context.Context, t Target, scannerName string, category domain.Category, findings []finding.Finding, closeMissing bool) (Scan, error) {
	exists, err := s.projects.Exists(ctx, t.ProjectID)
	if err != nil {
		return Scan{}, err
	}
	if !exists {
		return Scan{}, ErrProjectNotFound
	}
	sc := Scan{ProjectID: t.ProjectID, VersionID: t.VersionID, Scanner: scannerName, Category: category}
	if t.EngagementID != "" {
		sc.EngagementID = &t.EngagementID
	}
	sc, err = s.scans.Create(ctx, sc)
	if err != nil {
		return Scan{}, err
	}
	projectID := t.ProjectID
	summary := map[string]int{}
	for i := range findings {
		findings[i].ProjectID = projectID
		findings[i].Scanner = scannerName
		findings[i].VersionID = sc.VersionID
		findings[i].LastScanID = &sc.ID
		summary[string(findings[i].Severity)]++
	}
	if err := s.findings.UpsertBatch(ctx, findings, t.Actor); err != nil {
		_, _ = s.scans.Finalize(ctx, sc.ID, domain.ScanFailed, summary, err.Error())
		return Scan{}, err
	}
	return s.finish(ctx, sc, summary, closeMissing)
}

// finish runs the shared pipeline tail: auto-close, auto-triage, cross-tool dedup,
// finalize, and the new-critical alert.
func (s *Service) finish(ctx context.Context, sc Scan, summary map[string]int, closeMissing bool) (Scan, error) {
	// Closing a finding empties its slot in a correlation group, so dedup below
	// has to revisit those groups too.
	var closed []string
	if closeMissing {
		var err error
		closed, err = s.findings.CloseMissing(ctx, sc.ProjectID, sc.Scanner, sc.ID)
		if err != nil {
			_, _ = s.scans.Finalize(ctx, sc.ID, domain.ScanFailed, summary, err.Error())
			return Scan{}, err
		}
		if len(closed) > 0 {
			slog.InfoContext(ctx, "auto-closed findings no longer reported",
				"count", len(closed), "scanner", sc.Scanner, "project_id", sc.ProjectID, "scan_id", sc.ID)
		}
	}

	// Post-ingest passes, in order, over this scan's findings only — the rest of
	// the backlog was already processed by the ingest that reported it. They run
	// before the alert (so suppressed/downgraded findings don't page) and before
	// dedup (so a group's primary is elected on final priorities). A pass that
	// fails is logged, not fatal: the scan's findings are already stored, and the
	// next ingest re-runs the pass.
	for _, a := range s.appliers {
		if n, err := a.ApplyToScan(ctx, sc.ProjectID, sc.ID); err != nil {
			slog.WarnContext(ctx, "post-ingest pass failed",
				"pass", a.Name(), "error", err, "project_id", sc.ProjectID)
		} else if n > 0 {
			slog.InfoContext(ctx, "post-ingest pass changed findings",
				"pass", a.Name(), "count", n, "project_id", sc.ProjectID)
		}
	}

	// Collapse the same CVE+package reported by multiple scanners, in the groups
	// this scan could have disturbed. Triage runs first because it can change a
	// severity, and severity decides which report of a CVE becomes the primary.
	if n, err := s.findings.DeduplicateScan(ctx, sc.ProjectID, sc.ID, closed); err != nil {
		slog.WarnContext(ctx, "dedup failed", "error", err, "project_id", sc.ProjectID)
	} else if n > 0 {
		slog.InfoContext(ctx, "regrouped cross-tool duplicates", "count", n, "project_id", sc.ProjectID)
	}
	for _, p := range s.followUps {
		if _, err := p.ApplyToScan(ctx, sc.ProjectID, sc.ID); err != nil {
			slog.WarnContext(ctx, "post-dedup pass failed", "pass", p.Name(), "error", err, "project_id", sc.ProjectID)
		}
	}

	final, err := s.scans.Finalize(ctx, sc.ID, domain.ScanCompleted, summary, "")
	if err != nil {
		return Scan{}, err
	}
	s.notifyNewCritical(ctx, sc.ProjectID, sc.Scanner, sc.ID)
	return final, nil
}

// notifyNewCritical alerts (best-effort, async) when a scan introduces new
// critical/high findings — the "scary stuff" worth hearing about immediately.
func (s *Service) notifyNewCritical(ctx context.Context, projectID, scanner, scanID string) {
	if s.notifier == nil {
		return
	}
	newHigh, err := s.findings.ListNewHighSeverity(ctx, scanID)
	if err != nil || len(newHigh) == 0 {
		return
	}
	var critical int
	titles := make([]string, 0, 3)
	for _, f := range newHigh {
		if f.Severity == domain.SeverityCritical {
			critical++
		}
		if len(titles) < 3 {
			titles = append(titles, string(f.Severity)+": "+f.Title)
		}
	}
	sev := "high"
	if critical > 0 {
		sev = "critical"
	}
	go s.notifier.Notify(context.Background(), notify.Event{
		Type:      notify.EventCriticalFinding,
		Title:     fmt.Sprintf("%d new critical/high finding(s) from %s", len(newHigh), scanner),
		Text:      strings.Join(titles, "\n"),
		Severity:  sev,
		ProjectID: projectID,
		Fields: map[string]string{
			"critical": strconv.Itoa(critical),
			"total":    strconv.Itoa(len(newHigh)),
			"scanner":  scanner,
		},
	})
}

// toFinding converts a parsed finding into a persistable finding, assigning the
// dedup fingerprint.
func toFinding(projectID, scannerName, scanID string, assetID *string, pf scanner.ParsedFinding) finding.Finding {
	metadata := pf.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	return finding.Finding{
		ProjectID:      projectID,
		AssetID:        assetID,
		Fingerprint:    fingerprint(scannerName, pf),
		Scanner:        scannerName,
		Category:       pf.Category,
		RuleID:         pf.RuleID,
		Title:          pf.Title,
		Description:    pf.Description,
		Severity:       pf.Severity,
		CWE:            pf.CWE,
		CVE:            pf.CVE,
		FilePath:       pf.FilePath,
		Line:           pf.Line,
		PackageName:    pf.Package,
		PackageVersion: pf.PackageVersion,
		FixedVersion:   pf.FixedVersion,
		Purl:           pf.Purl,
		CVSS:           pf.CVSS,
		URL:            pf.URL,
		Metadata:       metadata,
		LastScanID:     &scanID,
	}
}

// fingerprint is the stable identity of a finding within a project. It is
// intentionally independent of the installed package version and line content
// so that a finding persists across scans until it is actually fixed (which
// changes location/rule and thus stops it reappearing).
func fingerprint(scannerName string, pf scanner.ParsedFinding) string {
	parts := []string{
		scannerName,
		string(pf.Category),
		pf.RuleID,
		pf.FilePath,
		pf.Package,
	}
	if pf.Line != nil {
		parts = append(parts, strconv.Itoa(*pf.Line))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])
}
