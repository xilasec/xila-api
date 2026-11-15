package scan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sort"
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
	// CarryForward moves the target's live findings from a repeated scan onto
	// the new one that matched its content hash (see Service.runPipeline's
	// skip-unchanged path), refreshing last_seen_at without touching
	// first_scan_id.
	CarryForward(ctx context.Context, prevScanID, newScanID string, want int) (bool, error)
	// ChangedSince reports whether the earlier scan's findings (or its asset's
	// exposure) changed after it finished, which rules out skipping.
	ChangedSince(ctx context.Context, prevScanID string, since time.Time, assetID *string) (bool, error)
}

// eventNotifier dispatches events (notify.Service satisfies it). Optional.
type eventNotifier interface {
	Notify(ctx context.Context, e notify.Event)
}

// scanStore records and finalizes scans. *Repository satisfies it; tests use a fake.
type scanStore interface {
	Create(ctx context.Context, s Scan) (Scan, error)
	Get(ctx context.Context, id string) (Scan, error)
	Finalize(ctx context.Context, id string, status domain.ScanStatus, summary map[string]int, errMsg, contentHash string) (Scan, error)
	// LatestCompletedTarget finds the previous completed scan of the same
	// target (project, scanner, version, asset) — see Service.runPipeline.
	LatestCompletedTarget(ctx context.Context, projectID, scannerName, versionID string, assetID *string) (Scan, bool, error)
	// MarkUnchanged finalizes a scan as a skipped repeat of an earlier one.
	MarkUnchanged(ctx context.Context, id, repeatOf, contentHash string, summary map[string]int) (Scan, error)
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
	// Force bypasses skip-unchanged: always run the full pipeline even if this
	// report's content hash matches the target's previous scan.
	Force bool
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
	// skipUnchanged short-circuits the pipeline when a report's content hash
	// matches its target's previous completed scan (INGEST_SKIP_UNCHANGED; see
	// WithSkipUnchanged and runPipeline). Off by default: callers that want it
	// opt in explicitly.
	skipUnchanged bool
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
	EnqueueJob(ctx context.Context, scanID string, payload []byte, format string, closeMissing, force bool) error
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

// WithSkipUnchanged enables the skip-unchanged short-circuit (see
// runPipeline): a report whose content hash matches its target's previous
// completed scan records the repeat cheaply instead of re-running the whole
// pipeline. Individual uploads can still force a full run (IngestRequest.Force).
func (s *Service) WithSkipUnchanged(enabled bool) *Service {
	s.skipUnchanged = enabled
	return s
}

// Ingest synchronously parses + processes a scan and returns the finalized scan.
func (s *Service) Ingest(ctx context.Context, req IngestRequest, raw io.Reader) (Scan, error) {
	sc, err := s.createScan(ctx, req)
	if err != nil {
		return Scan{}, err
	}
	return s.runPipeline(ctx, sc, raw, req.Format, req.CloseMissing, s.skipUnchanged && !req.Force)
}

// Enqueue persists the raw payload + a scan row and returns immediately; a worker
// processes it later via ProcessJob. Used when async ingestion is enabled so
// uploads don't hold a request (or a DB connection) for the whole pipeline.
func (s *Service) Enqueue(ctx context.Context, req IngestRequest, payload []byte) (Scan, error) {
	sc, err := s.createScan(ctx, req)
	if err != nil {
		return Scan{}, err
	}
	if err := s.jobs.EnqueueJob(ctx, sc.ID, payload, req.Format, req.CloseMissing, req.Force); err != nil {
		_, _ = s.scans.Finalize(ctx, sc.ID, domain.ScanFailed, nil, err.Error(), "")
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
	_, err = s.runPipeline(ctx, sc, bytes.NewReader(job.Payload), job.Format, job.CloseMissing, s.skipUnchanged && !job.Force)
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
//
// trySkip is INGEST_SKIP_UNCHANGED (Service.skipUnchanged) with the upload's
// own force=false — when true, a report whose content hash matches its
// target's previous completed scan short-circuits: no upsert, no auto-close,
// no appliers, no dedup, no follow-ups, no alert. The scan is recorded
// completed with the previous summary and unchanged_of set, and the target's
// live findings are carried onto it (see findingWriter.CarryForward) so they
// look seen by this scan without counting as newly introduced by it.
func (s *Service) runPipeline(ctx context.Context, sc Scan, raw io.Reader, format string, closeMissing, trySkip bool) (Scan, error) {
	parser, ok := s.parsers.Get(IngestRequest{Scanner: sc.Scanner, Format: format}.parserKey())
	if !ok {
		_, _ = s.scans.Finalize(ctx, sc.ID, domain.ScanFailed, nil, "unknown scanner", "")
		return Scan{}, fmt.Errorf("%w: %q", ErrUnknownScanner, sc.Scanner)
	}

	parsed, err := parser.Parse(raw)
	if err != nil {
		if _, ferr := s.scans.Finalize(ctx, sc.ID, domain.ScanFailed, nil, err.Error(), ""); ferr != nil {
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

	// Hashing the parsed findings rather than the raw bytes means a report that
	// differs only in a scanner-embedded timestamp (e.g. Trivy's top-level
	// CreatedAt, which we never parse into a ParsedFinding) still counts as
	// unchanged. A hashing failure (should not happen — it's pure encoding) just
	// disables the optimization for this scan; it still runs and finalizes
	// normally, just without a content_hash for future comparisons.
	hash, hashErr := contentHash(sc.Scanner, parsed, closeMissing)
	if hashErr != nil {
		slog.WarnContext(ctx, "content hash failed; processing normally", "error", hashErr, "scan_id", sc.ID)
		hash = ""
	}

	if trySkip && hashErr == nil {
		prev, ok, err := s.scans.LatestCompletedTarget(ctx, sc.ProjectID, sc.Scanner, sc.VersionID, sc.AssetID)
		if err != nil {
			slog.WarnContext(ctx, "latest completed scan lookup failed; processing normally", "error", err, "scan_id", sc.ID)
		} else if ok && prev.ContentHash != nil && *prev.ContentHash == hash && prev.FinishedAt != nil {
			if final, skipped, err := s.repeat(ctx, sc, prev, hash, summary, findings); err != nil || skipped {
				return final, err
			}
		}
	}

	if err := s.findings.UpsertBatch(ctx, findings, ""); err != nil {
		_, _ = s.scans.Finalize(ctx, sc.ID, domain.ScanFailed, summary, err.Error(), "")
		return Scan{}, err
	}

	return s.finish(ctx, sc, summary, closeMissing, hash)
}

// repeat records sc as an unchanged repeat of prev when that is safe: nobody
// changed prev's findings or its asset's exposure since it finished (a reset
// field, a manually closed finding or a cleared exposure all need the full
// pipeline to restore the scanner's view), and every one of this report's
// findings is still there to carry forward. skipped is false when the caller
// should run the full pipeline.
func (s *Service) repeat(ctx context.Context, sc, prev Scan, hash string, summary map[string]int, findings []finding.Finding) (Scan, bool, error) {
	changed, err := s.findings.ChangedSince(ctx, prev.ID, *prev.FinishedAt, sc.AssetID)
	if err != nil {
		slog.WarnContext(ctx, "change check failed; processing normally", "error", err, "scan_id", sc.ID)
		return Scan{}, false, nil
	}
	if changed {
		return Scan{}, false, nil
	}
	distinct := map[string]struct{}{}
	for _, f := range findings {
		distinct[f.Fingerprint] = struct{}{}
	}
	moved, err := s.findings.CarryForward(ctx, prev.ID, sc.ID, len(distinct))
	if err != nil {
		_, _ = s.scans.Finalize(ctx, sc.ID, domain.ScanFailed, summary, err.Error(), "")
		return Scan{}, true, err
	}
	if !moved {
		slog.InfoContext(ctx, "unchanged report but its findings moved; processing normally", "scan_id", sc.ID, "repeats", prev.ID)
		return Scan{}, false, nil
	}
	final, err := s.scans.MarkUnchanged(ctx, sc.ID, prev.ID, hash, prev.Summary)
	if err != nil {
		return Scan{}, true, err
	}
	slog.InfoContext(ctx, "scan unchanged; pipeline skipped",
		"scan_id", sc.ID, "repeats", prev.ID, "scanner", sc.Scanner, "project_id", sc.ProjectID)
	return final, true, nil
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
		_, _ = s.scans.Finalize(ctx, sc.ID, domain.ScanFailed, summary, err.Error(), "")
		return Scan{}, err
	}
	return s.finish(ctx, sc, summary, closeMissing, "")
}

// finish runs the shared pipeline tail: auto-close, auto-triage, cross-tool dedup,
// finalize, and the new-critical alert. contentHash ("" when the scan has no raw
// report, e.g. ApplyFindings) is stored on the completed scan for the *next*
// upload of the same target to compare against.
func (s *Service) finish(ctx context.Context, sc Scan, summary map[string]int, closeMissing bool, contentHash string) (Scan, error) {
	// Closing a finding empties its slot in a correlation group, so dedup below
	// has to revisit those groups too.
	var closed []string
	if closeMissing {
		var err error
		closed, err = s.findings.CloseMissing(ctx, sc.ProjectID, sc.Scanner, sc.ID)
		if err != nil {
			_, _ = s.scans.Finalize(ctx, sc.ID, domain.ScanFailed, summary, err.Error(), "")
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

	final, err := s.scans.Finalize(ctx, sc.ID, domain.ScanCompleted, summary, "", contentHash)
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

// contentHash is a deterministic digest of a parsed report: every field the
// upsert would write for each finding, keyed by its dedup fingerprint and
// sorted, plus closeMissing (which changes what the scan does to findings it
// did NOT report). Hashing the parsed findings rather than the raw bytes means
// a report that differs only in a scanner-embedded value we never read (e.g.
// Trivy's top-level CreatedAt) still hashes the same, while a parser upgrade
// that changes what we extract counts as a change.
func contentHash(scannerName string, parsed []scanner.ParsedFinding, closeMissing bool) (string, error) {
	type canonicalFinding struct {
		Fingerprint    string          `json:"fp"`
		Category       domain.Category `json:"category"`
		RuleID         string          `json:"rule_id"`
		Title          string          `json:"title"`
		Description    string          `json:"description"`
		Severity       domain.Severity `json:"severity"`
		CWE            *int            `json:"cwe"`
		CVE            []string        `json:"cve"`
		FilePath       string          `json:"file_path"`
		Line           *int            `json:"line"`
		Package        string          `json:"package"`
		PackageVersion string          `json:"package_version"`
		FixedVersion   string          `json:"fixed_version"`
		Purl           string          `json:"purl"`
		CVSS           *float64        `json:"cvss"`
		URL            string          `json:"url"`
		Metadata       map[string]any  `json:"metadata"`
	}
	canon := make([]canonicalFinding, len(parsed))
	for i, pf := range parsed {
		cve := append([]string(nil), pf.CVE...)
		sort.Strings(cve)
		canon[i] = canonicalFinding{
			Fingerprint:    fingerprint(scannerName, pf),
			Category:       pf.Category,
			RuleID:         pf.RuleID,
			Title:          pf.Title,
			Description:    pf.Description,
			Severity:       pf.Severity,
			CWE:            pf.CWE,
			CVE:            cve,
			FilePath:       pf.FilePath,
			Line:           pf.Line,
			Package:        pf.Package,
			PackageVersion: pf.PackageVersion,
			FixedVersion:   pf.FixedVersion,
			Purl:           pf.Purl,
			CVSS:           pf.CVSS,
			URL:            pf.URL,
			Metadata:       pf.Metadata,
		}
	}
	sort.SliceStable(canon, func(i, j int) bool { return canon[i].Fingerprint < canon[j].Fingerprint })

	payload := struct {
		CloseMissing bool               `json:"close_missing"`
		Findings     []canonicalFinding `json:"findings"`
	}{closeMissing, canon}
	b, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal content hash payload: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
