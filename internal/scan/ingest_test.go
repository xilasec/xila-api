package scan

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/scanner"
)

// --- fakes (no DB, no framework) ---

type fakeProjects struct {
	exists bool
	err    error
}

func (f fakeProjects) Exists(context.Context, string) (bool, error) { return f.exists, f.err }

type fakeFindings struct {
	upserts      []finding.Finding
	newHigh      []finding.Finding
	err          error
	closeCalls   int
	closedScanID string
	closes       []string    // ids CloseMissing reports as auto-closed
	dedupCalls   int         // number of DeduplicateScan calls
	dedupClosed  []string    // ids handed to DeduplicateScan
	carryForward [][2]string // [prevScanID, newScanID] pairs passed to CarryForward
}

func (f *fakeFindings) UpsertBatch(_ context.Context, fs []finding.Finding, _ string) error {
	if f.err != nil {
		return f.err
	}
	f.upserts = append(f.upserts, fs...)
	return nil
}

func (f *fakeFindings) ListNewHighSeverity(context.Context, string) ([]finding.Finding, error) {
	return f.newHigh, nil
}

func (f *fakeFindings) ListNew(context.Context, string) ([]finding.Finding, error) {
	return f.newHigh, nil
}

func (f *fakeFindings) DeduplicateScan(_ context.Context, _, _ string, closedIDs []string) (int, error) {
	f.dedupCalls++
	f.dedupClosed = closedIDs
	return 0, nil
}

func (f *fakeFindings) CarryForward(_ context.Context, prevScanID, newScanID string, _ int) (bool, error) {
	f.carryForward = append(f.carryForward, [2]string{prevScanID, newScanID})
	return true, nil
}

func (f *fakeFindings) ChangedSince(context.Context, string, time.Time, *string) (bool, error) {
	return false, nil
}

// prevFinished is a completed previous scan's finished_at for the skip fixtures.
var prevFinished = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

type fakeNotifier struct{ events chan notify.Event }

func (f *fakeNotifier) Notify(_ context.Context, e notify.Event) { f.events <- e }

func (f *fakeFindings) CloseMissing(_ context.Context, _, _, scanID string) ([]string, error) {
	f.closeCalls++
	f.closedScanID = scanID
	return f.closes, nil
}

type fakeScans struct {
	created      Scan
	finalStatus  domain.ScanStatus
	finalSummary map[string]int
	finalErr     string
	finalHash    string
	// latest/latestOK are what LatestCompletedTarget returns, set by the test.
	latest      Scan
	latestOK    bool
	unchangedOf string
}

func (f *fakeScans) Create(_ context.Context, s Scan) (Scan, error) {
	s.ID = "scan-1"
	f.created = s
	return s, nil
}
func (f *fakeScans) Get(_ context.Context, id string) (Scan, error) {
	return Scan{ID: id, ProjectID: f.created.ProjectID, Scanner: f.created.Scanner}, nil
}

func (f *fakeScans) Finalize(_ context.Context, id string, status domain.ScanStatus, summary map[string]int, errMsg, contentHash string) (Scan, error) {
	f.finalStatus, f.finalSummary, f.finalErr, f.finalHash = status, summary, errMsg, contentHash
	return Scan{ID: id, Status: status, Summary: summary, Error: errMsg}, nil
}

func (f *fakeScans) LatestCompletedTarget(context.Context, string, string, string, *string) (Scan, bool, error) {
	return f.latest, f.latestOK, nil
}

func (f *fakeScans) MarkUnchanged(_ context.Context, id, repeatOf, contentHash string, summary map[string]int) (Scan, error) {
	f.unchangedOf = repeatOf
	f.finalHash = contentHash
	return Scan{ID: id, Status: domain.ScanCompleted, Summary: summary, UnchangedOf: &repeatOf, ContentHash: &contentHash}, nil
}

const trivyDoc = `{"Results":[
  {"Target":"go.mod","Class":"lang-pkgs","Type":"gomod","Vulnerabilities":[
    {"VulnerabilityID":"CVE-1","PkgName":"pkgA","InstalledVersion":"1.0","Severity":"HIGH"}]},
  {"Target":".env","Class":"secret","Secrets":[
    {"RuleID":"aws-key","Severity":"CRITICAL","StartLine":2}]}
]}`

// newTestRegistry is the parser set the handler/ingest tests share.
func newTestRegistry() *scanner.Registry { return scanner.NewRegistry(scanner.NewTrivy()) }

func newService(scans scanStore, findings findingWriter, projects projectChecker) *Service {
	return NewService(scans, findings, projects, scanner.NewRegistry(scanner.NewTrivy()), nil, nil, nil)
}

func TestIngestSuccess(t *testing.T) {
	scans := &fakeScans{}
	findings := &fakeFindings{}
	svc := newService(scans, findings, fakeProjects{exists: true})

	sc, err := svc.Ingest(context.Background(),
		IngestRequest{ProjectID: "proj-1", Scanner: "trivy"},
		strings.NewReader(trivyDoc))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	if sc.Status != domain.ScanCompleted {
		t.Errorf("status = %q, want completed", sc.Status)
	}
	if scans.created.Category != domain.CategorySCA {
		t.Errorf("scan category = %q, want sca", scans.created.Category)
	}
	if len(findings.upserts) != 2 {
		t.Fatalf("upserted %d findings, want 2", len(findings.upserts))
	}
	if got := scans.finalSummary; got["high"] != 1 || got["critical"] != 1 {
		t.Errorf("summary = %v, want high:1 critical:1", got)
	}
	for _, f := range findings.upserts {
		if f.ProjectID != "proj-1" || f.Fingerprint == "" {
			t.Errorf("finding not stamped correctly: %+v", f)
		}
		if f.LastScanID == nil || *f.LastScanID != "scan-1" {
			t.Errorf("last_scan_id = %v, want scan-1", f.LastScanID)
		}
	}
}

func TestIngestClosesMissingWhenEnabled(t *testing.T) {
	findings := &fakeFindings{}
	svc := newService(&fakeScans{}, findings, fakeProjects{exists: true})

	if _, err := svc.Ingest(context.Background(),
		IngestRequest{ProjectID: "proj-1", Scanner: "trivy", CloseMissing: true},
		strings.NewReader(trivyDoc)); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if findings.closeCalls != 1 || findings.closedScanID != "scan-1" {
		t.Errorf("CloseMissing calls=%d scanID=%q, want 1 / scan-1", findings.closeCalls, findings.closedScanID)
	}
}

func TestIngestSkipsCloseWhenDisabled(t *testing.T) {
	findings := &fakeFindings{}
	svc := newService(&fakeScans{}, findings, fakeProjects{exists: true})

	if _, err := svc.Ingest(context.Background(),
		IngestRequest{ProjectID: "proj-1", Scanner: "trivy", CloseMissing: false},
		strings.NewReader(trivyDoc)); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if findings.closeCalls != 0 {
		t.Errorf("CloseMissing calls=%d, want 0 when disabled", findings.closeCalls)
	}
}

func TestIngestNotifiesNewCritical(t *testing.T) {
	fn := &fakeNotifier{events: make(chan notify.Event, 1)}
	ff := &fakeFindings{newHigh: []finding.Finding{
		{Severity: domain.SeverityCritical, Title: "RCE in pkgA"},
	}}
	svc := NewService(&fakeScans{}, ff, fakeProjects{exists: true},
		scanner.NewRegistry(scanner.NewTrivy()), fn, nil, nil)

	if _, err := svc.Ingest(context.Background(),
		IngestRequest{ProjectID: "proj-1", Scanner: "trivy"}, strings.NewReader(trivyDoc)); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	select {
	case e := <-fn.events:
		if e.Type != notify.EventCriticalFinding || e.ProjectID != "proj-1" || e.Severity != "critical" {
			t.Errorf("event = %+v, want critical-finding/proj-1/critical", e)
		}
		if e.Fields["critical"] != "1" {
			t.Errorf("critical count = %q, want 1", e.Fields["critical"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("expected a new-critical notification")
	}
}

func TestIngestNoNotifyWhenNoNewCritical(t *testing.T) {
	fn := &fakeNotifier{events: make(chan notify.Event, 1)}
	svc := NewService(&fakeScans{}, &fakeFindings{}, fakeProjects{exists: true},
		scanner.NewRegistry(scanner.NewTrivy()), fn, nil, nil)
	if _, err := svc.Ingest(context.Background(),
		IngestRequest{ProjectID: "proj-1", Scanner: "trivy"}, strings.NewReader(trivyDoc)); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	select {
	case e := <-fn.events:
		t.Errorf("unexpected notification: %+v", e)
	case <-time.After(200 * time.Millisecond):
		// good — nothing sent
	}
}

func TestIngestUnknownScanner(t *testing.T) {
	svc := newService(&fakeScans{}, &fakeFindings{}, fakeProjects{exists: true})
	_, err := svc.Ingest(context.Background(),
		IngestRequest{ProjectID: "proj-1", Scanner: "nessus"}, strings.NewReader("{}"))
	if !errors.Is(err, ErrUnknownScanner) {
		t.Fatalf("err = %v, want ErrUnknownScanner", err)
	}
}

func TestIngestProjectNotFound(t *testing.T) {
	svc := newService(&fakeScans{}, &fakeFindings{}, fakeProjects{exists: false})
	_, err := svc.Ingest(context.Background(),
		IngestRequest{ProjectID: "missing", Scanner: "trivy"}, strings.NewReader(trivyDoc))
	if !errors.Is(err, ErrProjectNotFound) {
		t.Fatalf("err = %v, want ErrProjectNotFound", err)
	}
}

func TestIngestParseFailureMarksScanFailed(t *testing.T) {
	scans := &fakeScans{}
	svc := newService(scans, &fakeFindings{}, fakeProjects{exists: true})

	_, err := svc.Ingest(context.Background(),
		IngestRequest{ProjectID: "proj-1", Scanner: "trivy"},
		strings.NewReader("this is not json"))
	if err == nil {
		t.Fatal("expected parse error")
	}
	if scans.finalStatus != domain.ScanFailed {
		t.Errorf("scan status = %q, want failed", scans.finalStatus)
	}
	if scans.finalErr == "" {
		t.Error("expected error recorded on scan")
	}
}

func TestFingerprintStableAndDistinct(t *testing.T) {
	base := scanner.ParsedFinding{
		Category: domain.CategorySCA, RuleID: "CVE-1", FilePath: "go.mod", Package: "pkgA",
	}
	// Same identity fields (even with a different installed version) -> same fp.
	a := fingerprint("trivy", base)
	bumped := base
	bumped.PackageVersion = "9.9.9"
	if a != fingerprint("trivy", bumped) {
		t.Error("fingerprint should ignore installed version")
	}
	// Different package -> different fp.
	other := base
	other.Package = "pkgB"
	if a == fingerprint("trivy", other) {
		t.Error("different package should yield a different fingerprint")
	}
}

// --- skip-unchanged (M11 11.4) ---

// trivyParsed parses trivyDoc the same way runPipeline does, for computing the
// content hash a test expects to match.
func trivyParsed(t *testing.T) []scanner.ParsedFinding {
	t.Helper()
	parsed, err := scanner.NewTrivy().Parse(strings.NewReader(trivyDoc))
	if err != nil {
		t.Fatalf("parse trivyDoc: %v", err)
	}
	return parsed
}

func TestIngestSkipsUnchangedWhenHashMatches(t *testing.T) {
	hash, err := contentHash("trivy", trivyParsed(t), true)
	if err != nil {
		t.Fatalf("contentHash: %v", err)
	}
	scans := &fakeScans{latestOK: true, latest: Scan{ID: "prev-1", ContentHash: &hash, Summary: map[string]int{"high": 1, "critical": 1}, FinishedAt: &prevFinished}}
	findings := &fakeFindings{}
	svc := newService(scans, findings, fakeProjects{exists: true}).WithSkipUnchanged(true)

	sc, err := svc.Ingest(context.Background(),
		IngestRequest{ProjectID: "proj-1", Scanner: "trivy", CloseMissing: true},
		strings.NewReader(trivyDoc))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if sc.Status != domain.ScanCompleted {
		t.Errorf("status = %q, want completed", sc.Status)
	}
	if sc.UnchangedOf == nil || *sc.UnchangedOf != "prev-1" {
		t.Errorf("unchanged_of = %v, want prev-1", sc.UnchangedOf)
	}
	if sc.ContentHash == nil || *sc.ContentHash != hash {
		t.Errorf("content_hash = %v, want %s", sc.ContentHash, hash)
	}
	if len(findings.upserts) != 0 {
		t.Errorf("upserted %d findings, want 0 (pipeline skipped)", len(findings.upserts))
	}
	if findings.closeCalls != 0 {
		t.Errorf("CloseMissing calls = %d, want 0 (pipeline skipped)", findings.closeCalls)
	}
	if findings.dedupCalls != 0 {
		t.Errorf("DeduplicateScan calls = %d, want 0 (pipeline skipped)", findings.dedupCalls)
	}
	if len(findings.carryForward) != 1 || findings.carryForward[0] != [2]string{"prev-1", "scan-1"} {
		t.Errorf("CarryForward calls = %v, want one [prev-1 scan-1]", findings.carryForward)
	}
}

func TestIngestForceBypassesSkipUnchanged(t *testing.T) {
	hash, err := contentHash("trivy", trivyParsed(t), true)
	if err != nil {
		t.Fatalf("contentHash: %v", err)
	}
	scans := &fakeScans{latestOK: true, latest: Scan{ID: "prev-1", ContentHash: &hash}}
	findings := &fakeFindings{}
	svc := newService(scans, findings, fakeProjects{exists: true}).WithSkipUnchanged(true)

	sc, err := svc.Ingest(context.Background(),
		IngestRequest{ProjectID: "proj-1", Scanner: "trivy", CloseMissing: true, Force: true},
		strings.NewReader(trivyDoc))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if sc.Status != domain.ScanCompleted {
		t.Errorf("status = %q, want completed", sc.Status)
	}
	if len(findings.upserts) != 2 {
		t.Errorf("upserted %d findings, want 2 (force reprocesses)", len(findings.upserts))
	}
	if findings.closeCalls != 1 {
		t.Errorf("CloseMissing calls = %d, want 1 (force reprocesses)", findings.closeCalls)
	}
	if len(findings.carryForward) != 0 {
		t.Errorf("CarryForward calls = %v, want none when forced", findings.carryForward)
	}
}

func TestIngestProcessesWhenHashDiffers(t *testing.T) {
	otherHash := strings.Repeat("a", 64) // never matches a real content hash
	scans := &fakeScans{latestOK: true, latest: Scan{ID: "prev-1", ContentHash: &otherHash}}
	findings := &fakeFindings{}
	svc := newService(scans, findings, fakeProjects{exists: true}).WithSkipUnchanged(true)

	sc, err := svc.Ingest(context.Background(),
		IngestRequest{ProjectID: "proj-1", Scanner: "trivy", CloseMissing: true},
		strings.NewReader(trivyDoc))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if sc.UnchangedOf != nil {
		t.Errorf("unchanged_of = %v, want nil (content differs)", sc.UnchangedOf)
	}
	if len(findings.upserts) != 2 {
		t.Errorf("upserted %d findings, want 2", len(findings.upserts))
	}
	if findings.dedupCalls != 1 {
		t.Errorf("DeduplicateScan calls = %d, want 1", findings.dedupCalls)
	}
}

func TestIngestSkipUnchangedDisabledByDefault(t *testing.T) {
	hash, err := contentHash("trivy", trivyParsed(t), true)
	if err != nil {
		t.Fatalf("contentHash: %v", err)
	}
	scans := &fakeScans{latestOK: true, latest: Scan{ID: "prev-1", ContentHash: &hash}}
	findings := &fakeFindings{}
	// No WithSkipUnchanged(true): the feature is off unless a caller opts in.
	svc := newService(scans, findings, fakeProjects{exists: true})

	if _, err := svc.Ingest(context.Background(),
		IngestRequest{ProjectID: "proj-1", Scanner: "trivy", CloseMissing: true},
		strings.NewReader(trivyDoc)); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(findings.upserts) != 2 {
		t.Errorf("upserted %d findings, want 2 (skip-unchanged not enabled)", len(findings.upserts))
	}
	if len(findings.carryForward) != 0 {
		t.Errorf("CarryForward calls = %v, want none when disabled", findings.carryForward)
	}
}

func TestContentHashIgnoresExtraneousField(t *testing.T) {
	a := []scanner.ParsedFinding{{Category: domain.CategorySCA, RuleID: "CVE-1", FilePath: "go.mod", Package: "pkgA"}}
	b := []scanner.ParsedFinding{{Category: domain.CategorySCA, RuleID: "CVE-1", FilePath: "go.mod", Package: "pkgA"}}
	h1, err := contentHash("trivy", a, true)
	if err != nil {
		t.Fatalf("contentHash: %v", err)
	}
	h2, err := contentHash("trivy", b, true)
	if err != nil {
		t.Fatalf("contentHash: %v", err)
	}
	if h1 != h2 {
		t.Error("identical parsed findings should hash the same")
	}
	// A changed field (e.g. a parser upgrade extracting a description it
	// didn't before) must change the hash.
	c := b
	c[0].Description = "now we extract this"
	if h3, _ := contentHash("trivy", c, true); h3 == h1 {
		t.Error("a changed field should change the content hash")
	}
	// close_missing is part of the hash: the same report under a different
	// close_missing setting is a different "scan" for skip-unchanged purposes.
	if h4, _ := contentHash("trivy", a, false); h4 == h1 {
		t.Error("close_missing should affect the content hash")
	}
}
