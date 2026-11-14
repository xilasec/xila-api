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
	closes       []string // ids CloseMissing reports as auto-closed
	dedupClosed  []string // ids handed to DeduplicateScan
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

func (f *fakeFindings) DeduplicateScan(_ context.Context, _, _ string, closedIDs []string) (int, error) {
	f.dedupClosed = closedIDs
	return 0, nil
}

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
}

func (f *fakeScans) Create(_ context.Context, s Scan) (Scan, error) {
	s.ID = "scan-1"
	f.created = s
	return s, nil
}
func (f *fakeScans) Get(_ context.Context, id string) (Scan, error) {
	return Scan{ID: id, ProjectID: f.created.ProjectID, Scanner: f.created.Scanner}, nil
}

func (f *fakeScans) Finalize(_ context.Context, id string, status domain.ScanStatus, summary map[string]int, errMsg string) (Scan, error) {
	f.finalStatus, f.finalSummary, f.finalErr = status, summary, errMsg
	return Scan{ID: id, Status: status, Summary: summary, Error: errMsg}, nil
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
