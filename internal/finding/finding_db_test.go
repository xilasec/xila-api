package finding_test

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// seedProject creates a team + project directly and returns the project id.
func seedProject(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	var teamID string
	if err := pool.QueryRow(ctx,
		`WITH o AS (INSERT INTO organizations (slug, name) VALUES ('o-fd','o') RETURNING id) INSERT INTO teams (org_id, slug, name) SELECT id, 't', 'Team' FROM o RETURNING id`).Scan(&teamID); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	var projectID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (team_id, slug, name) VALUES ($1, 'p', 'Project') RETURNING id`,
		teamID).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return projectID
}

// seedScan inserts a scan row and returns its id (findings.last_scan_id FKs it).
func seedScan(t *testing.T, pool *pgxpool.Pool, projectID string) string {
	t.Helper()
	var scanID string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO scans (project_id, scanner, category, status) VALUES ($1, 'trivy', 'sca', 'completed') RETURNING id`,
		projectID).Scan(&scanID); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	return scanID
}

func sampleFinding(projectID string) finding.Finding {
	return finding.Finding{
		ProjectID:   projectID,
		Fingerprint: "fp-1",
		Scanner:     "trivy",
		Category:    domain.CategorySCA,
		RuleID:      "CVE-1",
		Title:       "Vuln in pkgA",
		Severity:    domain.SeverityHigh,
		Metadata:    map[string]any{},
	}
}

func TestUpsertDeduplicates(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	first, err := repo.Upsert(ctx, sampleFinding(projectID))
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if first.Status != domain.FindingOpen {
		t.Errorf("new finding status = %q, want open", first.Status)
	}

	// Same fingerprint, new severity/title: must update in place, not duplicate.
	updated := sampleFinding(projectID)
	updated.Severity = domain.SeverityCritical
	updated.Title = "Now critical"
	second, err := repo.Upsert(ctx, updated)
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	if second.ID != first.ID {
		t.Errorf("expected same row, got %s and %s", first.ID, second.ID)
	}
	if second.Severity != domain.SeverityCritical || second.Title != "Now critical" {
		t.Errorf("mutable fields not refreshed: %+v", second)
	}
	if !second.LastSeenAt.After(first.LastSeenAt) && !second.LastSeenAt.Equal(first.LastSeenAt) {
		t.Error("last_seen_at should advance or stay equal, never regress")
	}
	if !second.FirstSeenAt.Equal(first.FirstSeenAt) {
		t.Error("first_seen_at must be preserved across sightings")
	}

	list, err := repo.List(ctx, finding.Filter{ProjectID: projectID})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected 1 deduplicated finding, got %d", len(list))
	}
}

func TestRemediatedFindingReopensOnReappearance(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	created, err := repo.Upsert(ctx, sampleFinding(projectID))
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Analyst marks it remediated -> resolved_at is stamped.
	resolved, err := repo.SetStatus(ctx, created.ID, finding.Triage{Status: domain.FindingRemediated})
	if err != nil {
		t.Fatalf("set status: %v", err)
	}
	if resolved.ResolvedAt == nil {
		t.Fatal("resolved_at should be set when remediated")
	}

	// The same issue shows up in a later scan -> it must reopen and clear resolved_at.
	reopened, err := repo.Upsert(ctx, sampleFinding(projectID))
	if err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	if reopened.Status != domain.FindingOpen {
		t.Errorf("status = %q, want reopened to open", reopened.Status)
	}
	if reopened.ResolvedAt != nil {
		t.Error("resolved_at should be cleared on reopen")
	}
}

func TestTriageStatusIsSticky(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	created, _ := repo.Upsert(ctx, sampleFinding(projectID))
	if _, err := repo.SetStatus(ctx, created.ID, finding.Triage{Status: domain.FindingFalsePositive}); err != nil {
		t.Fatalf("set status: %v", err)
	}

	// Re-ingesting must NOT resurrect a false positive (only 'remediated' reopens).
	again, err := repo.Upsert(ctx, sampleFinding(projectID))
	if err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	if again.Status != domain.FindingFalsePositive {
		t.Errorf("status = %q, want false_positive to stick", again.Status)
	}
}

func TestCloseMissingAutoRemediates(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	scan1 := seedScan(t, pool, projectID)
	scan2 := seedScan(t, pool, projectID)

	// Two findings first seen in scan1.
	a := sampleFinding(projectID)
	a.Fingerprint, a.LastScanID = "fp-a", &scan1
	b := sampleFinding(projectID)
	b.Fingerprint, b.LastScanID = "fp-b", &scan1
	createdA, err := repo.Upsert(ctx, a)
	if err != nil {
		t.Fatalf("upsert a: %v", err)
	}
	createdB, err := repo.Upsert(ctx, b)
	if err != nil {
		t.Fatalf("upsert b: %v", err)
	}

	// A triaged finding must survive auto-close.
	if _, err := repo.SetStatus(ctx, createdB.ID, finding.Triage{Status: domain.FindingWontFix}); err != nil {
		t.Fatalf("set status b: %v", err)
	}

	// Rescan (scan2) re-sees only A.
	a.LastScanID = &scan2
	if _, err := repo.Upsert(ctx, a); err != nil {
		t.Fatalf("re-upsert a: %v", err)
	}

	// Anything from trivy not touched by scan2 and still live gets closed.
	closed, err := repo.CloseMissing(ctx, projectID, "trivy", scan2)
	if err != nil {
		t.Fatalf("close missing: %v", err)
	}
	if len(closed) != 0 {
		// A was seen (last_scan_id=scan2); B is wont_fix (not live) -> nothing to close.
		t.Errorf("closed = %v, want none (A seen, B triaged)", closed)
	}

	// Now add a third finding seen only in scan1, still open, and confirm it closes.
	cFinding := sampleFinding(projectID)
	cFinding.Fingerprint, cFinding.LastScanID = "fp-c", &scan1
	createdC, err := repo.Upsert(ctx, cFinding)
	if err != nil {
		t.Fatalf("upsert c: %v", err)
	}

	closed, err = repo.CloseMissing(ctx, projectID, "trivy", scan2)
	if err != nil {
		t.Fatalf("close missing 2: %v", err)
	}
	if len(closed) != 1 || closed[0] != createdC.ID {
		t.Fatalf("closed = %v, want exactly fp-c (%s) — dedup needs the ids to re-elect its group", closed, createdC.ID)
	}

	// A stays open; C is remediated with resolved_at set.
	gotA, _ := repo.Get(ctx, createdA.ID)
	if gotA.Status != domain.FindingOpen {
		t.Errorf("A status = %q, want open", gotA.Status)
	}
	gotC, _ := repo.Get(ctx, createdC.ID)
	if gotC.Status != domain.FindingRemediated || gotC.ResolvedAt == nil {
		t.Errorf("C = %q resolved=%v, want remediated with resolved_at", gotC.Status, gotC.ResolvedAt)
	}
}

// A scan only vouches for the target it scanned: a scan of another branch or
// another asset in the same project must not auto-close findings it never looked at.
func TestCloseMissingScopedToScanTarget(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	asset := func(identifier string) string {
		var id string
		if err := pool.QueryRow(ctx,
			`INSERT INTO assets (project_id, type, name, identifier) VALUES ($1, 'container_image', $2, $2) RETURNING id`,
			projectID, identifier).Scan(&id); err != nil {
			t.Fatalf("seed asset: %v", err)
		}
		return id
	}
	scan := func(assetID *string, branch string) string {
		var id string
		if err := pool.QueryRow(ctx,
			`INSERT INTO scans (project_id, asset_id, branch, scanner, category, status) VALUES ($1, $2, $3, 'trivy', 'sca', 'completed') RETURNING id`,
			projectID, assetID, branch).Scan(&id); err != nil {
			t.Fatalf("seed scan: %v", err)
		}
		return id
	}
	imageA, imageB := asset("registry/a"), asset("registry/b")
	mainA, mainB := scan(&imageA, "main"), scan(&imageB, "main")

	seen := func(fingerprint, scanID string) finding.Finding {
		f := sampleFinding(projectID)
		f.Fingerprint, f.LastScanID = fingerprint, &scanID
		created, err := repo.Upsert(ctx, f)
		if err != nil {
			t.Fatalf("upsert %s: %v", fingerprint, err)
		}
		return created
	}
	onA, onB := seen("fp-a", mainA), seen("fp-b", mainB)

	// Each of these scans reports nothing, but none of them scanned image A on main
	// or image B on main, so nothing may close.
	for name, other := range map[string]string{
		"feature branch of A": scan(&imageA, "feature/x"),
		"no asset, main":      scan(nil, "main"),
		"no asset, no branch": scan(nil, ""),
	} {
		closed, err := repo.CloseMissing(ctx, projectID, "trivy", other)
		if err != nil {
			t.Fatalf("%s: close missing: %v", name, err)
		}
		if len(closed) != 0 {
			t.Errorf("%s closed %v, want none", name, closed)
		}
	}

	// A rescan of image A on main that no longer reports fp-a closes fp-a only.
	closed, err := repo.CloseMissing(ctx, projectID, "trivy", scan(&imageA, "main"))
	if err != nil {
		t.Fatalf("close missing: %v", err)
	}
	if len(closed) != 1 || closed[0] != onA.ID {
		t.Fatalf("closed = %v, want exactly fp-a (%s)", closed, onA.ID)
	}
	if got, _ := repo.Get(ctx, onB.ID); got.Status != domain.FindingOpen {
		t.Errorf("image B finding status = %q, want open", got.Status)
	}
}

// A false positive / won't fix exception with an expiry reopens when it lapses.
func TestExceptionExpiry(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	created, err := repo.Upsert(ctx, sampleFinding(projectID))
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}

	// Won't fix, with a reason and an expiry already in the past.
	past := time.Now().Add(-time.Hour)
	accepted, err := repo.SetStatus(ctx, created.ID, finding.Triage{
		Status:    domain.FindingWontFix,
		Reason:    "compensating control in place",
		Actor:     "user-1",
		ExpiresAt: &past,
	})
	if err != nil {
		t.Fatalf("won't fix: %v", err)
	}
	if accepted.Status != domain.FindingWontFix || accepted.ExceptionReason != "compensating control in place" ||
		accepted.ExceptionBy != "user-1" || accepted.ExceptionExpiresAt == nil {
		t.Fatalf("exception fields not set: %+v", accepted)
	}

	// The acceptance is recorded in the audit log.
	history, err := repo.ListExceptions(ctx, created.ID)
	if err != nil {
		t.Fatalf("list exceptions: %v", err)
	}
	if len(history) != 1 || history[0].Reason != "compensating control in place" || history[0].Actor != "user-1" {
		t.Fatalf("audit history wrong: %+v", history)
	}

	// The sweep reopens it (expiry is in the past) and logs an audit event.
	n, err := repo.ExpireExceptions(ctx)
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if n != 1 {
		t.Fatalf("expired = %d, want 1", n)
	}
	reopened, _ := repo.Get(ctx, created.ID)
	if reopened.Status != domain.FindingOpen || reopened.ExceptionExpiresAt != nil || reopened.ExceptionReason != "" {
		t.Errorf("reopened finding still carries exception: %+v", reopened)
	}
	if history, _ := repo.ListExceptions(ctx, created.ID); len(history) != 2 {
		t.Errorf("audit history = %d, want 2 (accept + expire)", len(history))
	}
}

func TestExceptionWithFutureExpirySurvivesSweep(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	created, _ := repo.Upsert(ctx, sampleFinding(projectID))
	future := time.Now().Add(30 * 24 * time.Hour)
	if _, err := repo.SetStatus(ctx, created.ID, finding.Triage{
		Status: domain.FindingFalsePositive, Reason: "temporary", Actor: "u", ExpiresAt: &future,
	}); err != nil {
		t.Fatalf("accept: %v", err)
	}

	n, err := repo.ExpireExceptions(ctx)
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if n != 0 {
		t.Errorf("expired = %d, want 0 (expiry is in the future)", n)
	}
	if got, _ := repo.Get(ctx, created.ID); got.Status != domain.FindingFalsePositive {
		t.Errorf("status = %q, want false_positive (still valid)", got.Status)
	}

	// It shows up in the "expiring within 60 days" queue but not within 7.
	if soon, _ := repo.ListExpiring(ctx, 60, nil); len(soon) != 1 {
		t.Errorf("expiring within 60d = %d, want 1", len(soon))
	}
	if soon, _ := repo.ListExpiring(ctx, 7, nil); len(soon) != 0 {
		t.Errorf("expiring within 7d = %d, want 0 (expiry is 30d out)", len(soon))
	}
}

func TestListFiltersAndCounts(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	high := sampleFinding(projectID)
	high.Fingerprint = "fp-high"
	crit := sampleFinding(projectID)
	crit.Fingerprint = "fp-crit"
	crit.Severity = domain.SeverityCritical
	for _, f := range []finding.Finding{high, crit} {
		if _, err := repo.Upsert(ctx, f); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}

	critOnly, err := repo.List(ctx, finding.Filter{ProjectID: projectID, Severity: domain.SeverityCritical})
	if err != nil {
		t.Fatalf("list filtered: %v", err)
	}
	if len(critOnly) != 1 || critOnly[0].Severity != domain.SeverityCritical {
		t.Errorf("severity filter wrong: %+v", critOnly)
	}

	counts, err := repo.CountByProjects(ctx, []string{projectID})
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	total := 0
	for _, c := range counts {
		total += c.Count
	}
	if total != 2 {
		t.Errorf("counted %d findings, want 2", total)
	}
}

func TestListNewHighSeverity(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	scanID := seedScan(t, pool, projectID)

	crit := sampleFinding(projectID)
	crit.Fingerprint, crit.Severity, crit.LastScanID = "fp-crit", domain.SeverityCritical, &scanID
	low := sampleFinding(projectID)
	low.Fingerprint, low.Severity, low.LastScanID = "fp-low", domain.SeverityLow, &scanID
	for _, f := range []finding.Finding{crit, low} {
		if _, err := repo.Upsert(ctx, f); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}

	newHigh, err := repo.ListNewHighSeverity(ctx, scanID)
	if err != nil {
		t.Fatalf("ListNewHighSeverity: %v", err)
	}
	if len(newHigh) != 1 || newHigh[0].Severity != domain.SeverityCritical {
		t.Fatalf("newHigh = %+v, want 1 critical (low excluded)", newHigh)
	}
	if other, _ := repo.ListNewHighSeverity(ctx, seedScan(t, pool, projectID)); len(other) != 0 {
		t.Errorf("other scan newHigh = %d, want 0", len(other))
	}
}

func TestDeduplicateCrossTool(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	mk := func(fp, scanner string, sev domain.Severity) finding.Finding {
		f := sampleFinding(projectID)
		f.Fingerprint, f.Scanner, f.Severity = fp, scanner, sev
		f.CVE, f.PackageName = []string{"CVE-2021-44228"}, "log4j-core"
		f.Category = domain.CategorySCA
		return f
	}
	trivy, _ := repo.Upsert(ctx, mk("fp-trivy", "trivy", domain.SeverityHigh))
	grype, _ := repo.Upsert(ctx, mk("fp-grype", "grype", domain.SeverityCritical))
	// A non-CVE finding must never be grouped.
	secretF := sampleFinding(projectID)
	secretF.Fingerprint, secretF.Scanner, secretF.Category, secretF.CVE = "fp-secret", "gitleaks", domain.CategorySecret, nil
	secret, _ := repo.Upsert(ctx, secretF)

	n, err := repo.Deduplicate(ctx, projectID)
	if err != nil {
		t.Fatalf("dedup: %v", err)
	}
	if n != 1 {
		t.Fatalf("duplicates = %d, want 1", n)
	}

	// The critical (higher-priority) report is the primary; trivy points at it.
	gotGrype, _ := repo.Get(ctx, grype.ID)
	gotTrivy, _ := repo.Get(ctx, trivy.ID)
	if gotGrype.DuplicateOf != nil {
		t.Errorf("grype (critical) should be primary, got duplicate_of=%v", *gotGrype.DuplicateOf)
	}
	if gotTrivy.DuplicateOf == nil || *gotTrivy.DuplicateOf != grype.ID {
		t.Errorf("trivy should point at grype primary, got %v", gotTrivy.DuplicateOf)
	}
	if gotSecret, _ := repo.Get(ctx, secret.ID); gotSecret.DuplicateOf != nil || gotSecret.CorrelationKey != nil {
		t.Error("non-CVE finding must not be grouped")
	}

	// Default list collapses to primary + secret (2); with duplicates -> 3.
	if list, _ := repo.List(ctx, finding.Filter{ProjectID: projectID}); len(list) != 2 {
		t.Errorf("default list = %d, want 2 (duplicate hidden)", len(list))
	}
	if list, _ := repo.List(ctx, finding.Filter{ProjectID: projectID, IncludeDuplicates: true}); len(list) != 3 {
		t.Errorf("include_duplicates list = %d, want 3", len(list))
	}
	if dups, _ := repo.ListDuplicatesOf(ctx, grype.ID); len(dups) != 1 || dups[0].Scanner != "trivy" {
		t.Errorf("duplicates of grype = %+v, want [trivy]", dups)
	}
	if counts, _ := repo.DuplicateCounts(ctx, []string{grype.ID}); counts[grype.ID] != 1 {
		t.Errorf("duplicate count = %v, want 1", counts)
	}

	// Risk counting is not doubled: the CVE group contributes one open finding.
	counts, _ := repo.CountByProjects(ctx, []string{projectID})
	openSCA := 0
	for _, c := range counts {
		if c.Status == domain.FindingOpen && c.Severity == domain.SeverityCritical {
			openSCA += c.Count
		}
	}
	if openSCA != 1 {
		t.Errorf("open critical count = %d, want 1 (not double-counted)", openSCA)
	}

	// Re-election: close the primary -> the remaining report becomes primary.
	if _, err := repo.SetStatus(ctx, grype.ID, finding.Triage{Status: domain.FindingRemediated}); err != nil {
		t.Fatalf("close primary: %v", err)
	}
	if _, err := repo.Deduplicate(ctx, projectID); err != nil {
		t.Fatalf("re-dedup: %v", err)
	}
	if reTrivy, _ := repo.Get(ctx, trivy.ID); reTrivy.DuplicateOf != nil {
		t.Errorf("trivy should be re-elected primary after grype closed, got duplicate_of=%v", *reTrivy.DuplicateOf)
	}
}

// sastFinding builds a non-CVE SAST-style finding at an exact file/line, for
// the location+CWE correlation key tests below.
func sastFinding(projectID, fp, scanner, ruleID, file string, line int, cwe *int, sev domain.Severity) finding.Finding {
	f := sampleFinding(projectID)
	f.Fingerprint, f.Scanner, f.RuleID, f.Severity = fp, scanner, ruleID, sev
	f.Category, f.CVE = domain.CategorySAST, nil
	f.FilePath, f.Line, f.CWE = file, new(line), cwe
	return f
}

// TestDeduplicateLocationCrossScanner is 12.1: a SAST/secrets/IaC finding
// without a CVE now groups across scanners by category + file + line + CWE,
// the same way a CVE finding groups by CVE + package.
func TestDeduplicateLocationCrossScanner(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	cwe798 := 798

	semgrep, _ := repo.Upsert(ctx, sastFinding(projectID, "fp-semgrep-1", "semgrep", "hardcoded-secret", "app/auth.go", 42, &cwe798, domain.SeverityHigh))
	gosec, _ := repo.Upsert(ctx, sastFinding(projectID, "fp-gosec-1", "gosec", "G101", "app/auth.go", 42, &cwe798, domain.SeverityCritical))

	n, err := repo.Deduplicate(ctx, projectID)
	if err != nil {
		t.Fatalf("dedup: %v", err)
	}
	if n != 1 {
		t.Fatalf("duplicates = %d, want 1", n)
	}

	gotGosec, _ := repo.Get(ctx, gosec.ID)
	gotSemgrep, _ := repo.Get(ctx, semgrep.ID)
	if gotGosec.DuplicateOf != nil {
		t.Errorf("gosec (critical) should be primary, got duplicate_of=%v", *gotGosec.DuplicateOf)
	}
	if gotSemgrep.DuplicateOf == nil || *gotSemgrep.DuplicateOf != gosec.ID {
		t.Errorf("semgrep should point at gosec primary, got %v", gotSemgrep.DuplicateOf)
	}
	if gotGosec.CorrelationKey == nil || gotSemgrep.CorrelationKey == nil || *gotGosec.CorrelationKey != *gotSemgrep.CorrelationKey {
		t.Errorf("both reports of the same CWE at the same line should share a correlation key")
	}

	if list, _ := repo.List(ctx, finding.Filter{ProjectID: projectID}); len(list) != 1 {
		t.Errorf("default list = %d, want 1 (duplicate hidden)", len(list))
	}
}

// TestDeduplicateLocationSameScannerStaysSeparate pins the guard in step 2 of
// deduplicate: two rules reported by the *same* tool on the same line (even
// with the same CWE, so they'd share a correlation key) are two distinct
// findings, never one another's duplicate.
func TestDeduplicateLocationSameScannerStaysSeparate(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	cwe798 := 798

	rule1, _ := repo.Upsert(ctx, sastFinding(projectID, "fp-semgrep-1", "semgrep", "hardcoded-secret", "app/auth.go", 42, &cwe798, domain.SeverityHigh))
	rule2, _ := repo.Upsert(ctx, sastFinding(projectID, "fp-semgrep-2", "semgrep", "weak-crypto", "app/auth.go", 42, &cwe798, domain.SeverityCritical))

	if _, err := repo.Deduplicate(ctx, projectID); err != nil {
		t.Fatalf("dedup: %v", err)
	}

	got1, _ := repo.Get(ctx, rule1.ID)
	got2, _ := repo.Get(ctx, rule2.ID)
	if got1.DuplicateOf != nil {
		t.Errorf("rule1 must stay visible, got duplicate_of=%v", *got1.DuplicateOf)
	}
	if got2.DuplicateOf != nil {
		t.Errorf("rule2 must stay visible, got duplicate_of=%v", *got2.DuplicateOf)
	}
	if got1.CorrelationKey == nil || got2.CorrelationKey == nil || *got1.CorrelationKey != *got2.CorrelationKey {
		t.Errorf("both rules at the same line/CWE still share a correlation key (the guard is on election, not the key)")
	}
	if list, _ := repo.List(ctx, finding.Filter{ProjectID: projectID}); len(list) != 2 {
		t.Errorf("default list = %d, want 2 (one tool's two rules never hide each other)", len(list))
	}
}

// TestDeduplicateLocationDifferentLineStaysSeparate: two scanners reporting at
// different lines of the same file never group, even with the same CWE.
func TestDeduplicateLocationDifferentLineStaysSeparate(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	cwe798 := 798

	a, _ := repo.Upsert(ctx, sastFinding(projectID, "fp-semgrep-1", "semgrep", "hardcoded-secret", "app/auth.go", 42, &cwe798, domain.SeverityHigh))
	b, _ := repo.Upsert(ctx, sastFinding(projectID, "fp-gosec-1", "gosec", "G101", "app/auth.go", 99, &cwe798, domain.SeverityCritical))

	if _, err := repo.Deduplicate(ctx, projectID); err != nil {
		t.Fatalf("dedup: %v", err)
	}
	gotA, _ := repo.Get(ctx, a.ID)
	gotB, _ := repo.Get(ctx, b.ID)
	if gotA.DuplicateOf != nil || gotB.DuplicateOf != nil {
		t.Errorf("different lines must never group: a=%v b=%v", gotA.DuplicateOf, gotB.DuplicateOf)
	}
	if gotA.CorrelationKey == nil || gotB.CorrelationKey == nil || *gotA.CorrelationKey == *gotB.CorrelationKey {
		t.Errorf("different lines must produce different correlation keys")
	}
}

// TestDeduplicateLocationCWERules pins the exact CWE-matching rule: a key is
// never shared unless both sides carry the matching CWE, or both sides carry
// none at all.
func TestDeduplicateLocationCWERules(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	cwe798, cwe89 := 798, 89

	t.Run("different CWE at the same line never groups", func(t *testing.T) {
		a, _ := repo.Upsert(ctx, sastFinding(projectID, "fp-cwe-a", "semgrep", "r1", "app/db.go", 10, &cwe798, domain.SeverityHigh))
		b, _ := repo.Upsert(ctx, sastFinding(projectID, "fp-cwe-b", "gosec", "r2", "app/db.go", 10, &cwe89, domain.SeverityCritical))
		if _, err := repo.Deduplicate(ctx, projectID); err != nil {
			t.Fatalf("dedup: %v", err)
		}
		gotA, _ := repo.Get(ctx, a.ID)
		gotB, _ := repo.Get(ctx, b.ID)
		if gotA.DuplicateOf != nil || gotB.DuplicateOf != nil {
			t.Errorf("mismatched CWE must never group: a=%v b=%v", gotA.DuplicateOf, gotB.DuplicateOf)
		}
	})

	t.Run("CWE present on only one side never groups", func(t *testing.T) {
		a, _ := repo.Upsert(ctx, sastFinding(projectID, "fp-half-a", "semgrep", "r3", "app/handler.go", 20, &cwe798, domain.SeverityHigh))
		b, _ := repo.Upsert(ctx, sastFinding(projectID, "fp-half-b", "gosec", "r4", "app/handler.go", 20, nil, domain.SeverityCritical))
		if _, err := repo.Deduplicate(ctx, projectID); err != nil {
			t.Fatalf("dedup: %v", err)
		}
		gotA, _ := repo.Get(ctx, a.ID)
		gotB, _ := repo.Get(ctx, b.ID)
		if gotA.DuplicateOf != nil || gotB.DuplicateOf != nil {
			t.Errorf("one-sided CWE must never group: a=%v b=%v", gotA.DuplicateOf, gotB.DuplicateOf)
		}
	})

	t.Run("CWE absent on both sides falls back to location", func(t *testing.T) {
		a, _ := repo.Upsert(ctx, sastFinding(projectID, "fp-nocwe-a", "semgrep", "r5", "app/middleware.go", 30, nil, domain.SeverityHigh))
		b, _ := repo.Upsert(ctx, sastFinding(projectID, "fp-nocwe-b", "gosec", "r6", "app/middleware.go", 30, nil, domain.SeverityCritical))
		if n, err := repo.Deduplicate(ctx, projectID); err != nil || n == 0 {
			t.Fatalf("dedup = %d, %v; want at least one write", n, err)
		}
		gotA, _ := repo.Get(ctx, a.ID)
		gotB, _ := repo.Get(ctx, b.ID)
		if (gotA.DuplicateOf == nil) == (gotB.DuplicateOf == nil) {
			t.Errorf("exactly one of the two CWE-less reports should be primary: a=%v b=%v", gotA.DuplicateOf, gotB.DuplicateOf)
		}
	})
}

// TestDeduplicateCVEUnaffectedByLocationKey guards against the new location
// branch accidentally taking priority over, or interfering with, the existing
// CVE branch: two scanners reporting the same CVE+package but at different
// lines must still merge on the CVE, exactly as before.
func TestDeduplicateCVEUnaffectedByLocationKey(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	mk := func(fp, scanner string, line int, sev domain.Severity) finding.Finding {
		f := sampleFinding(projectID)
		f.Fingerprint, f.Scanner, f.Severity = fp, scanner, sev
		f.CVE, f.PackageName = []string{"CVE-2021-44228"}, "log4j-core"
		f.Category = domain.CategorySCA
		f.FilePath, f.Line = "pom.xml", new(line)
		f.CWE = nil
		return f
	}
	trivy, _ := repo.Upsert(ctx, mk("fp-trivy-cve", "trivy", 5, domain.SeverityHigh))
	grype, _ := repo.Upsert(ctx, mk("fp-grype-cve", "grype", 77, domain.SeverityCritical))

	if n, err := repo.Deduplicate(ctx, projectID); err != nil || n != 1 {
		t.Fatalf("dedup = %d, %v; want 1 (CVE+package, ignoring the differing lines)", n, err)
	}
	gotTrivy, _ := repo.Get(ctx, trivy.ID)
	gotGrype, _ := repo.Get(ctx, grype.ID)
	if gotGrype.DuplicateOf != nil {
		t.Errorf("grype (critical) should be primary")
	}
	if gotTrivy.DuplicateOf == nil || *gotTrivy.DuplicateOf != grype.ID {
		t.Errorf("trivy should point at grype, got %v", gotTrivy.DuplicateOf)
	}
	if gotGrype.CorrelationKey == nil || !strings.HasPrefix(*gotGrype.CorrelationKey, "cve-2021-44228|") {
		t.Errorf("CVE+package findings must still use the CVE key, got %v", gotGrype.CorrelationKey)
	}
}

// TestDeduplicateCVESameScannerStillCollapses pins that the scanner-identity
// rule is scoped to location keys only: a CVE-keyed group collapses whenever
// it has more than one member, same scanner or not, exactly as it did before
// this feature (e.g. one tool reporting the same CVE+package at two lockfile
// paths in a monorepo).
func TestDeduplicateCVESameScannerStillCollapses(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	mk := func(fp, path string, line int, sev domain.Severity) finding.Finding {
		f := sampleFinding(projectID)
		f.Fingerprint, f.Scanner, f.Severity = fp, "trivy", sev
		f.CVE, f.PackageName = []string{"CVE-2021-44228"}, "log4j-core"
		f.Category = domain.CategorySCA
		f.FilePath, f.Line = path, new(line)
		return f
	}
	a, _ := repo.Upsert(ctx, mk("fp-trivy-a", "services/a/pom.xml", 1, domain.SeverityHigh))
	b, _ := repo.Upsert(ctx, mk("fp-trivy-b", "services/b/pom.xml", 2, domain.SeverityCritical))

	if n, err := repo.Deduplicate(ctx, projectID); err != nil || n != 1 {
		t.Fatalf("dedup = %d, %v; want 1 (same scanner, same CVE+package, still one group)", n, err)
	}
	gotA, _ := repo.Get(ctx, a.ID)
	gotB, _ := repo.Get(ctx, b.ID)
	if gotB.DuplicateOf != nil {
		t.Errorf("critical report should be primary, got duplicate_of=%v", *gotB.DuplicateOf)
	}
	if gotA.DuplicateOf == nil || *gotA.DuplicateOf != b.ID {
		t.Errorf("same-scanner CVE+package report should still collapse to the primary, got %v", gotA.DuplicateOf)
	}
}

// TestDeduplicateLocationMixedScannerCountStaysUngrouped pins the group-level
// rule: a location-keyed group collapses only when every member is a
// different scanner (count(*) = count(distinct scanner)). Two reports from
// scanner X plus one from scanner Y at the same file/line/CWE must leave all
// three visible — collapsing any pair would either hide one tool's second
// rule behind its own first, or arbitrarily pick which of X's two reports
// survives alongside Y.
func TestDeduplicateLocationMixedScannerCountStaysUngrouped(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	cwe798 := 798

	x1, _ := repo.Upsert(ctx, sastFinding(projectID, "fp-x-1", "semgrep", "r1", "app/auth.go", 42, &cwe798, domain.SeverityHigh))
	x2, _ := repo.Upsert(ctx, sastFinding(projectID, "fp-x-2", "semgrep", "r2", "app/auth.go", 42, &cwe798, domain.SeverityCritical))
	y1, _ := repo.Upsert(ctx, sastFinding(projectID, "fp-y-1", "gosec", "G101", "app/auth.go", 42, &cwe798, domain.SeverityMedium))

	if _, err := repo.Deduplicate(ctx, projectID); err != nil {
		t.Fatalf("dedup: %v", err)
	}
	for name, id := range map[string]string{"x1": x1.ID, "x2": x2.ID, "y1": y1.ID} {
		got, _ := repo.Get(ctx, id)
		if got.DuplicateOf != nil {
			t.Errorf("%s should stay visible (group is not all-distinct-scanners), got duplicate_of=%v", name, *got.DuplicateOf)
		}
	}
	if list, _ := repo.List(ctx, finding.Filter{ProjectID: projectID}); len(list) != 3 {
		t.Errorf("default list = %d, want 3 (no member of a mixed-count group hides another)", len(list))
	}
}

// TestDeduplicateLocationScanMatchesFullRun extends the DeduplicateScan safety
// net to the new location+CWE correlation key: an ingest that moves a
// finding's line (so it leaves its old group) and closes a group's primary
// must still land exactly where a full recompute would.
func TestDeduplicateLocationScanMatchesFullRun(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	scan1 := seedScan(t, pool, projectID)
	cweA := 798

	mk := func(scanID, fp, scanner string, line int, sev domain.Severity) finding.Finding {
		f := sastFinding(projectID, fp, scanner, "r", "app/auth.go", line, &cweA, sev)
		f.LastScanID = &scanID
		out, err := repo.Upsert(ctx, f)
		if err != nil {
			t.Fatalf("upsert %s: %v", fp, err)
		}
		return out
	}

	// Group A: semgrep(high) + gosec(critical), both distinct scanners -> collapses, gosec primary.
	semgrepA := mk(scan1, "fp-semgrep-a", "semgrep", 42, domain.SeverityHigh)
	gosecA := mk(scan1, "fp-gosec-a", "gosec", 42, domain.SeverityCritical)
	// Group B: two gosec findings, same scanner -> never collapses (grp != distinct_scanners).
	mk(scan1, "fp-gosec-b1", "gosec", 100, domain.SeverityCritical)
	mk(scan1, "fp-gosec-b2", "gosec", 100, domain.SeverityLow)
	// Group C: checkov + semgrep at line 200, both distinct scanners -> collapses initially.
	checkovC1 := mk(scan1, "fp-checkov-c1", "checkov", 200, domain.SeverityCritical)
	semgrepC1 := mk(scan1, "fp-semgrep-c1", "semgrep", 200, domain.SeverityHigh)
	if _, err := repo.Deduplicate(ctx, projectID); err != nil {
		t.Fatalf("initial dedup: %v", err)
	}
	if got, _ := repo.Get(ctx, semgrepC1.ID); got.DuplicateOf == nil || *got.DuplicateOf != checkovC1.ID {
		t.Fatalf("group C should collapse before scan 2 (2 distinct scanners), got duplicate_of=%v", got.DuplicateOf)
	}

	// Scan 2 (semgrep only): its report of line 42 moves to line 55 — it
	// leaves group A, which must re-elect (gosec alone, now ungrouped).
	scan2 := seedScan(t, pool, projectID)
	moved := sastFinding(projectID, "fp-semgrep-a", "semgrep", "r", "app/auth.go", 55, &cweA, domain.SeverityHigh)
	moved.LastScanID = &scan2
	if _, err := repo.Upsert(ctx, moved); err != nil {
		t.Fatalf("upsert moved: %v", err)
	}
	// A second checkov report lands in group C: it now has two checkov members
	// and one semgrep (grp=3, distinct_scanners=2), so it must UN-collapse —
	// both checkovC1 (the old primary) and semgrepC1 (the old duplicate) must
	// end up with duplicate_of cleared. This is the "(b)" case: a mixed-count
	// group never collapses, verified through the scan-scoped path too.
	checkovC2 := sastFinding(projectID, "fp-checkov-c2", "checkov", "r2", "app/auth.go", 200, &cweA, domain.SeverityCritical)
	checkovC2.LastScanID = &scan2
	checkovC2Out, err := repo.Upsert(ctx, checkovC2)
	if err != nil {
		t.Fatalf("upsert checkov-c2: %v", err)
	}
	// ...and gosec's b1 (group B's primary) is no longer reported, so it closes.
	closed, err := repo.CloseMissing(ctx, projectID, "gosec", scan2)
	if err != nil {
		t.Fatalf("close missing: %v", err)
	}
	if len(closed) != 3 { // gosec-a, gosec-b1, gosec-b2 were all last seen in scan1
		t.Fatalf("closed %d gosec findings, want 3", len(closed))
	}

	if _, err := repo.DeduplicateScan(ctx, projectID, scan2, closed); err != nil {
		t.Fatalf("incremental dedup: %v", err)
	}
	incremental := grouping(t, pool, projectID)

	if _, err := repo.Deduplicate(ctx, projectID); err != nil {
		t.Fatalf("full dedup: %v", err)
	}
	full := grouping(t, pool, projectID)

	if !maps.Equal(incremental, full) {
		t.Errorf("incremental dedup diverged from a full recompute:\n incremental: %v\n full:        %v", incremental, full)
	}
	if d := incremental[semgrepA.ID]; d != "" {
		t.Errorf("moved finding still marked duplicate_of=%s", d)
	}
	if d := incremental[gosecA.ID]; d != "" {
		t.Errorf("group A has one member left, so it must not be a duplicate (got %s)", d)
	}
	for name, id := range map[string]string{"checkovC1": checkovC1.ID, "semgrepC1": semgrepC1.ID, "checkovC2": checkovC2Out.ID} {
		if d := incremental[id]; d != "" {
			t.Errorf("group C is now mixed-count (2 checkov + 1 semgrep), so %s must not be a duplicate (got %s)", name, d)
		}
	}
}

func TestGateStatsNewOnly(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	scan1 := seedScan(t, pool, projectID)
	scan2 := seedScan(t, pool, projectID)

	// An old finding: first seen in scan1, re-confirmed in scan2 (first != last).
	old := sampleFinding(projectID)
	old.Fingerprint, old.Severity, old.LastScanID = "fp-old", domain.SeverityCritical, &scan1
	if _, err := repo.Upsert(ctx, old); err != nil {
		t.Fatalf("upsert old #1: %v", err)
	}
	old.LastScanID = &scan2
	if _, err := repo.Upsert(ctx, old); err != nil {
		t.Fatalf("upsert old #2: %v", err)
	}
	// A newly-introduced finding: only ever seen in scan2 (first == last).
	fresh := sampleFinding(projectID)
	fresh.Fingerprint, fresh.Severity, fresh.LastScanID = "fp-new", domain.SeverityCritical, &scan2
	if _, err := repo.Upsert(ctx, fresh); err != nil {
		t.Fatalf("upsert new: %v", err)
	}

	total, err := repo.ComputeGateStats(ctx, projectID, "", false, "")
	if err != nil {
		t.Fatalf("stats total: %v", err)
	}
	if total.OpenCritical != 2 {
		t.Errorf("total open critical = %d, want 2", total.OpenCritical)
	}
	newOnly, err := repo.ComputeGateStats(ctx, projectID, "", true, "")
	if err != nil {
		t.Fatalf("stats new-only: %v", err)
	}
	if newOnly.OpenCritical != 1 {
		t.Errorf("new-only open critical = %d, want 1 (only the newly-introduced finding)", newOnly.OpenCritical)
	}
}

// TestGateStatsBaseline pins the baseline-branch definition of "new": a finding
// that also lives open on the baseline version (same fingerprint — the stable,
// branch-independent identity Upsert/CloseMissing already use, see
// gateStatsQuery) is excused, even though every finding here was reported in a
// single scan (so the old first_scan_id=last_scan_id heuristic would call both
// "new").
func TestGateStatsBaseline(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	var mainID, featureID string
	if err := pool.QueryRow(ctx, `SELECT project_version($1, '', 'branch'), project_version($1, 'feature/x', 'branch')`,
		projectID).Scan(&mainID, &featureID); err != nil {
		t.Fatalf("seed versions: %v", err)
	}

	// Present on both branches (same identity): open on main too, so the
	// feature-branch copy is excused.
	shared := sampleFinding(projectID)
	shared.Fingerprint, shared.Severity = "fp-shared", domain.SeverityCritical
	shared.VersionID = mainID
	if _, err := repo.Upsert(ctx, shared); err != nil {
		t.Fatalf("upsert shared on main: %v", err)
	}
	shared.VersionID = featureID
	if _, err := repo.Upsert(ctx, shared); err != nil {
		t.Fatalf("upsert shared on feature/x: %v", err)
	}

	// Only on the feature branch: no twin on main.
	branchOnly := sampleFinding(projectID)
	branchOnly.Fingerprint, branchOnly.Severity, branchOnly.VersionID = "fp-branch-only", domain.SeverityCritical, featureID
	if _, err := repo.Upsert(ctx, branchOnly); err != nil {
		t.Fatalf("upsert branch-only: %v", err)
	}

	total, err := repo.ComputeGateStats(ctx, projectID, featureID, false, "")
	if err != nil {
		t.Fatalf("stats total: %v", err)
	}
	if total.OpenCritical != 2 {
		t.Fatalf("total open critical on feature/x = %d, want 2", total.OpenCritical)
	}

	baseline, err := repo.ComputeGateStats(ctx, projectID, featureID, true, mainID)
	if err != nil {
		t.Fatalf("stats vs baseline: %v", err)
	}
	if baseline.OpenCritical != 1 {
		t.Errorf("new-vs-baseline open critical = %d, want 1 (the shared finding is excused by main)", baseline.OpenCritical)
	}
}

// TestUpsertBatchIsEquivalentToUpsert pins the batched path to the same semantics
// as the single upsert — ingestion correctness must not depend on which one ran.
func TestUpsertBatchIsEquivalentToUpsert(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	scanID := seedScan(t, pool, projectID)

	batch := make([]finding.Finding, 300)
	for i := range batch {
		f := sampleFinding(projectID)
		f.Fingerprint = fmt.Sprintf("fp-%d", i)
		f.LastScanID = &scanID
		batch[i] = f
	}
	if err := repo.UpsertBatch(ctx, batch, ""); err != nil {
		t.Fatalf("upsert batch: %v", err)
	}
	stored, err := repo.List(ctx, finding.Filter{ProjectID: projectID, Limit: 1000})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(stored) != 300 {
		t.Fatalf("stored %d findings, want 300", len(stored))
	}

	// Re-ingesting the same fingerprints is a sighting, not a new row — and the
	// second scan must not be recorded as "first seen".
	scan2 := seedScan(t, pool, projectID)
	for i := range batch {
		batch[i].LastScanID = &scan2
		batch[i].Severity = domain.SeverityCritical
	}
	if err := repo.UpsertBatch(ctx, batch, ""); err != nil {
		t.Fatalf("re-upsert batch: %v", err)
	}
	stored, err = repo.List(ctx, finding.Filter{ProjectID: projectID, Limit: 1000})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(stored) != 300 {
		t.Fatalf("after re-upsert stored %d findings, want still 300", len(stored))
	}
	for _, f := range stored {
		if f.Severity != domain.SeverityCritical {
			t.Fatalf("severity not refreshed: %+v", f)
		}
		if f.FirstScanID == nil || *f.FirstScanID != scanID {
			t.Fatalf("first_scan_id changed on re-sighting: %+v", f.FirstScanID)
		}
	}

	// An error in the middle of a batch surfaces (bad project FK).
	bad := sampleFinding("00000000-0000-0000-0000-000000000000")
	bad.Fingerprint = "fp-bad"
	if err := repo.UpsertBatch(ctx, []finding.Finding{batch[0], bad}, ""); err == nil {
		t.Error("expected a batch containing an invalid finding to fail")
	}
}

// TestDeduplicateConcurrentSameProject asserts that concurrent ingests of one
// project (several workers upserting, then dedup'ing) converge on a sane
// grouping: exactly one primary per correlation group, and never a duplicate
// pointing at a finding that is itself a duplicate — a chain would hide findings
// from every list in the product. This is a convergence check, not a regression
// test for the advisory lock in Deduplicate: the interleaving that lock rules out
// is timing-dependent and this test does not reliably reproduce it.
// A CVE without a package (network / DAST scanners) is grouped by where it
// was found: the same CVE on two hosts is two vulnerabilities, while two
// tools reporting it on the same host are one.
func TestDeduplicatePackagelessByLocation(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	mk := func(fp, scanner, location string) finding.Finding {
		f := sampleFinding(projectID)
		f.Fingerprint, f.Scanner, f.Category = fp, scanner, domain.CategoryDAST
		f.CVE, f.PackageName, f.FilePath, f.Line = []string{"CVE-2014-0160"}, "", location, nil
		return f
	}
	for _, f := range []finding.Finding{
		mk("ov-a", "openvas", "10.0.0.1:443/tcp"),
		mk("ov-b", "openvas", "10.0.0.2:443/tcp"),
		mk("ns-a", "nessus", "10.0.0.1:443/tcp"),
	} {
		if _, err := repo.Upsert(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := repo.Deduplicate(ctx, projectID); err != nil || n != 1 {
		t.Fatalf("dedup = %d, %v; want 1 (the two reports on 10.0.0.1)", n, err)
	}
	list, _ := repo.List(ctx, finding.Filter{ProjectID: projectID})
	hosts := map[string]bool{}
	for _, f := range list {
		hosts[f.FilePath] = true
	}
	if len(list) != 2 || !hosts["10.0.0.1:443/tcp"] || !hosts["10.0.0.2:443/tcp"] {
		t.Errorf("visible findings = %d on %v, want one per host", len(list), hosts)
	}
}

func TestDeduplicateConcurrentSameProject(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	scanID := seedScan(t, pool, projectID)

	const groups = 25
	upsert := func(tool string, g int, sev domain.Severity) {
		f := sampleFinding(projectID)
		f.Fingerprint = fmt.Sprintf("fp-%s-%d", tool, g)
		f.Scanner = tool
		f.Severity = sev
		f.CVE = []string{fmt.Sprintf("CVE-2024-%04d", g)}
		f.PackageName = "libfoo"
		f.LastScanID = &scanID
		if _, err := repo.Upsert(ctx, f); err != nil {
			t.Errorf("upsert: %v", err)
		}
	}
	for g := range groups {
		upsert("trivy", g, domain.SeverityLow)
	}

	// Each worker is an ingest: it adds its tool's view of every group (at a
	// severity that reshuffles the election) and then dedups the project.
	tools := []struct {
		name string
		sev  domain.Severity
	}{
		{"grype", domain.SeverityCritical},
		{"osv", domain.SeverityHigh},
		{"snyk", domain.SeverityMedium},
		{"blint", domain.SeverityCritical},
		{"semgrep", domain.SeverityHigh},
		{"checkov", domain.SeverityLow},
	}
	var wg sync.WaitGroup
	errs := make(chan error, len(tools))
	for _, tool := range tools {
		wg.Go(func() {
			for g := range groups {
				upsert(tool.name, g, tool.sev)
			}
			if _, err := repo.Deduplicate(ctx, projectID); err != nil {
				errs <- err
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent dedup: %v", err)
	}
	// A final settled run, as the last ingest of a burst would do.
	if _, err := repo.Deduplicate(ctx, projectID); err != nil {
		t.Fatalf("final dedup: %v", err)
	}

	// Invariants: exactly one primary per group, and no duplicate pointing at a
	// finding that is itself a duplicate.
	var multiPrimary, chained int
	if err := pool.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM (
				SELECT correlation_key FROM findings
				WHERE project_id = $1 AND correlation_key IS NOT NULL
				  AND duplicate_of IS NULL AND status IN ('open', 'confirmed')
				GROUP BY correlation_key HAVING count(*) <> 1) x),
			(SELECT count(*) FROM findings d
				JOIN findings p ON p.id = d.duplicate_of
				WHERE d.project_id = $1 AND p.duplicate_of IS NOT NULL)`,
		projectID).Scan(&multiPrimary, &chained); err != nil {
		t.Fatalf("invariant query: %v", err)
	}
	if multiPrimary != 0 {
		t.Errorf("%d correlation groups do not have exactly one primary", multiPrimary)
	}
	if chained != 0 {
		t.Errorf("%d findings point at a primary that is itself a duplicate (interleaved dedup)", chained)
	}

	visible, err := repo.List(ctx, finding.Filter{ProjectID: projectID, Limit: 200})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(visible) != groups {
		t.Errorf("visible findings = %d, want %d (one primary per group)", len(visible), groups)
	}
}

// TestDeduplicateDoesNotRewriteUnchangedRows pins the write cost of dedup, which
// runs after *every* ingest. Rewriting rows to store the values they already
// hold would churn the whole findings table on each scan (dead tuples, WAL,
// bloat, vacuum pressure) — at ingest scale that dwarfs the real work. ctid
// changes whenever Postgres writes a new row version, so an unchanged row must
// keep its ctid across a settled re-run.
func TestDeduplicateDoesNotRewriteUnchangedRows(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	scanID := seedScan(t, pool, projectID)

	// A realistic mix: duplicate groups, plus findings dedup never groups.
	for g := range 10 {
		for _, tool := range []string{"trivy", "grype"} {
			f := sampleFinding(projectID)
			f.Fingerprint = fmt.Sprintf("fp-%s-%d", tool, g)
			f.Scanner = tool
			f.CVE = []string{fmt.Sprintf("CVE-2024-%04d", g)}
			f.PackageName = "libfoo"
			f.LastScanID = &scanID
			if _, err := repo.Upsert(ctx, f); err != nil {
				t.Fatalf("seed: %v", err)
			}
		}
	}
	for i := range 10 { // no CVE, no file/line: never correlated
		f := sampleFinding(projectID)
		f.Fingerprint = fmt.Sprintf("fp-secret-%d", i)
		f.Category = domain.CategorySecret
		f.LastScanID = &scanID
		if _, err := repo.Upsert(ctx, f); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	cweA := 798
	for g := range 5 { // location+CWE groups: same tooling mix as the CVE groups above
		for _, tool := range []string{"semgrep", "gosec"} {
			f := sastFinding(projectID, fmt.Sprintf("fp-%s-sast-%d", tool, g), tool, "r", fmt.Sprintf("app/f%d.go", g), 10, &cweA, domain.SeverityMedium)
			f.LastScanID = &scanID
			if _, err := repo.Upsert(ctx, f); err != nil {
				t.Fatalf("seed: %v", err)
			}
		}
	}

	if _, err := repo.Deduplicate(ctx, projectID); err != nil {
		t.Fatalf("dedup: %v", err)
	}
	before := rowVersions(t, pool, projectID)

	// Nothing has changed since, so this run must write nothing at all.
	if _, err := repo.Deduplicate(ctx, projectID); err != nil {
		t.Fatalf("re-dedup: %v", err)
	}
	after := rowVersions(t, pool, projectID)

	var rewritten int
	for id, ctid := range before {
		if after[id] != ctid {
			rewritten++
		}
	}
	if rewritten != 0 {
		t.Errorf("a settled dedup rewrote %d/%d rows; it must write only what changes", rewritten, len(before))
	}
}

// rowVersions maps finding id -> ctid (the physical row version).
func rowVersions(t *testing.T, pool *pgxpool.Pool, projectID string) map[string]string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT id, ctid::text FROM findings WHERE project_id = $1`, projectID)
	if err != nil {
		t.Fatalf("row versions: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, ctid string
		if err := rows.Scan(&id, &ctid); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[id] = ctid
	}
	return out
}

// TestDeduplicateScanMatchesFullRun is the safety net for incremental dedup: the
// ingest path only revisits the correlation groups a scan could have disturbed,
// and that is only sound if it lands on exactly the grouping a full recompute
// would have produced. It exercises the two cases where "the groups this scan
// reported" is not the whole answer: a finding that *moves* between groups (its
// CVE set changed, so the group it left must re-elect), and a primary that gets
// auto-closed (its group must hand off to a still-open sibling).
func TestDeduplicateScanMatchesFullRun(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := finding.NewRepository(pool)
	ctx := context.Background()
	projectID := seedProject(t, pool)
	scan1 := seedScan(t, pool, projectID)

	mk := func(scanID, fp, tool, cve string, sev domain.Severity) finding.Finding {
		f := sampleFinding(projectID)
		f.Fingerprint, f.Scanner, f.Severity = fp, tool, sev
		f.PackageName, f.Category = "log4j-core", domain.CategorySCA
		f.CVE = []string{cve}
		f.LastScanID = &scanID
		out, err := repo.Upsert(ctx, f)
		if err != nil {
			t.Fatalf("upsert %s: %v", fp, err)
		}
		return out
	}

	// Group A: trivy(high) + grype(critical) -> grype primary.
	trivyA := mk(scan1, "fp-trivy-a", "trivy", "CVE-1111", domain.SeverityHigh)
	grypeA := mk(scan1, "fp-grype-a", "grype", "CVE-1111", domain.SeverityCritical)
	// Group B: two grype findings, so closing one still leaves the group populated.
	mk(scan1, "fp-grype-b1", "grype", "CVE-2222", domain.SeverityCritical)
	mk(scan1, "fp-grype-b2", "grype", "CVE-2222", domain.SeverityLow)
	if _, err := repo.Deduplicate(ctx, projectID); err != nil {
		t.Fatalf("initial dedup: %v", err)
	}

	// Scan 2 (trivy only): the trivy report of CVE-1111 now reports CVE-3333
	// instead — it leaves group A, which trivy's scan never mentions again. Group
	// A must still re-elect (it is down to grype alone, which becomes ungrouped).
	scan2 := seedScan(t, pool, projectID)
	moved := sampleFinding(projectID)
	moved.Fingerprint, moved.Scanner, moved.Severity = "fp-trivy-a", "trivy", domain.SeverityHigh
	moved.PackageName, moved.Category = "log4j-core", domain.CategorySCA
	moved.CVE, moved.LastScanID = []string{"CVE-3333"}, &scan2
	if _, err := repo.Upsert(ctx, moved); err != nil {
		t.Fatalf("upsert moved: %v", err)
	}
	// ...and grype's b1 (group B's primary) is no longer reported, so it closes.
	closed, err := repo.CloseMissing(ctx, projectID, "grype", scan2)
	if err != nil {
		t.Fatalf("close missing: %v", err)
	}
	if len(closed) != 3 { // grype-a, grype-b1, grype-b2 were all last seen in scan1
		t.Fatalf("closed %d grype findings, want 3", len(closed))
	}

	if _, err := repo.DeduplicateScan(ctx, projectID, scan2, closed); err != nil {
		t.Fatalf("incremental dedup: %v", err)
	}
	incremental := grouping(t, pool, projectID)

	// The full recompute is the oracle: it must agree, row for row.
	if _, err := repo.Deduplicate(ctx, projectID); err != nil {
		t.Fatalf("full dedup: %v", err)
	}
	full := grouping(t, pool, projectID)

	if !maps.Equal(incremental, full) {
		t.Errorf("incremental dedup diverged from a full recompute:\n incremental: %v\n full:        %v", incremental, full)
	}
	// And it is actually right: the moved finding left group A, so nothing is a
	// duplicate any more.
	if d := incremental[trivyA.ID]; d != "" {
		t.Errorf("moved finding still marked duplicate_of=%s", d)
	}
	if d := incremental[grypeA.ID]; d != "" {
		t.Errorf("group A has one member left, so it must not be a duplicate (got %s)", d)
	}
}

// grouping snapshots each finding's duplicate_of ("" when it is a primary).
func grouping(t *testing.T, pool *pgxpool.Pool, projectID string) map[string]string {
	t.Helper()
	rows, err := pool.Query(context.Background(),
		`SELECT id, COALESCE(duplicate_of::text, '') FROM findings WHERE project_id = $1`, projectID)
	if err != nil {
		t.Fatalf("grouping: %v", err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, dup string
		if err := rows.Scan(&id, &dup); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[id] = dup
	}
	return out
}
