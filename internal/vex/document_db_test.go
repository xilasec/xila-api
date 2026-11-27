package vex_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/vex"
)

func newDocsRepo(pool *pgxpool.Pool) *vex.DocumentRepository {
	return vex.NewDocumentRepository(pool, vex.NewRepository(pool))
}

// TestDocumentPublishOnlyAddsRevisionOnChange is the correctness trap the
// brief calls out: publishing twice with nothing changed must not grow the
// revision history (the comparison hash would otherwise always differ,
// because the frozen document's own revision history and version number grow
// on every publish). A real change (here, remediating the finding) must
// append exactly one new revision with an incremented tracking version.
func TestDocumentPublishOnlyAddsRevisionOnChange(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findingRepo := finding.NewRepository(pool)
	projectID := seedVexProject(t, pool, "docs-nochange")
	f, err := findingRepo.Upsert(ctx, finding.Finding{
		ProjectID: projectID, Fingerprint: "a", Scanner: "trivy", Category: domain.CategorySCA,
		Severity: domain.SeverityHigh, Title: "x", RuleID: "CVE-2024-9001", CVE: []string{"CVE-2024-9001"}, Purl: "pkg:npm/a@1",
	})
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}

	repo := newDocsRepo(pool)
	svc := vex.NewDocumentService(repo, nil, "TESTDOC")
	doc, err := svc.Create(ctx, "u1", true, vex.Document{
		Format: vex.FormatOpenVEX, ScopeKind: vex.ScopeProject, ProjectID: projectID, Targets: []vex.Target{{}},
	}, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if doc.Version != 0 || doc.PublishedAt != nil {
		t.Fatalf("new document version=%d published_at=%v, want unpublished", doc.Version, doc.PublishedAt)
	}

	doc, changed, err := svc.Publish(ctx, "u1", true, doc.ID)
	if err != nil {
		t.Fatalf("publish 1: %v", err)
	}
	if !changed || doc.Version != 1 || len(doc.Revisions) != 1 {
		t.Fatalf("publish 1: changed=%v version=%d revisions=%d, want true 1 1", changed, doc.Version, len(doc.Revisions))
	}
	firstPublishedAt := doc.PublishedAt

	// Publish again with nothing changed: no new revision, no version bump.
	doc, changed, err = svc.Publish(ctx, "u1", true, doc.ID)
	if err != nil {
		t.Fatalf("publish 2 (no change): %v", err)
	}
	if changed {
		t.Errorf("publish with no underlying change reported changed = true, want false")
	}
	if doc.Version != 1 || len(doc.Revisions) != 1 {
		t.Errorf("after unchanged publish: version=%d revisions=%d, want 1 1 (no growth)", doc.Version, len(doc.Revisions))
	}
	if doc.PublishedAt == nil || !doc.PublishedAt.Equal(*firstPublishedAt) {
		t.Errorf("published_at moved on an unchanged publish: %v -> %v", firstPublishedAt, doc.PublishedAt)
	}

	// A real change (remediate the finding) must produce a new revision.
	if _, err := findingRepo.SetStatus(ctx, f.ID, finding.Triage{Status: domain.FindingRemediated, Actor: "test"}); err != nil {
		t.Fatalf("set status: %v", err)
	}
	doc, changed, err = svc.Publish(ctx, "u1", true, doc.ID)
	if err != nil {
		t.Fatalf("publish 3 (changed): %v", err)
	}
	if !changed || doc.Version != 2 || len(doc.Revisions) != 2 {
		t.Fatalf("publish after a real change: changed=%v version=%d revisions=%d, want true 2 2", changed, doc.Version, len(doc.Revisions))
	}

	revs, err := svc.ListRevisions(ctx, "u1", true, doc.ID)
	if err != nil || len(revs) != 2 {
		t.Fatalf("list revisions: %v %d, want 2", err, len(revs))
	}
	content1, _, err := svc.RevisionContent(ctx, "u1", true, doc.ID, 1)
	if err != nil {
		t.Fatalf("revision 1 content: %v", err)
	}
	content2, _, err := svc.RevisionContent(ctx, "u1", true, doc.ID, 2)
	if err != nil {
		t.Fatalf("revision 2 content: %v", err)
	}
	if string(content1) == string(content2) {
		t.Errorf("revision 1 and 2 content are identical, want the remediated status reflected")
	}

	// Round-trip: revision 2's OpenVEX content imports back as a statement
	// matching the current (fixed) verdict.
	stmts, err := vex.Parse(content2)
	if err != nil {
		t.Fatalf("parse revision 2: %v", err)
	}
	if len(stmts) != 1 || stmts[0].VulnID != "CVE-2024-9001" || stmts[0].Status != vex.StatusFixed {
		t.Errorf("round-trip parse of revision 2 = %+v, want one CVE-2024-9001 statement with status fixed", stmts)
	}
}

// TestDocumentVersionsScope merges several of one project's versions into one
// document — a finding unique to a feature branch only shows up once that
// branch is one of the document's targets.
func TestDocumentVersionsScope(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findingRepo := finding.NewRepository(pool)
	projectID := seedVexProject(t, pool, "docs-versions")

	var featureID string
	if err := pool.QueryRow(ctx, `SELECT project_version($1, '', 'branch'), project_version($1, 'feature/x', 'branch')`,
		projectID).Scan(new(string), &featureID); err != nil {
		t.Fatalf("versions: %v", err)
	}
	for _, f := range []finding.Finding{
		{Fingerprint: "a", RuleID: "CVE-2024-1000", CVE: []string{"CVE-2024-1000"}, Purl: "pkg:npm/a@1"},
		{Fingerprint: "b", RuleID: "GHSA-aaaa-bbbb-cccc", Purl: "pkg:npm/b@1", VersionID: featureID},
	} {
		f.ProjectID, f.Scanner, f.Category, f.Severity, f.Title = projectID, "trivy", domain.CategorySCA, domain.SeverityLow, "x"
		if _, err := findingRepo.Upsert(ctx, f); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}

	repo := newDocsRepo(pool)
	svc := vex.NewDocumentService(repo, nil, "TESTDOC")
	doc, err := svc.Create(ctx, "u1", true, vex.Document{
		Format: vex.FormatOpenVEX, ScopeKind: vex.ScopeVersions, ProjectID: projectID,
		Targets: []vex.Target{{}, {Branch: "feature/x"}},
	}, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	doc, changed, err := svc.Publish(ctx, "u1", true, doc.ID)
	if err != nil || !changed {
		t.Fatalf("publish: changed=%v err=%v", changed, err)
	}
	content, _, err := svc.RevisionContent(ctx, "u1", true, doc.ID, doc.Version)
	if err != nil {
		t.Fatalf("content: %v", err)
	}
	stmts, err := vex.Parse(content)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	var names []string
	for _, s := range stmts {
		names = append(names, s.VulnID)
	}
	if len(stmts) != 2 {
		t.Errorf("versions-scope statements = %v, want both CVE-2024-1000 and GHSA-aaaa-bbbb-cccc", names)
	}
}

// TestDocumentVulnerabilityScopeSpansProjects: an admin-only vulnerability-
// scope document aggregates every project's analysis of one CVE, and
// round-trips through our own importer.
func TestDocumentVulnerabilityScopeSpansProjects(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findingRepo := finding.NewRepository(pool)
	projectA := seedVexProject(t, pool, "docs-vuln-a")
	projectB := seedVexProject(t, pool, "docs-vuln-b")
	for _, pid := range []string{projectA, projectB} {
		if _, err := findingRepo.Upsert(ctx, finding.Finding{
			ProjectID: pid, Fingerprint: "shared", Scanner: "trivy", Category: domain.CategorySCA,
			Severity: domain.SeverityCritical, Title: "shared CVE", RuleID: "CVE-2024-5555",
			CVE: []string{"CVE-2024-5555"}, Purl: "pkg:npm/shared@1",
		}); err != nil {
			t.Fatalf("seed finding in %s: %v", pid, err)
		}
	}

	repo := newDocsRepo(pool)
	svc := vex.NewDocumentService(repo, nil, "TESTDOC")
	doc, err := svc.Create(ctx, "admin", true, vex.Document{
		Format: vex.FormatOpenVEX, ScopeKind: vex.ScopeVulnerability, VulnID: "cve-2024-5555",
	}, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if doc.VulnID != "CVE-2024-5555" {
		t.Errorf("vuln_id = %q, want uppercased CVE-2024-5555", doc.VulnID)
	}

	doc, changed, err := svc.Publish(ctx, "admin", true, doc.ID)
	if err != nil || !changed {
		t.Fatalf("publish: changed=%v err=%v", changed, err)
	}
	content, _, err := svc.RevisionContent(ctx, "admin", true, doc.ID, doc.Version)
	if err != nil {
		t.Fatalf("content: %v", err)
	}
	stmts, err := vex.Parse(content)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(stmts) != 1 || stmts[0].VulnID != "CVE-2024-5555" {
		t.Fatalf("parsed statements = %+v, want one merged CVE-2024-5555 statement (same product in both projects)", stmts)
	}

	// Non-admin creation of a vulnerability-scope document is forbidden.
	if _, err := svc.Create(ctx, "nobody", false, vex.Document{
		Format: vex.FormatOpenVEX, ScopeKind: vex.ScopeVulnerability, VulnID: "CVE-2024-5555",
	}, nil); err == nil {
		t.Error("non-admin created a vulnerability-scope document, want forbidden")
	}
}
