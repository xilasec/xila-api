package vex_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/vex"
)

func seedVexProject(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-'||$1,'o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,'t-'||$1,'t' FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,$1,$1 FROM tm RETURNING id`, slug).Scan(&id); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return id
}

// exportCase is one finding, seeded identically into two projects, and the
// triage the source project gives it.
type exportCase struct {
	cve, pkg string
	triage   domain.FindingStatus // "" = left open (or triaged by VEX below)
	want     domain.FindingStatus // its status in the target after re-import
}

var exportCases = []exportCase{
	{"CVE-2024-0001", "alpha", domain.FindingFalsePositive, domain.FindingFalsePositive},
	{"CVE-2024-0002", "bravo", domain.FindingConfirmed, domain.FindingConfirmed},
	{"CVE-2024-0003", "charlie", domain.FindingRemediated, domain.FindingFalsePositive}, // fixed imports as false_positive
	{"CVE-2024-0004", "delta", "", domain.FindingOpen},                                  // under_investigation changes nothing
	{"CVE-2024-0005", "echo", domain.FindingRiskAccepted, domain.FindingConfirmed},
	{"CVE-2024-0006", "foxtrot", domain.FindingWontFix, domain.FindingConfirmed},
	{"CVE-2024-0007", "golf", "", domain.FindingFalsePositive},                   // triaged by a VEX statement
	{"CVE-2024-0008", "hotel", domain.FindingConfirmed, domain.FindingConfirmed}, // seeded without a purl
}

const upstreamVEX = `{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "statements": [{
    "vulnerability": {"name": "CVE-2024-0007"},
    "products": [{"@id": "pkg:npm/golf@1.0.0"}],
    "status": "not_affected",
    "justification": "vulnerable_code_not_present",
    "impact_statement": "The vulnerable function was removed in our fork."
  }]
}`

func purlFor(pkg string) string {
	if pkg == "hotel" {
		return "" // a scanner that reports name + version only
	}
	return "pkg:npm/" + pkg + "@1.0.0"
}

func seedCases(t *testing.T, repo *finding.Repository, projectID string) map[string]string {
	t.Helper()
	ids := map[string]string{}
	for _, c := range exportCases {
		f, err := repo.Upsert(context.Background(), finding.Finding{
			ProjectID: projectID, Fingerprint: "fp-" + c.pkg, Scanner: "trivy", Category: domain.CategorySCA,
			RuleID: c.cve, Title: "Bug in " + c.pkg, Severity: domain.SeverityHigh, CVE: []string{c.cve},
			PackageName: c.pkg, PackageVersion: "1.0.0", FixedVersion: "1.0.1", Purl: purlFor(c.pkg),
		})
		if err != nil {
			t.Fatalf("seed finding: %v", err)
		}
		ids[c.cve] = f.ID
	}
	return ids
}

// TestExportReimportsWithSameVerdicts: a project's analysis exported as OpenVEX
// or CycloneDX VEX, uploaded to another project carrying the same findings,
// lands every finding on the verdict the import semantics give it — and keeps
// the upstream justification a VEX-triaged finding came with.
func TestExportReimportsWithSameVerdicts(t *testing.T) {
	for _, tc := range []struct{ format, spec, justification string }{
		{vex.FormatOpenVEX, "", "vulnerable_code_not_present"},
		{vex.FormatCycloneDX, "", "code_not_present"},
		{vex.FormatCycloneDX, "1.7", "code_not_present"},
		{vex.FormatCSAF, "", "vulnerable_code_not_present"},
	} {
		t.Run(tc.format+tc.spec, func(t *testing.T) {
			pool := pgtest.Pool(t)
			ctx := context.Background()
			findingRepo := finding.NewRepository(pool)
			vexRepo := vex.NewRepository(pool)
			svc := vex.NewService(vexRepo, findingRepo, project.NewRepository(pool))

			source := seedVexProject(t, pool, "source")
			target := seedVexProject(t, pool, "target")
			srcIDs := seedCases(t, findingRepo, source)
			dstIDs := seedCases(t, findingRepo, target)

			for _, c := range exportCases {
				if c.triage == "" {
					continue
				}
				if c.triage == domain.FindingRiskAccepted {
					// Risk is accepted through an approved acceptance.
					a, _, err := findingRepo.CreateAcceptance(ctx, finding.AcceptanceInput{ProjectID: source,
						Title: "accept " + c.pkg, Justification: "analysed " + c.pkg, FindingIDs: []string{srcIDs[c.cve]}}, "alice@example.com")
					if err != nil {
						t.Fatalf("request acceptance: %v", err)
					}
					if _, _, err := findingRepo.ApproveAcceptance(ctx, source, a.ID, "bob@example.com", "", true); err != nil {
						t.Fatalf("approve acceptance: %v", err)
					}
					continue
				}
				if _, err := findingRepo.SetStatus(ctx, srcIDs[c.cve], finding.Triage{
					Status: c.triage, Reason: "analysed " + c.pkg, Actor: "alice@example.com"}); err != nil {
					t.Fatalf("triage: %v", err)
				}
			}
			if _, _, err := svc.Ingest(ctx, source, strings.NewReader(upstreamVEX)); err != nil {
				t.Fatalf("upstream vex: %v", err)
			}

			app := fiber.New()
			vex.NewHandler(vexRepo, svc).Register(app)
			res, err := app.Test(httptest.NewRequest("GET", "/projects/"+source+"/vex/export?format="+tc.format+"&spec="+tc.spec, nil), -1)
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			body, _ := io.ReadAll(res.Body)
			if res.StatusCode != fiber.StatusOK {
				t.Fatalf("export status %d: %s", res.StatusCode, body)
			}
			if cd := res.Header.Get(fiber.HeaderContentDisposition); !strings.Contains(cd, "attachment") {
				t.Errorf("Content-Disposition = %q, want an attachment", cd)
			}
			if tc.spec != "" && !strings.Contains(string(body), `"specVersion":"`+tc.spec+`"`) {
				t.Errorf("?spec=%s exported another version: %.200s", tc.spec, body)
			}

			if _, _, err := svc.Ingest(ctx, target, strings.NewReader(string(body))); err != nil {
				t.Fatalf("re-import: %v\n%s", err, body)
			}
			for _, c := range exportCases {
				f, err := findingRepo.Get(ctx, dstIDs[c.cve])
				if err != nil {
					t.Fatalf("get: %v", err)
				}
				if f.Status != c.want {
					t.Errorf("%s (%s at source) re-imported as %s, want %s", c.cve, c.triage, f.Status, c.want)
				}
			}
			stmts, err := vexRepo.ListByProject(ctx, target)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			var found bool
			for _, s := range stmts {
				if s.VulnID == "CVE-2024-0007" {
					found = true
					if s.Justification != tc.justification || !strings.Contains(s.Detail, "removed in our fork") {
						t.Errorf("VEX-triaged statement re-imported as %q / %q", s.Justification, s.Detail)
					}
				}
				if s.VulnID == "CVE-2024-0001" && !strings.Contains(s.Detail, "analysed alpha") {
					t.Errorf("manual false positive lost its reason: %q", s.Detail)
				}
			}
			if !found {
				t.Error("the VEX-triaged finding was not exported")
			}
		})
	}
}

// TestExportScopesToVersion: findings on another branch are not part of the
// default version's analysis, and ?branch= exports that branch instead.
func TestExportScopesToVersion(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	findingRepo := finding.NewRepository(pool)
	vexRepo := vex.NewRepository(pool)
	svc := vex.NewService(vexRepo, findingRepo, project.NewRepository(pool))
	projectID := seedVexProject(t, pool, "branchy")

	var featureID string
	if err := pool.QueryRow(ctx, `SELECT project_version($1, '', 'branch'), project_version($1, 'feature/x', 'branch')`,
		projectID).Scan(new(string), &featureID); err != nil {
		t.Fatalf("versions: %v", err)
	}
	for _, f := range []finding.Finding{
		{Fingerprint: "a", RuleID: "CVE-2024-1000", CVE: []string{"CVE-2024-1000"}, Purl: "pkg:npm/a@1"},
		{Fingerprint: "b", RuleID: "GHSA-aaaa-bbbb-cccc", Purl: "pkg:npm/b@1", VersionID: featureID},
		{Fingerprint: "c", RuleID: "semgrep.sqli"}, // no advisory id: not a VEX subject
	} {
		f.ProjectID, f.Scanner, f.Category, f.Severity, f.Title = projectID, "trivy", domain.CategorySCA, domain.SeverityLow, "x"
		if _, err := findingRepo.Upsert(ctx, f); err != nil {
			t.Fatalf("upsert: %v", err)
		}
	}

	app := fiber.New()
	vex.NewHandler(vexRepo, svc).Register(app)
	get := func(query string) (int, map[string]any) {
		res, err := app.Test(httptest.NewRequest("GET", "/projects/"+projectID+"/vex/export"+query, nil), -1)
		if err != nil {
			t.Fatalf("export: %v", err)
		}
		var doc map[string]any
		_ = json.NewDecoder(res.Body).Decode(&doc)
		return res.StatusCode, doc
	}
	vulns := func(doc map[string]any) []string {
		var out []string
		for _, s := range doc["statements"].([]any) {
			out = append(out, s.(map[string]any)["vulnerability"].(map[string]any)["name"].(string))
		}
		return out
	}

	if code, doc := get(""); code != 200 || strings.Join(vulns(doc), ",") != "CVE-2024-1000" {
		t.Errorf("default version export = %d %v, want only CVE-2024-1000", code, doc["statements"])
	}
	if code, doc := get("?branch=feature/x"); code != 200 || strings.Join(vulns(doc), ",") != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("branch export = %d %v, want only the GHSA", code, doc["statements"])
	}
	if code, _ := get("?branch=nope"); code != fiber.StatusNotFound {
		t.Errorf("unknown branch = %d, want 404", code)
	}
	if code, _ := get("?format=spdx"); code != fiber.StatusBadRequest {
		t.Errorf("unknown format = %d, want 400", code)
	}
}
