package sbom_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/sbom"
)

// An npm app: web → express → (qs, debug), web → lodash; jest is dev-only.
// express calls the payments API (which calls a nested fraud check); a ref-less
// metrics service sits unconnected.
const exportSource = `{
  "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "metadata": {"component": {"bom-ref": "pkg:npm/web@1.2.0", "type": "application", "name": "web", "version": "1.2.0"}},
  "components": [
    {"bom-ref": "pkg:npm/express@4.17.1", "type": "library", "name": "express", "version": "4.17.1",
     "purl": "pkg:npm/express@4.17.1", "scope": "required", "licenses": [{"license": {"id": "MIT"}}],
     "hashes": [{"alg": "SHA-512", "content": "abcd"}]},
    {"bom-ref": "pkg:npm/qs@6.7.0", "type": "library", "name": "qs", "version": "6.7.0",
     "purl": "pkg:npm/qs@6.7.0", "licenses": [{"expression": "BSD-3-Clause OR MIT"}]},
    {"bom-ref": "pkg:npm/debug@2.6.9", "type": "library", "name": "debug", "version": "2.6.9",
     "purl": "pkg:npm/debug@2.6.9", "evidence": {"occurrences": [{"location": "node_modules/debug/package.json"}]}},
    {"bom-ref": "pkg:npm/lodash@4.17.15", "type": "library", "name": "lodash", "version": "4.17.15",
     "purl": "pkg:npm/lodash@4.17.15"},
    {"bom-ref": "pkg:npm/%40jest/core@29.0.0", "type": "library", "group": "@jest", "name": "core",
     "version": "29.0.0", "purl": "pkg:npm/%40jest/core@29.0.0", "scope": "excluded"}
  ],
  "services": [
    {"bom-ref": "payments-api", "provider": {"name": "Acme Inc", "url": ["https://acme.example"]},
     "group": "com.acme", "name": "payments", "version": "3", "description": "Card payments",
     "endpoints": ["https://pay.acme.example/v3"], "authenticated": true, "x-trust-boundary": true,
     "trustZone": "partner", "licenses": [{"license": {"name": "Acme EULA"}}],
     "data": [{"name": "card data", "description": "PAN in, token out", "classification": "PCI", "flow": "inbound",
               "governance": {"owners": [{"organization": {"name": "Acme Inc"}}]},
               "source": ["urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#pkg:npm/web@1.2.0"]},
              {"classification": "token", "flow": "outbound"}],
     "externalReferences": [{"type": "documentation", "url": "https://pay.acme.example/docs"}],
     "properties": [{"name": "acme:tier", "value": "gold"}],
     "services": [
       {"bom-ref": "fraud-check", "name": "fraud-check", "endpoints": ["https://fraud.internal"],
        "authenticated": false, "trustZone": "core", "data": [{"classification": "PII", "flow": "bi-directional"}]}
     ]},
    {"name": "metrics", "endpoints": ["udp://metrics:8125"]}
  ],
  "dependencies": [
    {"ref": "pkg:npm/web@1.2.0", "dependsOn": ["pkg:npm/express@4.17.1", "pkg:npm/lodash@4.17.15", "pkg:npm/%40jest/core@29.0.0"]},
    {"ref": "pkg:npm/express@4.17.1", "dependsOn": ["pkg:npm/qs@6.7.0", "pkg:npm/debug@2.6.9", "payments-api"]},
    {"ref": "payments-api", "dependsOn": ["fraud-check"]}
  ]
}`

type compKey struct {
	BomRef, Group, Name, Version, Purl, License, FilePath string
	Scope                                                 domain.DepScope
	Hashes                                                string
	Depth                                                 int
}

func inventory(t *testing.T, repo *sbom.Repository, id string) (map[compKey]bool, []sbom.Edge) {
	t.Helper()
	ctx := context.Background()
	comps, err := repo.SnapshotComponents(ctx, id)
	if err != nil {
		t.Fatalf("components: %v", err)
	}
	out := map[compKey]bool{}
	for _, c := range comps {
		k := compKey{BomRef: c.BomRef, Group: c.Group, Name: c.Name, Version: c.Version, Purl: c.Purl,
			License: c.License, FilePath: c.FilePath, Scope: c.Scope, Hashes: c.Hashes["SHA-512"], Depth: -1}
		if c.Depth != nil {
			k.Depth = *c.Depth
		}
		out[k] = true
	}
	edges, err := repo.Edges(ctx, id)
	if err != nil {
		t.Fatalf("edges: %v", err)
	}
	return out, edges
}

// services returns a snapshot's services without their per-snapshot identity.
func services(t *testing.T, repo *sbom.Repository, id string) []sbom.BomService {
	t.Helper()
	svcs, err := repo.SnapshotServices(context.Background(), id)
	if err != nil {
		t.Fatalf("services: %v", err)
	}
	for i := range svcs {
		s := &svcs[i]
		s.ID, s.SbomID, s.ProjectID = "", "", ""
		s.CreatedAt = time.Time{}
	}
	return svcs
}

// TestCycloneDXExportRoundTrips: a snapshot exports as a CycloneDX 1.6 BOM with
// its vulnerabilities and the project's analysis, and the export re-uploads to
// exactly the same inventory and dependency graph.
func TestCycloneDXExportRoundTrips(t *testing.T) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	repo := sbom.NewRepository(pool)
	svc := sbom.NewService(repo, project.NewRepository(pool), nil, nil)
	findingRepo := finding.NewRepository(pool)

	source := seedProject(t, pool, "src")
	snap, err := svc.Ingest(ctx, sbom.IngestRequest{ProjectID: source}, strings.NewReader(exportSource))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	// The advisory feed matched qs and lodash; a scanner also reported the lodash
	// CVE, which the team ruled a false positive.
	if err := repo.RecordMatches(ctx, []string{snap.ID}, []sbom.SnapshotVuln{
		{SbomID: snap.ID, Purl: "pkg:npm/qs@6.7.0", VulnID: "GHSA-hrpp-h998-j3pp", CVEs: []string{"CVE-2022-24999"},
			Severity: domain.SeverityHigh, Summary: "qs prototype poisoning", FixedVersion: "6.7.3"},
		{SbomID: snap.ID, Purl: "pkg:npm/lodash@4.17.15", VulnID: "GHSA-p6mc-m468-83gw", CVEs: []string{"CVE-2020-8203"},
			Severity: domain.SeverityHigh, Summary: "lodash prototype pollution"},
	}); err != nil {
		t.Fatalf("record matches: %v", err)
	}
	f, err := findingRepo.Upsert(ctx, finding.Finding{ProjectID: source, Fingerprint: "lodash", Scanner: "trivy",
		Category: domain.CategorySCA, RuleID: "CVE-2020-8203", CVE: []string{"CVE-2020-8203"}, Title: "lodash",
		Severity: domain.SeverityHigh, PackageName: "lodash", PackageVersion: "4.17.15", Purl: "pkg:npm/lodash@4.17.15"})
	if err != nil {
		t.Fatalf("finding: %v", err)
	}
	if _, err := findingRepo.SetStatus(ctx, f.ID, finding.Triage{Status: domain.FindingFalsePositive,
		Reason: "zipObjectDeep is never called", Actor: "alice"}); err != nil {
		t.Fatalf("triage: %v", err)
	}

	app := fiber.New()
	sbom.NewHandler(repo, svc).Register(app)
	res, err := app.Test(httptest.NewRequest(http.MethodGet, "/sboms/"+snap.ID+"/export", nil), -1)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("export = %d: %s", res.StatusCode, body)
	}

	var doc struct {
		BomFormat, SpecVersion string
		Metadata               struct {
			Component struct {
				BomRef string `json:"bom-ref"`
			}
		}
		Components []struct {
			BomRef string `json:"bom-ref"`
		}
		Services []struct {
			BomRef   string `json:"bom-ref"`
			Data     []map[string]any
			Services []struct {
				BomRef string `json:"bom-ref"`
			}
		}
		Vulnerabilities []struct {
			ID       string
			Ratings  []struct{ Severity string }
			Affects  []struct{ Ref string }
			Analysis *struct{ State, Detail string }
		}
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.BomFormat != "CycloneDX" || doc.SpecVersion != "1.6" || doc.Metadata.Component.BomRef != "pkg:npm/web@1.2.0" {
		t.Errorf("header = %s %s root %q", doc.BomFormat, doc.SpecVersion, doc.Metadata.Component.BomRef)
	}
	if len(doc.Services) != 2 || doc.Services[0].BomRef != "payments-api" || len(doc.Services[0].Services) != 1 ||
		doc.Services[0].Services[0].BomRef != "fraud-check" || doc.Services[1].BomRef != "" {
		t.Fatalf("exported services = %+v, want payments-api ⊃ fraud-check, then metrics", doc.Services)
	}
	for _, d := range doc.Services[0].Data {
		if _, ok := d["crosses_trust_zone"]; ok {
			t.Errorf("exported data flow %v carries a computed field outside the CycloneDX schema", d)
		}
	}
	refs := map[string]bool{}
	for _, c := range doc.Components {
		refs[c.BomRef] = true
	}
	states := map[string]string{}
	for _, v := range doc.Vulnerabilities {
		if len(v.Ratings) == 0 || v.Ratings[0].Severity != "high" {
			t.Errorf("%s ratings = %+v", v.ID, v.Ratings)
		}
		for _, a := range v.Affects {
			if !refs[a.Ref] {
				t.Errorf("%s affects %q, which is not a component of the BOM", v.ID, a.Ref)
			}
		}
		states[v.ID] = ""
		if v.Analysis != nil {
			states[v.ID] = v.Analysis.State
			if v.Analysis.Detail != "zipObjectDeep is never called" {
				t.Errorf("analysis detail = %q", v.Analysis.Detail)
			}
		}
	}
	if want := map[string]string{"CVE-2020-8203": "not_affected", "CVE-2022-24999": ""}; !reflect.DeepEqual(states, want) {
		t.Errorf("vulnerability analysis = %v, want %v (untriaged advisory match carries none)", states, want)
	}

	// Without vulnerabilities: a plain BOM.
	res, _ = app.Test(httptest.NewRequest(http.MethodGet, "/sboms/"+snap.ID+"/export?vulnerabilities=false", nil), -1)
	plain, _ := io.ReadAll(res.Body)
	if strings.Contains(string(plain), `"vulnerabilities"`) {
		t.Error("vulnerabilities=false still exported vulnerabilities")
	}

	// Re-upload elsewhere: same components, services and graph.
	target := seedProject(t, pool, "dst")
	again, err := svc.Ingest(ctx, sbom.IngestRequest{ProjectID: target}, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("re-ingest: %v", err)
	}
	if again.RootRef != snap.RootRef || again.Artifact != snap.Artifact || again.Version != snap.Version {
		t.Errorf("re-imported subject = %q %q@%q, want %q %q@%q",
			again.RootRef, again.Artifact, again.Version, snap.RootRef, snap.Artifact, snap.Version)
	}
	wantComps, wantEdges := inventory(t, repo, snap.ID)
	gotComps, gotEdges := inventory(t, repo, again.ID)
	if !reflect.DeepEqual(gotComps, wantComps) {
		t.Errorf("components differ after round trip:\n got %v\nwant %v", gotComps, wantComps)
	}
	if !reflect.DeepEqual(gotEdges, wantEdges) {
		t.Errorf("edges differ after round trip:\n got %v\nwant %v", gotEdges, wantEdges)
	}
	if len(wantComps) != 5 || len(wantEdges) != 7 {
		t.Fatalf("source inventory = %d components / %d edges, want 5 / 7", len(wantComps), len(wantEdges))
	}
	wantSvcs, gotSvcs := services(t, repo, snap.ID), services(t, repo, again.ID)
	if !reflect.DeepEqual(gotSvcs, wantSvcs) {
		t.Errorf("services differ after round trip:\n got %+v\nwant %+v", gotSvcs, wantSvcs)
	}
	if len(wantSvcs) != 3 || wantSvcs[1].ParentRef != "payments-api" || len(wantSvcs[0].Data) != 2 ||
		len(wantSvcs[0].Data[0].Governance) == 0 || wantSvcs[0].License != "Acme EULA" ||
		!wantSvcs[0].CrossesTrustBoundary || !wantSvcs[1].UnauthenticatedExternal || wantSvcs[2].BomRef != "" {
		t.Fatalf("source services = %+v", wantSvcs)
	}
}
