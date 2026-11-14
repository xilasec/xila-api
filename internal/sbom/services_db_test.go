package sbom_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"slices"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/sbom"
)

func getJSON(t *testing.T, app *fiber.App, path string, out any) int {
	t.Helper()
	res, err := app.Test(httptest.NewRequest("GET", path, nil), -1)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode == 200 {
		if err := json.Unmarshal(body, out); err != nil {
			t.Fatalf("decode %s: %v (%s)", path, err, body)
		}
	}
	return res.StatusCode
}

func uploadFixture(t *testing.T, svc *sbom.Service, req sbom.IngestRequest, name string) sbom.Sbom {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s, err := svc.Ingest(context.Background(), req, f)
	if err != nil {
		t.Fatalf("ingest %s: %v", name, err)
	}
	return s
}

type servicesResp struct {
	Services []sbom.BomService `json:"services"`
	Summary  sbom.ServiceSummary
}

// TestServicesStoredPerSnapshot: services a CycloneDX upload declares are stored
// with endpoints, authentication, trust boundary/zone and data flows, listed
// per snapshot and for the project's current inventory, and their graph edges
// connect to typed service nodes.
func TestServicesStoredPerSnapshot(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := sbom.NewRepository(pool)
	svc := sbom.NewService(repo, project.NewRepository(pool), nil, nil)
	app := fiber.New()
	sbom.NewHandler(repo, svc).Register(app)

	projectID := seedProject(t, pool, "saas")
	snap := uploadFixture(t, svc, sbom.IngestRequest{ProjectID: projectID}, "saasbom-1.4.cdx.json")

	var got servicesResp
	if code := getJSON(t, app, "/sboms/"+snap.ID+"/services", &got); code != 200 {
		t.Fatalf("services = %d", code)
	}
	if len(got.Services) != 6 || got.Summary != (sbom.ServiceSummary{Total: 6, UnauthenticatedExternal: 1, CrossesTrustBoundary: 2}) {
		t.Fatalf("services = %d, summary %+v", len(got.Services), got.Summary)
	}
	gw := got.Services[0] // document order
	if gw.BomRef != "api-gateway" || gw.SbomID != snap.ID || gw.ProjectID != projectID || gw.Artifact != "Acme Cloud Example" ||
		gw.Provider != "Acme Inc" || !slices.Equal(gw.Endpoints, []string{"https://example.com/", "https://example.com/app"}) ||
		gw.Authenticated == nil || *gw.Authenticated || gw.TrustBoundary == nil || !*gw.TrustBoundary ||
		len(gw.Data) != 3 || gw.Data[0].Classification != "PII" || gw.Data[0].Flow != "bi-directional" ||
		!gw.UnauthenticatedExternal || !gw.CrossesTrustBoundary {
		t.Errorf("gateway = %+v", gw)
	}
	if pg := got.Services[4]; pg.Name != "Postgres" || pg.ParentRef != "api-gateway" || pg.Authenticated == nil || !*pg.Authenticated ||
		pg.TrustBoundary == nil || *pg.TrustBoundary || pg.CrossesTrustBoundary {
		t.Errorf("postgres = %+v", pg)
	}

	// The project's current services: the newest snapshot of the default version.
	var proj servicesResp
	if code := getJSON(t, app, "/projects/"+projectID+"/services", &proj); code != 200 || len(proj.Services) != 6 {
		t.Fatalf("project services = %d, %d services", code, len(proj.Services))
	}
	// A release snapshot doesn't change what the default version ships.
	rel := uploadFixture(t, svc, sbom.IngestRequest{ProjectID: projectID, Release: "v2"}, "service-1.6.cdx.json")
	if code := getJSON(t, app, "/projects/"+projectID+"/services", &proj); code != 200 || len(proj.Services) != 6 {
		t.Errorf("default services after a release upload = %d", len(proj.Services))
	}
	if code := getJSON(t, app, "/projects/"+projectID+"/services?release=v2", &proj); code != 200 ||
		len(proj.Services) != 1 || proj.Services[0].SbomID != rel.ID || proj.Services[0].Name != "Stock ticker service" {
		t.Errorf("release services = %d %+v", code, proj.Services)
	}
	if code := getJSON(t, app, "/projects/"+projectID+"/services?branch=nope", &proj); code != 404 {
		t.Errorf("unknown branch = %d, want 404", code)
	}
	empty := seedProject(t, pool, "empty")
	var none map[string]json.RawMessage
	if code := getJSON(t, app, "/projects/"+empty+"/services", &none); code != 200 || string(none["services"]) != "[]" {
		t.Errorf("project without sboms = %d %s, want []", code, none["services"])
	}

	// Graph: service refs are typed nodes, not "missing" components.
	var g sbom.Graph
	if code := getJSON(t, app, "/sboms/"+snap.ID+"/graph", &g); code != 200 {
		t.Fatalf("graph = %d", code)
	}
	kinds := map[string]string{}
	for _, n := range g.Nodes {
		if n.Missing {
			t.Errorf("node %s is missing", n.Ref)
		}
		kinds[n.Ref] = n.Kind
	}
	if kinds["api-gateway"] != "service" || kinds["s3-example.amazon.com"] != "service" || len(g.Edges) != 6 {
		t.Errorf("graph kinds = %v, %d edges", kinds, len(g.Edges))
	}

	// Deleting the snapshot takes its services with it.
	if _, err := pool.Exec(context.Background(), `DELETE FROM sboms WHERE id = $1`, snap.ID); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := pool.QueryRow(context.Background(), `SELECT count(*) FROM sbom_services WHERE sbom_id = $1`, snap.ID).Scan(&n); err != nil || n != 0 {
		t.Errorf("services left after delete = %d (%v)", n, err)
	}
}

// TestServicesDiff: the diff between two releases reports how a service's data
// classifications changed (the 1.5 → 1.6 spec samples differ in exactly one:
// S3 now receives PII where it received Public data).
func TestServicesDiff(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := sbom.NewRepository(pool)
	svc := sbom.NewService(repo, project.NewRepository(pool), nil, nil)
	app := fiber.New()
	sbom.NewHandler(repo, svc).Register(app)

	projectID := seedProject(t, pool, "diff")
	v1 := uploadFixture(t, svc, sbom.IngestRequest{ProjectID: projectID}, "saasbom-1.5.cdx.json")
	v2 := uploadFixture(t, svc, sbom.IngestRequest{ProjectID: projectID}, "saasbom-1.6.cdx.json")

	var d sbom.Diff
	if code := getJSON(t, app, "/sboms/"+v2.ID+"/diff", &d); code != 200 {
		t.Fatalf("diff = %d", code)
	}
	if d.Base == nil || d.Base.ID != v1.ID || len(d.Services) != 1 {
		t.Fatalf("diff base %v, services %+v", d.Base, d.Services)
	}
	s3 := d.Services[0]
	if s3.Name != "S3" || s3.Change != sbom.ChangeChanged || !slices.Equal(s3.Fields, []string{"data"}) ||
		!slices.Equal(s3.DataAdded, []sbom.DataClass{{Flow: "inbound", Classification: "PII"}}) ||
		!slices.Equal(s3.DataRemoved, []sbom.DataClass{{Flow: "inbound", Classification: "Public"}}) {
		t.Errorf("s3 diff = %+v", s3)
	}
	if d.Summary.ServicesChanged != 1 || d.Summary.ServicesAdded != 0 || d.Summary.ServicesRemoved != 0 {
		t.Errorf("summary = %+v", d.Summary)
	}

	// Against the 1.4 gateway layout: different services entirely.
	legacy := uploadFixture(t, svc, sbom.IngestRequest{ProjectID: projectID, Artifact: "legacy"}, "saasbom-1.4.cdx.json")
	if code := getJSON(t, app, "/sboms/"+v2.ID+"/diff?base="+legacy.ID, &d); code != 200 {
		t.Fatalf("diff = %d", code)
	}
	changes := map[string]sbom.ServiceDiff{}
	for _, s := range d.Services {
		changes[s.Name] = s
	}
	if c := changes["API Gateway"]; c.Change != sbom.ChangeRemoved {
		t.Errorf("api gateway = %+v, want removed", c)
	}
	if c := changes["Stock Ticker Service"]; c.Change != sbom.ChangeAdded || c.TrustZoneTo != "Acme Public Zone" {
		t.Errorf("stock ticker = %+v, want added in the public zone", c)
	}
	// Same microservice, now zoned and with named flows: trust_boundary went
	// from false to unstated, the zone appeared.
	if c := changes["Microservice 1"]; c.Change != sbom.ChangeChanged ||
		!slices.Equal(c.Fields, []string{"trust_boundary", "trust_zone"}) || c.TrustZoneTo != "Acme Private Zone" {
		t.Errorf("microservice 1 = %+v", c)
	}
	if d.Summary.ServicesAdded != 1 || d.Summary.ServicesRemoved != 1 {
		t.Errorf("summary = %+v", d.Summary)
	}
}
