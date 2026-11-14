package sbom

import (
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
)

// The fixtures in testdata are real CycloneDX documents, unmodified, Apache-2.0
// licensed by the CycloneDX project:
//
//   - saasbom-1.4.cdx.json: bom-examples, SaaSBOM/apigateway-microservices-datastores/bom.json
//     (https://github.com/CycloneDX/bom-examples) — legacy data {flow, classification}
//     and x-trust-boundary.
//   - saasbom-1.5.cdx.json / saasbom-1.6.cdx.json: specification,
//     tools/src/test/resources/1.{5,6}/valid-saasbom-1.{5,6}.json
//     (https://github.com/CycloneDX/specification) — 1.5+ serviceData (name,
//     governance, source/destination BOM-Links) and trustZone.
//   - service-1.6.cdx.json: specification, tools/src/test/resources/1.6/valid-service-1.6.json —
//     a component depending on a service, service licenses, every flow direction.
func parseFixture(t *testing.T, name string) Document {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	return doc
}

func byRef(svcs []BomService) map[string]BomService {
	out := map[string]BomService{}
	for _, s := range svcs {
		out[s.BomRef] = s
	}
	return out
}

func TestParseServicesLegacy14(t *testing.T) {
	doc := parseFixture(t, "saasbom-1.4.cdx.json")
	var refs []string
	for _, s := range doc.Services {
		refs = append(refs, s.BomRef)
	}
	// Nested services are flattened in document order.
	if want := []string{"api-gateway", "ms-1.example.com", "ms-2.example.com", "ms-3.example.com",
		"ms-1-pgsql.example.com", "s3-example.amazon.com"}; !slices.Equal(refs, want) {
		t.Fatalf("services = %v, want %v", refs, want)
	}
	FlagServices(doc.Services)
	s := byRef(doc.Services)

	gw := s["api-gateway"]
	if gw.ParentRef != "" || gw.Group != "com.example" || gw.Name != "API Gateway" || gw.Version != "2022-1" ||
		gw.Description != "Example API Gateway" || gw.Provider != "Acme Inc" ||
		!slices.Equal(gw.ProviderURL, []string{"https://example.com"}) ||
		!slices.Equal(gw.Endpoints, []string{"https://example.com/", "https://example.com/app"}) {
		t.Errorf("api-gateway = %+v", gw)
	}
	if gw.Authenticated == nil || *gw.Authenticated || gw.TrustBoundary == nil || !*gw.TrustBoundary || gw.TrustZone != "" {
		t.Errorf("api-gateway auth/boundary = %v/%v zone %q, want false/true", gw.Authenticated, gw.TrustBoundary, gw.TrustZone)
	}
	if got := dataClasses(gw.Data); !slices.Equal(got, []DataClass{
		{"bi-directional", "PIFI"}, {"bi-directional", "PII"}, {"bi-directional", "Public"}}) {
		t.Errorf("api-gateway data = %v", got)
	}
	if len(gw.ExternalRefs) != 1 || gw.ExternalRefs[0] != (ExternalRef{Type: "documentation", URL: "http://example.com/app/swagger"}) {
		t.Errorf("api-gateway external refs = %+v", gw.ExternalRefs)
	}
	// The unauthenticated, internet-facing gateway is the one to worry about.
	if !gw.UnauthenticatedExternal || !gw.CrossesTrustBoundary {
		t.Errorf("api-gateway flags = unauth %v crosses %v, want both", gw.UnauthenticatedExternal, gw.CrossesTrustBoundary)
	}

	ms1 := s["ms-1.example.com"]
	if ms1.ParentRef != "api-gateway" || ms1.Authenticated == nil || !*ms1.Authenticated ||
		ms1.UnauthenticatedExternal || ms1.CrossesTrustBoundary {
		t.Errorf("ms-1 = parent %q auth %v flags %v/%v", ms1.ParentRef, ms1.Authenticated, ms1.UnauthenticatedExternal, ms1.CrossesTrustBoundary)
	}
	if pg := s["ms-1-pgsql.example.com"]; pg.Provider != "" || len(pg.ProviderURL) != 0 || pg.ParentRef != "api-gateway" {
		t.Errorf("pgsql = %+v, want no provider, nested under the gateway", pg)
	}
	if s3 := s["s3-example.amazon.com"]; !s3.CrossesTrustBoundary || s3.UnauthenticatedExternal {
		t.Errorf("s3 flags = crosses %v unauth %v, want x-trust-boundary to count", s3.CrossesTrustBoundary, s3.UnauthenticatedExternal)
	}

	// Service nodes take part in the dependency graph like components.
	for _, want := range []Edge{{"acme-application", "api-gateway"}, {"api-gateway", "ms-1.example.com"},
		{"ms-3.example.com", "s3-example.amazon.com"}} {
		if !slices.Contains(doc.Edges, want) {
			t.Errorf("edge %v missing from %v", want, doc.Edges)
		}
	}
	if doc.RootRef != "acme-application" || len(doc.Components) != 0 {
		t.Errorf("root %q, %d components", doc.RootRef, len(doc.Components))
	}
}

func TestParseServicesDataflow(t *testing.T) {
	for _, name := range []string{"saasbom-1.5.cdx.json", "saasbom-1.6.cdx.json"} {
		t.Run(name, func(t *testing.T) {
			doc := parseFixture(t, name)
			if len(doc.Services) != 6 {
				t.Fatalf("%d services, want 6", len(doc.Services))
			}
			FlagServices(doc.Services)
			s := byRef(doc.Services)

			st := s["stock-ticker-service"]
			if st.TrustZone != "Acme Public Zone" || st.TrustBoundary != nil || len(st.Data) != 4 {
				t.Fatalf("stock ticker = zone %q boundary %v, %d flows", st.TrustZone, st.TrustBoundary, len(st.Data))
			}
			d := st.Data[1]
			if d.Name != "Stock Service to MS-1" || d.Description != "Traffic to/from stock service to microservice-1" ||
				d.Classification != "PII" || d.Flow != "bi-directional" ||
				!slices.Equal(d.Source, []string{"urn:cdx:3e671687-395b-41f5-a30f-a58921a69b79/1#ms-1.example.com"}) ||
				!slices.Equal(d.Destination, d.Source) {
				t.Errorf("flow = %+v", d)
			}
			// Public zone → private zone crosses; a flow to an outside URL has no
			// known zone and doesn't.
			if st.Data[0].CrossesTrustZone || !st.Data[1].CrossesTrustZone || !st.CrossesTrustBoundary {
				t.Errorf("stock ticker crossings = %v/%v, service %v", st.Data[0].CrossesTrustZone, st.Data[1].CrossesTrustZone, st.CrossesTrustBoundary)
			}

			ms1 := s["ms-1.example.com"]
			if ms1.ParentRef != "stock-ticker-service" || ms1.TrustZone != "Acme Private Zone" {
				t.Errorf("ms-1 parent %q zone %q", ms1.ParentRef, ms1.TrustZone)
			}
			var gov struct {
				Owners []struct {
					Organization struct{ Name string }
				}
			}
			if err := json.Unmarshal(ms1.Data[0].Governance, &gov); err != nil || len(gov.Owners) != 1 ||
				gov.Owners[0].Organization.Name != "Customer Name" {
				t.Errorf("ms-1 governance = %s (%v)", ms1.Data[0].Governance, err)
			}
			// ms-1 ↔ its database stay in the private zone.
			if !ms1.Data[0].CrossesTrustZone || ms1.Data[1].CrossesTrustZone {
				t.Errorf("ms-1 crossings = %v/%v, want stock-ticker only", ms1.Data[0].CrossesTrustZone, ms1.Data[1].CrossesTrustZone)
			}
			if pg := s["ms-1-pgsql.example.com"]; pg.CrossesTrustBoundary {
				t.Error("the database only talks to ms-1 in its own zone, yet crosses a boundary")
			}
			if s3 := s["s3-example.amazon.com"]; s3.TrustZone != "Public Internet" || !s3.CrossesTrustBoundary ||
				s3.Data[0].Flow != "inbound" || s3.Data[0].Destination != nil {
				t.Errorf("s3 = zone %q crosses %v data %+v", s3.TrustZone, s3.CrossesTrustBoundary, s3.Data)
			}
			for _, sv := range doc.Services {
				if sv.UnauthenticatedExternal {
					t.Errorf("%s flagged unauthenticated, but every service authenticates", sv.BomRef)
				}
			}
		})
	}
}

func TestParseServiceLicensesAndComponentEdge(t *testing.T) {
	doc := parseFixture(t, "service-1.6.cdx.json")
	if len(doc.Services) != 1 || len(doc.Components) != 1 {
		t.Fatalf("%d services / %d components", len(doc.Services), len(doc.Components))
	}
	sv := doc.Services[0]
	if sv.License != "Partner license" || sv.Provider != "Partner Org" || len(sv.ExternalRefs) != 2 {
		t.Errorf("service = %+v", sv)
	}
	var flows []string
	for _, d := range sv.Data {
		flows = append(flows, d.Flow+":"+d.Classification)
	}
	if want := []string{"inbound:PII", "outbound:PIFI", "bi-directional:public", "unknown:partner-data"}; !slices.Equal(flows, want) {
		t.Errorf("flows = %v, want %v", flows, want)
	}
	if want := (Edge{"pkg:maven/com.acme/stock-java-client@1.0.12", "b2a46a4b-8367-4bae-9820-95557cfe03a8"}); !slices.Contains(doc.Edges, want) {
		t.Errorf("component → service edge missing: %v", doc.Edges)
	}
	FlagServices(doc.Services)
	if !doc.Services[0].CrossesTrustBoundary || doc.Services[0].UnauthenticatedExternal {
		t.Errorf("flags = %+v", doc.Services[0])
	}
}

func TestFlattenServicesEdgeCases(t *testing.T) {
	doc, err := Parse([]byte(`{"bomFormat": "CycloneDX", "specVersion": "1.2", "services": [
	  {"name": "gateway", "authenticated": false, "endpoints": ["tcp://10.0.0.1:9000"],
	   "data": [{"flow": "Inbound", "classification": "PII"}, {"flow": "sideways", "classification": "x"}],
	   "services": [{"bom-ref": "inner", "name": "inner", "endpoints": ["HTTP://inner.local"], "authenticated": false}]},
	  {"bom-ref": "nameless-is-dropped"}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Services) != 2 {
		t.Fatalf("services = %+v", doc.Services)
	}
	gw, inner := doc.Services[0], doc.Services[1]
	// A ref-less parent gets a synthetic ref so its children stay attached.
	if gw.BomRef == "" || inner.ParentRef != gw.BomRef {
		t.Errorf("gateway ref %q, inner parent %q", gw.BomRef, inner.ParentRef)
	}
	if gw.Data[0].Flow != "inbound" || gw.Data[1].Flow != "unknown" {
		t.Errorf("flows = %+v, want normalized", gw.Data)
	}
	FlagServices(doc.Services)
	// Unauthenticated over raw TCP isn't an http(s) exposure; over HTTP it is.
	if doc.Services[0].UnauthenticatedExternal || !doc.Services[1].UnauthenticatedExternal {
		t.Errorf("unauthenticated flags = %v/%v", doc.Services[0].UnauthenticatedExternal, doc.Services[1].UnauthenticatedExternal)
	}
}

func TestFlagServicesResolvesPeers(t *testing.T) {
	svcs := []BomService{
		{BomRef: "web", TrustZone: "dmz", Data: []DataFlow{
			{Flow: "outbound", Destination: []string{"https://DB.internal/"}},        // by endpoint
			{Flow: "outbound", Destination: []string{"urn:cdx:other/2#queue%20one"}}, // by escaped BOM-Link
			{Flow: "inbound", Source: []string{"web"}},                               // itself: same zone
		}},
		{BomRef: "db", TrustZone: "core", Endpoints: []string{"https://db.internal"}},
		{BomRef: "queue one", TrustZone: "dmz"},
		{BomRef: "zoneless", Data: []DataFlow{{Flow: "outbound", Destination: []string{"db"}}}},
	}
	FlagServices(svcs)
	got := []bool{svcs[0].Data[0].CrossesTrustZone, svcs[0].Data[1].CrossesTrustZone, svcs[0].Data[2].CrossesTrustZone}
	if !slices.Equal(got, []bool{true, false, false}) || !svcs[0].CrossesTrustBoundary {
		t.Errorf("web crossings = %v (service %v), want [true false false]", got, svcs[0].CrossesTrustBoundary)
	}
	// A service with no zone of its own can't be judged to cross into another.
	if svcs[3].CrossesTrustBoundary {
		t.Error("zoneless service flagged as crossing")
	}
}

func TestDiffServices(t *testing.T) {
	yes, no := new(true), new(false)
	base := []BomService{
		{BomRef: "a", Group: "acme", Name: "Payments", Version: "1", Endpoints: []string{"https://pay/v1"},
			Authenticated: yes, TrustZone: "core", Data: []DataFlow{{Flow: "inbound", Classification: "PIFI"}}},
		{BomRef: "b", Name: "Legacy", Endpoints: []string{"http://legacy"}},
		{BomRef: "c", Name: "Same", Endpoints: []string{"https://same"}, Authenticated: yes},
	}
	head := []BomService{
		// bom-refs differ between documents; group/name identifies the service.
		{BomRef: "uuid-1", Group: "acme", Name: "Payments", Version: "2", Endpoints: []string{"https://pay/v2"},
			Authenticated: no, TrustBoundary: yes, TrustZone: "dmz",
			Data: []DataFlow{{Flow: "inbound", Classification: "PIFI"}, {Flow: "outbound", Classification: "PII"}}},
		{BomRef: "c", Name: "Same", Endpoints: []string{"https://same"}, Authenticated: yes},
		{BomRef: "d", Name: "Search", Endpoints: []string{"https://search"}, Data: []DataFlow{{Flow: "inbound", Classification: "Public"}}},
	}
	ds := DiffServices(base, head)
	got := map[string]ServiceDiff{}
	for _, d := range ds {
		got[d.Name] = d
	}
	if len(ds) != 3 {
		t.Fatalf("diff = %+v, want Payments changed, Legacy removed, Search added", ds)
	}
	p := got["Payments"]
	if p.Change != ChangeChanged ||
		!slices.Equal(p.Fields, []string{"version", "endpoints", "authenticated", "trust_boundary", "trust_zone", "data"}) ||
		!slices.Equal(p.EndpointsAdded, []string{"https://pay/v2"}) || !slices.Equal(p.EndpointsRemoved, []string{"https://pay/v1"}) ||
		*p.AuthenticatedFrom != true || *p.AuthenticatedTo != false || p.TrustBoundaryFrom != nil || !*p.TrustBoundaryTo ||
		p.TrustZoneFrom != "core" || p.TrustZoneTo != "dmz" ||
		!slices.Equal(p.DataAdded, []DataClass{{"outbound", "PII"}}) || len(p.DataRemoved) != 0 {
		t.Errorf("payments = %+v", p)
	}
	if l := got["Legacy"]; l.Change != ChangeRemoved || !slices.Equal(l.EndpointsRemoved, []string{"http://legacy"}) {
		t.Errorf("legacy = %+v", l)
	}
	if s := got["Search"]; s.Change != ChangeAdded || !slices.Equal(s.DataAdded, []DataClass{{"inbound", "Public"}}) {
		t.Errorf("search = %+v", s)
	}
	var sum DiffSummary
	sum.countServices(ds)
	if sum.ServicesAdded != 1 || sum.ServicesRemoved != 1 || sum.ServicesChanged != 1 {
		t.Errorf("summary = %+v", sum)
	}
	b, _ := json.Marshal(DiffServices(nil, nil))
	if string(b) != "[]" {
		t.Errorf("empty diff = %s, want []", b)
	}
}

func TestSPDXHasNoServices(t *testing.T) {
	doc, err := Parse([]byte(`{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "x", "packages": []}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Services) != 0 || !strings.HasPrefix(doc.Format, "SPDX") {
		t.Errorf("spdx = %s with %d services", doc.Format, len(doc.Services))
	}
}
