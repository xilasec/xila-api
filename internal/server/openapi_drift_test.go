package server

import (
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/apidoc"
)

// TestOpenAPICoversEveryRoute is what stops the documentation from rotting.
//
// Hand-written API docs decay the moment someone adds an endpoint and forgets the
// spec — and undocumented-but-live endpoints are worse than no docs at all,
// because now the docs actively lie about what the API is. So we don't rely on
// discipline: we walk Fiber's *real* route table and fail the build in both
// directions.
//
// If this test fails, either document the route in internal/apidoc/openapi.yaml,
// or remove the stale path from it.
func TestOpenAPICoversEveryRoute(t *testing.T) {
	app := newTestApp(t) // the fully wired application

	documented, err := apidoc.Routes()
	if err != nil {
		t.Fatalf("the OpenAPI spec does not parse: %v", err)
	}

	// Routes that only exist when a feature is configured on. They are real, and
	// documented, but this test app doesn't turn them on — so their absence here is
	// not drift. Their *presence* would still have to be documented. (The SSO
	// login routes are always mounted and 404 for an unknown provider.)
	optional := map[string]bool{}

	// Fiber's route table also carries group mount points (every method against the
	// group prefix) and the HEAD twins it generates itself. Neither is an operation.
	groupMounts := map[string]bool{"/api/v1": true, "/api/v1/auth": true}

	live := map[string]bool{}
	for _, r := range app.GetRoutes() {
		if r.Method == "USE" || r.Method == http.MethodHead || r.Method == http.MethodOptions {
			continue
		}
		if groupMounts[r.Path] {
			continue
		}
		if !strings.HasPrefix(r.Path, "/api") && r.Path != "/health" && r.Path != "/ready" {
			continue // the embedded SPA's catch-all
		}
		if strings.Contains(r.Path, "openapi") {
			continue // the spec describes the API, not itself
		}
		live[r.Method+" "+r.Path] = true
	}

	if len(live) == 0 {
		t.Fatal("no live routes found — the route walker is broken, not the spec")
	}

	var undocumented, stale []string
	for route := range live {
		if !documented[route] {
			undocumented = append(undocumented, route)
		}
	}
	for route := range documented {
		if !live[route] && !optional[route] {
			stale = append(stale, route)
		}
	}
	sort.Strings(undocumented)
	sort.Strings(stale)

	for _, r := range undocumented {
		t.Errorf("route is live but UNDOCUMENTED: %s — add it to internal/apidoc/openapi.yaml", r)
	}
	for _, r := range stale {
		t.Errorf("route is DOCUMENTED but does not exist: %s — remove it from internal/apidoc/openapi.yaml", r)
	}
	if len(undocumented) == 0 && len(stale) == 0 {
		t.Logf("all %d routes documented", len(live))
	}
}
