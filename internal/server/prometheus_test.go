package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/observability"
)

// scrape GETs /metrics with an optional bearer token.
func scrape(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
}, token string) (int, string) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := app.Test(r, -1)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

// METRICS_ENABLED exposes every OpenTelemetry instrument in the Prometheus
// format — HTTP requests labelled by route template (never the raw path, which
// would explode cardinality with ids), job runs, and the outbox backlog —
// behind METRICS_TOKEN; off, /metrics doesn't exist.
func TestPrometheusMetrics(t *testing.T) {
	off := newTestApp(t)
	if code, _ := scrape(t, off, ""); code != http.StatusNotFound {
		t.Fatalf("metrics disabled: /metrics = %d, want 404", code)
	}

	app := newTestApp(t, func(c *config.Config) {
		c.Metrics = config.Metrics{Enabled: true, Token: "scrape-secret"}
	})
	if code, _ := scrape(t, app, ""); code != http.StatusUnauthorized {
		t.Fatalf("no token: %d, want 401", code)
	}
	if code, _ := scrape(t, app, "wrong"); code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d, want 401", code)
	}

	// Traffic with ids in the path, plus a job run.
	token := rbacUser(t, app, "founder@xila.io")
	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", token, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", token, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)
	_, project := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", token, `{"slug":"metered","name":"Metered"}`)
	id, _ := project["id"].(string)
	if id == "" {
		t.Fatalf("create project: %v", project)
	}
	if res, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+id, token, ""); res.StatusCode != http.StatusOK {
		t.Fatalf("get project: %d", res.StatusCode)
	}
	observability.RecordJob(context.Background(), "test_sweep", time.Now(), nil)

	code, body := scrape(t, app, "scrape-secret")
	if code != http.StatusOK {
		t.Fatalf("scrape: %d", code)
	}
	for _, want := range []string{
		`http_route="/api/v1/projects/:projectID"`, // the route template
		`xila_job_runs_total{`, `job="test_sweep"`, `outcome="ok"`,
		`xila_job_last_success_seconds{`,
		`xila_job_duration_seconds_bucket{`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("scrape lacks %s", want)
		}
	}
	if strings.Contains(body, id) {
		t.Errorf("a raw path (project id %s) leaked into a label", id)
	}
	// The Host header is client-controlled: it must not become a label.
	if strings.Contains(body, "server_address=") {
		t.Error("server_address (from the Host header) is a label: unbounded cardinality")
	}
}
