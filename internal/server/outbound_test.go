package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/netguard"
)

// Project owners — not instance admins — configure issue-tracker and connector
// URLs, and the server fetches them. They must not be able to point Xila at the
// cloud metadata service, and the Test / pull results they see must not carry
// what an internal service answered (that would turn the Test button into a
// reader for anything on the network). Admins still see the detail they need
// to debug an integration.
func TestOutboundRequestsAreGuarded(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "founder@xila.io") // first user: instance admin
	lead := rbacUser(t, app, "lead@xila.io")
	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgBody["id"].(string)+"/teams", lead, `{"slug":"core","name":"Core"}`)
	_, projBody := req(t, app, http.MethodPost, "/api/v1/teams/"+teamBody["id"].(string)+"/projects", lead, `{"slug":"alpha","name":"Alpha"}`)
	projectID := projBody["id"].(string)

	// Metadata endpoints are refused under every policy, at configuration time.
	resp, body := req(t, app, http.MethodPut, "/api/v1/projects/"+projectID+"/issue-tracker", lead,
		`{"kind":"jira","base_url":"http://169.254.169.254/latest","target":"SEC","token":"x"}`)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(fmt.Sprint(body["error"]), "not an allowed destination") {
		t.Errorf("tracker at the metadata service = %d %v, want 400", resp.StatusCode, body)
	}

	// An internal service that answers with something secret.
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "SECRET-INTERNAL-TOKEN=abc123")
	}))
	defer internal.Close()
	connPath := "/api/v1/projects/" + projectID + "/connectors"
	resp, conn := req(t, app, http.MethodPost, connPath, lead,
		`{"kind":"dependency-track","base_url":"`+internal.URL+`","remote_project":"ca4f2da9-0fad-4a13-92d7-f627f3168a56","token":"odt_x"}`)
	connID, _ := conn["id"].(string)
	if resp.StatusCode != http.StatusCreated || connID == "" {
		t.Fatalf("create connector = %d %v", resp.StatusCode, conn)
	}

	resp, body = req(t, app, http.MethodPost, connPath+"/"+connID+"/test", lead, "")
	if resp.StatusCode != http.StatusBadGateway || strings.Contains(fmt.Sprint(body), "SECRET") {
		t.Errorf("owner's Test = %d %v: want 502 without the remote's response", resp.StatusCode, body)
	}
	if !strings.Contains(fmt.Sprint(body["error"]), "HTTP 500") {
		t.Errorf("owner's Test error %q should still say what failed (status)", body["error"])
	}
	if _, body := req(t, app, http.MethodPost, connPath+"/"+connID+"/test", admin, ""); !strings.Contains(fmt.Sprint(body["error"]), "SECRET") {
		t.Errorf("admin's Test = %v: admins see the remote's answer to debug", body)
	}
	req(t, app, http.MethodPost, connPath+"/"+connID+"/pull", lead, "")
	if _, list := req(t, app, http.MethodGet, connPath, lead, ""); strings.Contains(fmt.Sprint(list), "SECRET") {
		t.Errorf("stored last_error leaks the remote's response: %v", list)
	}

	// With loopback refused (the production default), the same URL is rejected
	// when configured.
	prev := netguard.Default()
	netguard.SetDefault(netguard.Policy{AllowPrivate: true})
	defer netguard.SetDefault(prev)
	resp, body = req(t, app, http.MethodPut, connPath+"/"+connID, lead,
		`{"kind":"dependency-track","base_url":"`+internal.URL+`","remote_project":"ca4f2da9-0fad-4a13-92d7-f627f3168a56","token":"odt_x"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("connector pointed at loopback with loopback refused = %d %v, want 400", resp.StatusCode, body)
	}
}
