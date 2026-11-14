package server

import (
	"net/http"
	"strings"
	"testing"
)

// /me/notifications is always the caller's own (there is no way to name
// another user); a webhook URL is write-only; watching needs only viewer on
// the project and is refused on a project you can't see; service accounts
// can't subscribe.
func TestPersonalNotificationsOverHTTP(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "founder@xila.io")
	viewer := rbacUser(t, app, "viewer@xila.io")
	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", admin, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", admin, `{"slug":"web","name":"web"}`)
	web := p["id"].(string)
	_, p = req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", admin, `{"slug":"api","name":"api"}`)
	api := p["id"].(string)
	req(t, app, http.MethodPost, "/api/v1/projects/"+web+"/members", admin, `{"email":"viewer@xila.io","role":"viewer"}`)

	const hook = "https://hooks.slack.com/services/T000/B000/XXXX"
	res, prefs := req(t, app, http.MethodPut, "/api/v1/me/notifications", viewer,
		`{"on_watched":true,"methods":{"slack":{"enabled":true,"url":"`+hook+`","min_severity":"high"}}}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("save: %d %v", res.StatusCode, prefs)
	}
	slack := prefs["methods"].(map[string]any)["slack"].(map[string]any)
	if slack["has_url"] != true || slack["min_severity"] != "high" || strings.Contains(asJSON(t, prefs), "hooks.slack.com") {
		t.Errorf("prefs = %v", prefs)
	}
	if res, _ := req(t, app, http.MethodPut, "/api/v1/me/notifications", viewer, `{"methods":{"pager":{"enabled":true}}}`); res.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown method = %d", res.StatusCode)
	}
	// Another user sees their own (default) prefs, not the viewer's.
	if _, other := req(t, app, http.MethodGet, "/api/v1/me/notifications", admin, ""); other["methods"].(map[string]any)["slack"].(map[string]any)["has_url"] != false {
		t.Errorf("admin sees someone else's subscription: %v", other)
	}

	if res, w := req(t, app, http.MethodPut, "/api/v1/projects/"+web+"/watch", viewer, ""); res.StatusCode != http.StatusOK || w["watching"] != true {
		t.Errorf("viewer watch = %d %v", res.StatusCode, w)
	}
	if res, _ := req(t, app, http.MethodPut, "/api/v1/projects/"+api+"/watch", viewer, ""); res.StatusCode != http.StatusForbidden {
		t.Errorf("watching an invisible project = %d, want 403", res.StatusCode)
	}
	if _, prefs = req(t, app, http.MethodGet, "/api/v1/me/notifications", viewer, ""); len(prefs["watching"].([]any)) != 1 {
		t.Errorf("watching = %v", prefs["watching"])
	}

	// A service account can't subscribe.
	_, sa := req(t, app, http.MethodPost, "/api/v1/service-accounts", admin, `{"name":"bot"}`)
	_, k := req(t, app, http.MethodPost, "/api/v1/service-accounts/"+sa["id"].(string)+"/keys", admin, `{"name":"k"}`)
	key, _ := k["secret"].(string)
	if res, _ := req(t, app, http.MethodGet, "/api/v1/me/notifications", key, ""); res.StatusCode != http.StatusForbidden {
		t.Errorf("service account = %d, want 403", res.StatusCode)
	}
}
