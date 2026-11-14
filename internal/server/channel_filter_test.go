package server

import (
	"net/http"
	"strings"
	"testing"
)

// A channel's CEL filter is checked when saved (400 with the reason), stored,
// returned, kept on a PATCH that doesn't name it, and cleared with "".
func TestChannelFilterOverHTTP(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "admin@xila.io")

	res, body := req(t, app, http.MethodPost, "/api/v1/notifications/channels", admin,
		`{"name":"x","type":"webhook","url":"https://hooks.example.test/x","filter":"event.finding.nope"}`)
	if res.StatusCode != http.StatusBadRequest || !strings.Contains(body["error"].(string), "filter") {
		t.Fatalf("bad filter: %d %v", res.StatusCode, body)
	}
	res, ch := req(t, app, http.MethodPost, "/api/v1/notifications/channels", admin,
		`{"name":"kev","type":"webhook","url":"https://hooks.example.test/x","filter":"event.finding.kev"}`)
	if res.StatusCode != http.StatusCreated || ch["filter"] != "event.finding.kev" {
		t.Fatalf("create: %d %v", res.StatusCode, ch)
	}
	id := ch["id"].(string)
	if _, ch = req(t, app, http.MethodPatch, "/api/v1/notifications/channels/"+id, admin, `{"name":"kev2"}`); ch["filter"] != "event.finding.kev" {
		t.Fatalf("PATCH without filter dropped it: %v", ch)
	}
	if _, ch = req(t, app, http.MethodPatch, "/api/v1/notifications/channels/"+id, admin, `{"filter":""}`); ch["filter"] != "" {
		t.Fatalf("clearing the filter: %v", ch)
	}
}
