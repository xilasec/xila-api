package server

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/feature"
)

// Every route a feature switch turns off, pinned against the real route table:
// a new route under a feature's path, or a pattern that starts catching a core
// route, fails here until someone decides which feature owns it.
func TestFeatureRoutesMatchRouteTable(t *testing.T) {
	want := map[string][]string{
		feature.AITriage: {
			"GET /api/v1/findings/:findingID/ai-proposals", "GET /api/v1/findings/:findingID/ai-proposals/prompt",
			"POST /api/v1/findings/:findingID/ai-proposals", "POST /api/v1/findings/:findingID/ai-proposals/:proposalID/accept",
			"POST /api/v1/findings/:findingID/ai-proposals/:proposalID/reject"},
		feature.Badges: {
			"DELETE /api/v1/projects/:projectID/badge-token", "GET /api/v1/badges/:token/:file",
			"GET /api/v1/projects/:projectID/badge-token", "POST /api/v1/projects/:projectID/badge-token"},
		feature.CRA: {
			"GET /api/v1/cra/cases", "GET /api/v1/cra/cases/:caseID", "GET /api/v1/cra/cases/:caseID/report",
			"GET /api/v1/projects/:projectID/cra", "PATCH /api/v1/cra/cases/:caseID", "POST /api/v1/cra/cases/:caseID/close",
			"POST /api/v1/cra/cases/:caseID/dismiss", "POST /api/v1/cra/cases/:caseID/submit", "POST /api/v1/cra/sweep",
			"POST /api/v1/projects/:projectID/cra/cases", "PUT /api/v1/projects/:projectID/cra"},
		feature.CustomFields: {
			"DELETE /api/v1/custom-fields/:fieldID", "GET /api/v1/custom-fields", "GET /api/v1/custom-fields/:fieldID",
			"PATCH /api/v1/assets/:assetID/custom", "PATCH /api/v1/custom-fields/:fieldID", "PATCH /api/v1/findings/:findingID/custom",
			"PATCH /api/v1/projects/:projectID/custom", "POST /api/v1/custom-fields"},
		feature.Engagements: {
			"DELETE /api/v1/engagements/:engagementID", "GET /api/v1/engagements/:engagementID",
			"GET /api/v1/projects/:projectID/engagements", "PATCH /api/v1/engagements/:engagementID",
			"POST /api/v1/engagements/:engagementID/restore", "POST /api/v1/projects/:projectID/engagements"},
		feature.MCP: {"POST /api/v1/mcp"},
		feature.MFA: {
			"DELETE /api/v1/users/:userID/mfa", "GET /api/v1/me/mfa", "POST /api/v1/auth/mfa", "POST /api/v1/me/mfa/disable",
			"POST /api/v1/me/mfa/enable", "POST /api/v1/me/mfa/setup"},
		feature.PersonalNotifications: {
			"DELETE /api/v1/projects/:projectID/watch", "GET /api/v1/me/notifications", "GET /api/v1/me/notifications/deliveries",
			"GET /api/v1/projects/:projectID/watch", "PUT /api/v1/me/notifications", "PUT /api/v1/projects/:projectID/watch"},
		feature.PSIRT: {
			"DELETE /api/v1/psirt/advisories/:advisoryID", "GET /.well-known/csaf/provider-metadata.json",
			"GET /api/v1/psirt/advisories", "GET /api/v1/psirt/advisories/:advisoryID", "GET /api/v1/psirt/advisories/:advisoryID/csaf",
			"GET /api/v1/psirt/advisories/:advisoryID/preview", "GET /csaf/advisories/:year/:file", "GET /csaf/advisories/changes.csv",
			"GET /csaf/advisories/index.txt", "POST /api/v1/psirt/advisories", "POST /api/v1/psirt/advisories/:advisoryID/publish",
			"POST /api/v1/psirt/advisories/:advisoryID/withdraw", "PUT /api/v1/psirt/advisories/:advisoryID"},
		feature.Remediation: {
			"GET /api/v1/projects/:projectID/remediation", "GET /api/v1/projects/:projectID/remediation/proposals",
			"GET /api/v1/remediation", "GET /api/v1/remediation/:actionID", "GET /api/v1/remediation/:actionID/findings",
			"PATCH /api/v1/remediation/:actionID", "POST /api/v1/projects/:projectID/remediation",
			"POST /api/v1/remediation/:actionID/issue", "POST /api/v1/remediation/sweep",
			"GET /api/v1/root-causes", "GET /api/v1/root-causes/:kind/:key", "POST /api/v1/root-causes/:kind/:key/remediation"},
	}
	app := newTestApp(t)
	store := feature.NewStore(nil)
	param := regexp.MustCompile(`:[A-Za-z]+\??|\*`)
	got := map[string][]string{}
	for _, r := range app.GetRoutes(true) {
		if r.Method == http.MethodHead {
			continue
		}
		if k := store.FeatureFor(param.ReplaceAllString(r.Path, "x")); k != "" {
			got[k] = append(got[k], r.Method+" "+r.Path)
		}
	}
	for _, d := range feature.Defs {
		g, w := got[d.Key], want[d.Key]
		slices.Sort(g)
		slices.Sort(w)
		if !slices.Equal(g, w) {
			t.Errorf("%s gates:\n  %s\nwant:\n  %s", d.Key, strings.Join(g, "\n  "), strings.Join(w, "\n  "))
		}
	}
}

// A switched-off feature's routes answer 404 — public ones too — and come
// back with their data when it is switched on; only admins switch features,
// only the signed-in owner switches two-factor; and with two-factor off an
// enrolled user signs in without a code.
func TestFeatureSwitches(t *testing.T) {
	app := newTestApp(t, func(c *config.Config) {
		c.PSIRT = config.PSIRT{Public: true, AdvisoryPrefix: "ACME-SA", PublisherName: "Acme PSIRT",
			PublisherNamespace: "https://acme.example", PublisherContact: "psirt@acme.example"}
	})
	owner := rbacUser(t, app, "owner@xila.io")
	admin := rbacUser(t, app, "admin@xila.io")
	bob := rbacUser(t, app, "bob@xila.io")
	req(t, app, http.MethodPatch, "/api/v1/users/"+userIDOf(t, app, owner, "admin@xila.io"), owner, `{"is_admin":true}`)
	set := func(token, key string, on bool) int {
		t.Helper()
		resp, _ := req(t, app, http.MethodPut, "/api/v1/features/"+key, token, fmt.Sprintf(`{"enabled":%v}`, on))
		return resp.StatusCode
	}
	status := func(token, method, path string) int {
		t.Helper()
		resp, _ := req(t, app, method, path, token, "")
		return resp.StatusCode
	}

	// Anyone signed in reads the switches; all on by default, MCP and AI
	// unavailable (not configured here).
	resp, body := req(t, app, http.MethodGet, "/api/v1/features", bob, "")
	list, _ := body["features"].([]any)
	if resp.StatusCode != http.StatusOK || len(list) != len(feature.Defs) {
		t.Fatalf("GET /features = %d %v", resp.StatusCode, body)
	}
	for _, f := range list {
		st := f.(map[string]any)
		unconfigured := st["key"] == feature.MCP || st["key"] == feature.AITriage
		if st["enabled"] == unconfigured || st["available"] == unconfigured {
			t.Errorf("default %v", st)
		}
	}

	// Only admins switch; turning on an unconfigured feature is refused.
	if code := set(bob, feature.CRA, false); code != http.StatusForbidden {
		t.Errorf("a member switching cra = %d, want 403", code)
	}
	if code := set(admin, feature.MCP, true); code != http.StatusConflict {
		t.Errorf("turning on unconfigured MCP = %d, want 409", code)
	}
	if code := set(admin, "nope", false); code != http.StatusNotFound {
		t.Errorf("unknown feature = %d, want 404", code)
	}
	if resp, _ := req(t, app, http.MethodPut, "/api/v1/features/cra", admin, `{}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("no enabled field = %d, want 400", resp.StatusCode)
	}

	// Off: the feature's API, and its public pages, are gone; the rest isn't.
	if code := status(admin, http.MethodGet, "/api/v1/cra/cases"); code != http.StatusOK {
		t.Fatalf("cra cases while on = %d", code)
	}
	if code, _ := publicGet(t, app, "/.well-known/csaf/provider-metadata.json"); code != http.StatusOK {
		t.Fatalf("CSAF provider metadata while on = %d", code)
	}
	if set(admin, feature.CRA, false) != http.StatusOK || set(admin, feature.PSIRT, false) != http.StatusOK {
		t.Fatal("switching cra / psirt off failed")
	}
	for _, p := range []string{"/api/v1/cra/cases", "/API/V1/CRA/CASES/", "/api/v1/psirt/advisories"} {
		if code := status(admin, http.MethodGet, p); code != http.StatusNotFound {
			t.Errorf("GET %s while off = %d, want 404", p, code)
		}
	}
	if code, _ := publicGet(t, app, "/.well-known/csaf/provider-metadata.json"); code != http.StatusNotFound {
		t.Errorf("CSAF provider metadata while psirt is off = %d, want 404", code)
	}
	if code := status(admin, http.MethodGet, "/api/v1/findings"); code != http.StatusOK {
		t.Errorf("findings while cra is off = %d", code)
	}
	if set(admin, feature.CRA, true) != http.StatusOK {
		t.Fatal("switching cra back on failed")
	}
	if code := status(admin, http.MethodGet, "/api/v1/cra/cases"); code != http.StatusOK {
		t.Errorf("cra cases back on = %d", code)
	}

	// The switch is in the audit log with its before/after state.
	_, logBody := req(t, app, http.MethodGet, "/api/v1/audit-log?limit=200", owner, "")
	var recorded bool
	for _, e := range logBody["entries"].([]any) {
		en := e.(map[string]any)
		if ch := fmt.Sprint(en["changes"]); en["path"] == "/api/v1/features/psirt" && en["outcome"] == "success" &&
			strings.Contains(ch, "enabled:false") && strings.Contains(ch, "feature:psirt") {
			recorded = true
		}
	}
	if !recorded {
		t.Error("switching psirt off is not in the audit log with its change")
	}

	// Two-factor: bob enrolls; only the owner, signed in, may switch it off.
	_, setup := req(t, app, http.MethodPost, "/api/v1/me/mfa/setup", bob, "")
	secret, _ := setup["secret"].(string)
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/me/mfa/enable", bob, `{"code":"`+totp(t, secret, 0)+`"}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("enroll = %d", resp.StatusCode)
	}
	login := func() map[string]any {
		t.Helper()
		_, b := req(t, app, http.MethodPost, "/api/v1/auth/login", "", `{"email":"bob@xila.io","password":"supersecret"}`)
		return b
	}
	if b := login(); b["mfa_required"] != true {
		t.Fatalf("enrolled sign-in = %v, want a challenge", b)
	}
	if code := set(admin, feature.MFA, false); code != http.StatusForbidden {
		t.Errorf("an admin (not the owner) switching mfa = %d, want 403", code)
	}
	_, tok := req(t, app, http.MethodPost, "/api/v1/tokens", owner, `{"name":"ci"}`)
	if code := set(tok["secret"].(string), feature.MFA, false); code != http.StatusForbidden {
		t.Errorf("the owner's API token switching mfa = %d, want 403", code)
	}
	if code := set(owner, feature.MFA, false); code != http.StatusOK {
		t.Fatalf("the owner switching mfa off = %d", code)
	}
	if b := login(); b["token"] == nil || b["mfa_required"] == true {
		t.Errorf("sign-in with mfa off = %v, want a session", b)
	}
	if code := status(bob, http.MethodGet, "/api/v1/me/mfa"); code != http.StatusNotFound {
		t.Errorf("GET /me/mfa with mfa off = %d, want 404", code)
	}
	if code := set(owner, feature.MFA, true); code != http.StatusOK {
		t.Fatalf("the owner switching mfa on = %d", code)
	}
	if b := login(); b["mfa_required"] != true {
		t.Errorf("sign-in with mfa back on = %v, want the kept enrollment to challenge again", b)
	}
}
