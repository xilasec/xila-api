package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// README badges: an owner issues a token; anyone holding it — signed in or
// not — reads the project's live numbers; nobody else can, and a rotated or
// revoked token stops working without revealing whether the project exists.
func TestProjectBadges(t *testing.T) {
	app := newTestApp(t)
	_ = rbacUser(t, app, "founder@xila.io")
	lead := rbacUser(t, app, "lead@xila.io")
	editor := rbacUser(t, app, "editor@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", lead, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", lead, `{"slug":"web","name":"web"}`)
	pid, _ := p["id"].(string)
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/members", lead, `{"email":"editor@xila.io","role":"editor"}`)
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=trivy", lead, smokeTrivyReport)

	badge := func(token, kind string) (int, string, http.Header) {
		t.Helper()
		res, err := app.Test(httptest.NewRequest(http.MethodGet, "/api/v1/badges/"+token+"/"+kind+".svg", nil), -1)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(body), res.Header
	}

	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/badge-token", editor, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor issuing a badge token = %d, want 403", resp.StatusCode)
	}
	if _, st := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/badge-token", editor, ""); st["enabled"] != false {
		t.Errorf("badge status before issuing = %v", st)
	}
	resp, issued := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/badge-token", lead, "")
	token, _ := issued["token"].(string)
	if resp.StatusCode != http.StatusCreated || !strings.HasPrefix(token, "xb_") {
		t.Fatalf("issue badge token = %d %v", resp.StatusCode, issued)
	}
	if md, _ := issued["markdown"].(map[string]any); !strings.Contains(md["findings"].(string), token+"/findings.svg") {
		t.Errorf("markdown snippets = %v", issued["markdown"])
	}
	_, st := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/badge-token", editor, "")
	if st["enabled"] != true || st["token"] != nil {
		t.Errorf("badge status = %v: enabled, and never the token", st)
	}

	// Public, no Authorization header.
	code, svg, hdr := badge(token, "findings")
	if code != http.StatusOK || !strings.Contains(svg, "1 critical · 1 high") || !strings.Contains(svg, "vulnerabilities") {
		t.Fatalf("findings badge = %d %s", code, svg)
	}
	if hdr.Get("Content-Type") != "image/svg+xml; charset=utf-8" || hdr.Get("Cache-Control") != "max-age=300" ||
		!strings.Contains(hdr.Get("Content-Security-Policy"), "default-src 'none'") {
		t.Errorf("badge headers = %v", hdr)
	}
	if code, svg, _ := badge(token, "gate"); code != http.StatusOK || !strings.Contains(svg, "passing") {
		t.Errorf("gate badge under the default (empty) policy = %d %s, want passing", code, svg)
	}
	req(t, app, http.MethodPut, "/api/v1/projects/"+pid+"/gate/policy", lead, `{"max_critical":0}`)
	if code, svg, _ := badge(token, "gate"); code != http.StatusOK || !strings.Contains(svg, "failing") {
		t.Errorf("gate badge with an open critical over max_critical 0 = %d %s, want failing", code, svg)
	}
	if code, svg, _ := badge(token, "sla"); code != http.StatusOK || !strings.Contains(svg, "remediation SLA") {
		t.Errorf("sla badge = %d %s", code, svg)
	}

	// Unknown kinds, unknown tokens, rotated and revoked tokens all look alike.
	unknown := func(token, kind, why string) {
		t.Helper()
		if code, svg, _ := badge(token, kind); code != http.StatusNotFound || !strings.Contains(svg, "unknown") {
			t.Errorf("%s = %d %s, want the unknown badge with 404", why, code, svg)
		}
	}
	unknown(token, "secrets", "unknown kind")
	unknown("xb_nope", "findings", "unknown token")
	unknown(pid, "findings", "a project id instead of a token")
	_, rotated := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/badge-token", lead, "")
	unknown(token, "findings", "rotated-out token")
	if code, _, _ := badge(rotated["token"].(string), "findings"); code != http.StatusOK {
		t.Errorf("new token after rotation = %d", code)
	}
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/projects/"+pid+"/badge-token", lead, ""); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke = %d", resp.StatusCode)
	}
	unknown(rotated["token"].(string), "findings", "revoked token")
}
