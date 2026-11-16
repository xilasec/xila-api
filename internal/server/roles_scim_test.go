package server

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/pgtest"
)

// rolesFixture is an org with one team and project, a scanned finding, and
// the users the tests grant things to.
type rolesFixture struct {
	app                    *fiber.App
	pool                   *pgxpool.Pool
	admin, lead, dana, eve string
	org, team, project     string
	finding                string
}

func setupRoles(t *testing.T) rolesFixture {
	t.Helper()
	pool := pgtest.Pool(t)
	app := newTestAppOn(t, pool)
	f := rolesFixture{app: app, pool: pool}
	f.admin = rbacUser(t, app, "admin@xila.io") // instance admin
	f.lead = rbacUser(t, app, "lead@xila.io")
	f.dana = rbacUser(t, app, "dana@xila.io")
	f.eve = rbacUser(t, app, "eve@xila.io")
	_, o := req(t, app, http.MethodPost, "/api/v1/orgs", f.lead, `{"slug":"acme","name":"Acme"}`)
	f.org = o["id"].(string)
	_, tm := req(t, app, http.MethodPost, "/api/v1/orgs/"+f.org+"/teams", f.lead, `{"slug":"core","name":"Core"}`)
	f.team = tm["id"].(string)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+f.team+"/projects", f.lead, `{"slug":"web","name":"web"}`)
	f.project = p["id"].(string)
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+f.project+"/scans?scanner=trivy", f.lead, smokeTrivyReport); resp.StatusCode != http.StatusCreated {
		t.Fatalf("scan = %d", resp.StatusCode)
	}
	_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+f.project+"/findings", f.lead, "")
	f.finding = list["findings"].([]any)[0].(map[string]any)["id"].(string)
	return f
}

func (f rolesFixture) code(t *testing.T, method, path, token, body string) int {
	t.Helper()
	resp, _ := req(t, f.app, method, path, token, body)
	return resp.StatusCode
}

// A group grant gives every member the role; leaving the group takes it
// away; the permission audit names the group.
func TestGroupGrants(t *testing.T) {
	f := setupRoles(t)
	resp, g := req(t, f.app, http.MethodPost, "/api/v1/orgs/"+f.org+"/groups", f.lead, `{"name":"Auditors"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create group = %d %v", resp.StatusCode, g)
	}
	group := g["id"].(string)
	if c := f.code(t, http.MethodPost, "/api/v1/orgs/"+f.org+"/groups/"+group+"/members", f.lead, `{"email":"dana@xila.io"}`); c >= 300 {
		t.Fatalf("add group member = %d", c)
	}
	if c := f.code(t, http.MethodGet, "/api/v1/projects/"+f.project, f.dana, ""); c != http.StatusForbidden && c != http.StatusNotFound {
		t.Fatalf("before the grant dana reads the project: %d", c)
	}
	if c := f.code(t, http.MethodPost, "/api/v1/projects/"+f.project+"/members", f.lead, `{"group_id":"`+group+`","role":"viewer"}`); c != http.StatusCreated {
		t.Fatalf("grant group = %d", c)
	}
	if c := f.code(t, http.MethodGet, "/api/v1/projects/"+f.project, f.dana, ""); c != http.StatusOK {
		t.Errorf("group member reading the project = %d, want 200", c)
	}
	if c := f.code(t, http.MethodPatch, "/api/v1/findings/"+f.finding, f.dana, `{"status":"confirmed"}`); c != http.StatusForbidden {
		t.Errorf("viewer via group triaging = %d, want 403", c)
	}
	// The permission audit shows why.
	_, audit := req(t, f.app, http.MethodGet, "/api/v1/permissions?project_id="+f.project, f.admin, "")
	if !strings.Contains(toJSON(t, audit), `"group_name":"Auditors"`) {
		t.Errorf("permission audit doesn't name the group: %s", toJSON(t, audit))
	}
	// Leaving the group ends the access.
	_, me := req(t, f.app, http.MethodGet, "/api/v1/me", f.dana, "")
	if c := f.code(t, http.MethodDelete, "/api/v1/orgs/"+f.org+"/groups/"+group+"/members/"+me["id"].(string), f.lead, ""); c >= 300 {
		t.Fatalf("remove group member = %d", c)
	}
	if c := f.code(t, http.MethodGet, "/api/v1/projects/"+f.project, f.dana, ""); c != http.StatusForbidden && c != http.StatusNotFound {
		t.Errorf("after leaving the group = %d, want 403/404", c)
	}

	// A group of another org can't be granted here (nor named).
	_, o2 := req(t, f.app, http.MethodPost, "/api/v1/orgs", f.eve, `{"slug":"other","name":"Other"}`)
	_, g2 := req(t, f.app, http.MethodPost, "/api/v1/orgs/"+o2["id"].(string)+"/groups", f.eve, `{"name":"Theirs"}`)
	if c := f.code(t, http.MethodPost, "/api/v1/projects/"+f.project+"/members", f.lead, `{"group_id":"`+g2["id"].(string)+`","role":"owner"}`); c != http.StatusNotFound {
		t.Errorf("granting another org's group = %d, want 404", c)
	}
}

// A custom role is its base role minus denied capabilities, enforced in the
// middleware and in the bulk edit; several grants combine by union.
func TestCustomRoles(t *testing.T) {
	f := setupRoles(t)
	resp, r := req(t, f.app, http.MethodPost, "/api/v1/orgs/"+f.org+"/custom-roles", f.lead,
		`{"name":"Reporter","base_role":"editor","denied_capabilities":["triage","export"]}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create custom role = %d %v", resp.StatusCode, r)
	}
	role := r["id"].(string)
	if c := f.code(t, http.MethodPost, "/api/v1/projects/"+f.project+"/members", f.lead,
		`{"email":"dana@xila.io","role":"editor","custom_role_id":"`+role+`"}`); c != http.StatusCreated {
		t.Fatalf("grant custom role = %d", c)
	}
	findings := "/api/v1/findings/" + f.finding
	if c := f.code(t, http.MethodPost, "/api/v1/projects/"+f.project+"/scans?scanner=trivy", f.dana, smokeTrivyReport); c != http.StatusCreated {
		t.Errorf("Reporter uploading = %d, want 201", c)
	}
	if c := f.code(t, http.MethodPost, findings+"/comments", f.dana, `{"body":"looks real"}`); c != http.StatusCreated {
		t.Errorf("Reporter commenting = %d, want 201", c)
	}
	if c := f.code(t, http.MethodPatch, findings, f.dana, `{"status":"false_positive","reason":"x"}`); c != http.StatusForbidden {
		t.Errorf("Reporter changing status = %d, want 403", c)
	}
	if c := f.code(t, http.MethodGet, "/api/v1/projects/"+f.project+"/findings/export", f.dana, ""); c != http.StatusForbidden {
		t.Errorf("Reporter exporting = %d, want 403", c)
	}
	_, bulk := req(t, f.app, http.MethodPost, "/api/v1/findings/bulk", f.dana, `{"ids":["`+f.finding+`"],"status":"false_positive","reason":"x"}`)
	if failed, _ := bulk["failed"].([]any); len(failed) != 1 {
		t.Errorf("Reporter bulk triage = %v, want the finding refused", bulk)
	}

	// A second grant without the denial: union, so triage is allowed.
	resp, g := req(t, f.app, http.MethodPost, "/api/v1/orgs/"+f.org+"/groups", f.lead, `{"name":"Triagers"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatal("create group")
	}
	group := g["id"].(string)
	f.code(t, http.MethodPost, "/api/v1/orgs/"+f.org+"/groups/"+group+"/members", f.lead, `{"email":"dana@xila.io"}`)
	if c := f.code(t, http.MethodPost, "/api/v1/teams/"+f.team+"/members", f.lead, `{"group_id":"`+group+`","role":"editor"}`); c != http.StatusCreated {
		t.Fatalf("grant group on team = %d", c)
	}
	if c := f.code(t, http.MethodPatch, findings, f.dana, `{"status":"confirmed"}`); c != http.StatusOK {
		t.Errorf("with a second, plain editor grant = %d, want 200", c)
	}
	// A custom role of another org can't be used here.
	_, o2 := req(t, f.app, http.MethodPost, "/api/v1/orgs", f.eve, `{"slug":"other","name":"Other"}`)
	_, r2 := req(t, f.app, http.MethodPost, "/api/v1/orgs/"+o2["id"].(string)+"/custom-roles", f.eve, `{"name":"X","base_role":"viewer"}`)
	if c := f.code(t, http.MethodPost, "/api/v1/projects/"+f.project+"/members", f.lead,
		`{"email":"eve@xila.io","role":"owner","custom_role_id":"`+r2["id"].(string)+`"}`); c != http.StatusNotFound {
		t.Errorf("another org's custom role = %d, want 404", c)
	}
}

// SCIM: an org-scoped token provisions users and groups; deactivation ends
// sessions; SCIM and API tokens can't stand in for each other.
func TestSCIMProvisioning(t *testing.T) {
	f := setupRoles(t)
	if c := f.code(t, http.MethodPost, "/api/v1/scim-tokens", f.lead, `{"name":"okta","org_id":"`+f.org+`"}`); c != http.StatusForbidden {
		t.Errorf("non-admin creating a SCIM token = %d, want 403", c)
	}
	resp, tok := req(t, f.app, http.MethodPost, "/api/v1/scim-tokens", f.admin, `{"name":"okta","org_id":"`+f.org+`"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create SCIM token = %d %v", resp.StatusCode, tok)
	}
	scim := tok["secret"].(string)
	base := "/api/v1/scim/v2"

	// New user, then the filter IdPs use to find it.
	resp, u := req(t, f.app, http.MethodPost, base+"/Users", scim,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"Frank@Xila.io","externalId":"00u1","active":true,"name":{"givenName":"Frank"}}`)
	if resp.StatusCode != http.StatusCreated || u["userName"] != "frank@xila.io" || u["active"] != true {
		t.Fatalf("create user = %d %v", resp.StatusCode, u)
	}
	frank := u["id"].(string)
	_, list := req(t, f.app, http.MethodGet, base+`/Users?filter=userName%20eq%20%22frank%40xila.io%22`, scim, "")
	if list["totalResults"] != float64(1) {
		t.Errorf("filter by userName = %v", list)
	}
	if resp, _ := req(t, f.app, http.MethodPost, base+"/Users", scim, `{"userName":"frank@xila.io"}`); resp.StatusCode != http.StatusConflict {
		t.Errorf("creating it twice = %d, want 409", resp.StatusCode)
	}

	// An existing account (dana, with a live session) joins the org through
	// SCIM; deactivating her ends that session.
	resp, d := req(t, f.app, http.MethodPost, base+"/Users", scim, `{"userName":"dana@xila.io"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("adopt dana = %d %v", resp.StatusCode, d)
	}
	dana := d["id"].(string)
	resp, patched := req(t, f.app, http.MethodPatch, base+"/Users/"+dana, scim,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":"False"}]}`)
	if resp.StatusCode != http.StatusOK || patched["active"] != false {
		t.Fatalf("deactivate = %d %v", resp.StatusCode, patched)
	}
	if c := f.code(t, http.MethodGet, "/api/v1/me", f.dana, ""); c != http.StatusUnauthorized {
		t.Errorf("dana's session after SCIM deactivation = %d, want 401", c)
	}

	// Groups with members, then member changes.
	resp, g := req(t, f.app, http.MethodPost, base+"/Groups", scim,
		`{"schemas":["urn:ietf:params:scim:schemas:core:2.0:Group"],"displayName":"Engineering","members":[{"value":"`+frank+`"}]}`)
	if resp.StatusCode != http.StatusCreated || len(g["members"].([]any)) != 1 {
		t.Fatalf("create group = %d %v", resp.StatusCode, g)
	}
	group := g["id"].(string)
	op := func(ops string) map[string]any {
		t.Helper()
		resp, out := req(t, f.app, http.MethodPatch, base+"/Groups/"+group, scim,
			`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":`+ops+`}`)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("patch group %s = %d %v", ops, resp.StatusCode, out)
		}
		return out
	}
	if out := op(`[{"op":"add","path":"members","value":[{"value":"` + dana + `"}]}]`); len(out["members"].([]any)) != 2 {
		t.Errorf("after add: %v", out["members"])
	}
	if out := op(`[{"op":"remove","path":"members[value eq \"` + frank + `\"]"}]`); len(out["members"].([]any)) != 1 {
		t.Errorf("after remove: %v", out["members"])
	}
	if out := op(`[{"op":"replace","path":"displayName","value":"Eng"}]`); out["displayName"] != "Eng" {
		t.Errorf("rename: %v", out)
	}
	if resp, _ := req(t, f.app, http.MethodPatch, base+"/Groups/"+group, scim,
		`{"Operations":[{"op":"add","path":"members","value":[{"value":"00000000-0000-0000-0000-000000000000"}]}]}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("adding a non-member = %d, want 400", resp.StatusCode)
	}
	// The group is a Xila group of the org, grantable like any other.
	_, groups := req(t, f.app, http.MethodGet, "/api/v1/orgs/"+f.org+"/groups", f.lead, "")
	if !strings.Contains(toJSON(t, groups), `"Eng"`) {
		t.Errorf("org groups = %v, want the provisioned group", groups)
	}
	if c := f.code(t, http.MethodDelete, base+"/Groups/"+group, scim, ""); c != http.StatusNoContent {
		t.Errorf("delete group = %d", c)
	}

	// Every change is audited with the token as the actor.
	var audited int
	if err := f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_log WHERE actor_kind = 'scim' AND actor_email = 'scim:okta' AND action LIKE 'scim.%' AND outcome = 'success'`).Scan(&audited); err != nil || audited < 7 {
		t.Errorf("SCIM audit entries = %d (%v), want one per change", audited, err)
	}

	// Discovery.
	if c := f.code(t, http.MethodGet, base+"/ServiceProviderConfig", scim, ""); c != http.StatusOK {
		t.Errorf("ServiceProviderConfig = %d", c)
	}

	// Credentials don't cross: a SCIM token on the API, a session or API
	// token on SCIM, a revoked SCIM token.
	if c := f.code(t, http.MethodGet, "/api/v1/projects", scim, ""); c != http.StatusUnauthorized {
		t.Errorf("SCIM token on the API = %d, want 401", c)
	}
	if c := f.code(t, http.MethodGet, base+"/Users", f.admin, ""); c != http.StatusUnauthorized {
		t.Errorf("session on SCIM = %d, want 401", c)
	}
	var refused int
	_ = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM audit_log WHERE action = 'scim.auth' AND outcome = 'failure'`).Scan(&refused)
	if refused == 0 {
		t.Error("a refused SCIM token isn't in the audit log")
	}
	_, apiTok := req(t, f.app, http.MethodPost, "/api/v1/tokens", f.admin, `{"name":"ci"}`)
	if c := f.code(t, http.MethodGet, base+"/Users", apiTok["secret"].(string), ""); c != http.StatusUnauthorized {
		t.Errorf("API token on SCIM = %d, want 401", c)
	}
	f.code(t, http.MethodDelete, "/api/v1/scim-tokens/"+tok["token"].(map[string]any)["id"].(string), f.admin, "")
	if c := f.code(t, http.MethodGet, base+"/Users", scim, ""); c != http.StatusUnauthorized {
		t.Errorf("revoked SCIM token = %d, want 401", c)
	}
}

func toJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
