package server

import (
	"net/http"
	"os"
	"slices"
	"testing"
)

// Project hierarchy end to end: a collection refuses uploads; its rollups
// (summary, findings, components, metric trends) are the sum of its children;
// a grant on it reaches the children and the audit names it; moving a child
// out takes that access away; the tree refuses cycles, other orgs and depth;
// moves need owner on both ends.
func TestProjectHierarchy(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "founder@xila.io")
	dana := rbacUser(t, app, "dana@xila.io")
	lead := rbacUser(t, app, "lead@xila.io")
	outsider := rbacUser(t, app, "outsider@xila.io")

	create := func(path, body string) string {
		t.Helper()
		res, b := req(t, app, http.MethodPost, path, admin, body)
		id, _ := b["id"].(string)
		if res.StatusCode != http.StatusCreated || id == "" {
			t.Fatalf("POST %s %s = %d %v", path, body, res.StatusCode, b)
		}
		return id
	}
	org := create("/api/v1/orgs", `{"slug":"acme","name":"Acme"}`)
	core := create("/api/v1/orgs/"+org+"/teams", `{"slug":"core","name":"Core"}`)
	ops := create("/api/v1/orgs/"+org+"/teams", `{"slug":"ops","name":"Ops"}`)
	other := create("/api/v1/orgs", `{"slug":"other","name":"Other"}`)
	elsewhere := create("/api/v1/orgs/"+other+"/teams", `{"slug":"x","name":"X"}`)

	platform := create("/api/v1/teams/"+core+"/projects", `{"slug":"platform","name":"Platform","is_collection":true}`)
	web := create("/api/v1/teams/"+core+"/projects", `{"slug":"web","name":"web","parent_id":"`+platform+`","business_criticality":"high"}`)
	api := create("/api/v1/teams/"+ops+"/projects", `{"slug":"api","name":"api","parent_id":"`+platform+`","business_criticality":"low"}`)
	foreign := create("/api/v1/teams/"+elsewhere+"/projects", `{"slug":"f","name":"f"}`)

	// A collection holds no scans or SBOMs of its own.
	if res, b := req(t, app, http.MethodPost, "/api/v1/projects/"+platform+"/scans?scanner=trivy", admin, smokeTrivyReport); res.StatusCode != http.StatusConflict {
		t.Errorf("scan upload to a collection = %d %v, want 409", res.StatusCode, b)
	}
	if res, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+platform+"/sboms?artifact=x", admin, smokeCycloneDX); res.StatusCode != http.StatusConflict {
		t.Errorf("SBOM upload to a collection = %d, want 409", res.StatusCode)
	}
	bandit, err := os.ReadFile("../scanner/testdata/bandit.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, up := range []struct{ project, path, body string }{
		{web, "/scans?scanner=trivy", smokeTrivyReport},
		{web, "/sboms?artifact=web&version=1.0.0", smokeCycloneDX},
		{api, "/scans?scanner=bandit", string(bandit)},
	} {
		if res, b := req(t, app, http.MethodPost, "/api/v1/projects/"+up.project+up.path, admin, up.body); res.StatusCode != http.StatusCreated {
			t.Fatalf("upload %s = %d %v", up.path, res.StatusCode, b)
		}
	}
	// A project with scans can't become a collection.
	if res, _ := req(t, app, http.MethodPatch, "/api/v1/projects/"+web, admin, `{"is_collection":true}`); res.StatusCode != http.StatusConflict {
		t.Errorf("web -> collection = %d, want 409", res.StatusCode)
	}

	// Rollups: the collection's numbers are its children's, summed.
	num := func(m map[string]any, k string) float64 { v, _ := m[k].(float64); return v }
	summary := func(id, query string) map[string]any {
		t.Helper()
		res, b := req(t, app, http.MethodGet, "/api/v1/projects/"+id+"/summary"+query, admin, "")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("summary %s%s = %d", id, query, res.StatusCode)
		}
		return b
	}
	sw, sa, sp := summary(web, ""), summary(api, ""), summary(platform, "")
	if num(sw, "total") == 0 || num(sa, "total") == 0 {
		t.Fatalf("children have no findings: web %v api %v", sw, sa)
	}
	for _, k := range []string{"total", "total_open", "risk_score"} {
		if num(sp, k) != num(sw, k)+num(sa, k) {
			t.Errorf("platform %s = %v, want %v + %v", k, num(sp, k), num(sw, k), num(sa, k))
		}
	}
	if ids, _ := sp["project_ids"].([]any); len(ids) != 3 {
		t.Errorf("platform summary covers %v", sp["project_ids"])
	}
	if s := summary(platform, "?include_children=false"); num(s, "total") != 0 {
		t.Errorf("platform alone = %v, want no findings", s)
	}
	if res, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+platform+"/summary?include_children=maybe", admin, ""); res.StatusCode != http.StatusBadRequest {
		t.Errorf("bad include_children = %d", res.StatusCode)
	}
	count := func(path, key string) int {
		t.Helper()
		res, b := req(t, app, http.MethodGet, path, admin, "")
		items, _ := b[key].([]any)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d", path, res.StatusCode)
		}
		return len(items)
	}
	fw := count("/api/v1/projects/"+web+"/findings?limit=500", "findings")
	fa := count("/api/v1/projects/"+api+"/findings?limit=500", "findings")
	if fp := count("/api/v1/projects/"+platform+"/findings?limit=500", "findings"); fp != fw+fa || fp != int(num(sp, "total")) {
		t.Errorf("platform findings = %d, want %d + %d", fp, fw, fa)
	}
	// A regular project includes its children only when asked.
	if n := count("/api/v1/projects/"+web+"/findings?limit=500&include_children=true", "findings"); n != fw {
		t.Errorf("web (no children) with include_children = %d, want %d", n, fw)
	}
	cw := count("/api/v1/projects/"+web+"/components?limit=500", "components")
	if cp := count("/api/v1/projects/"+platform+"/components?limit=500", "components"); cw == 0 || cp != cw {
		t.Errorf("platform components = %d, want web's %d", cp, cw)
	}
	if res, _ := req(t, app, http.MethodPost, "/api/v1/metrics/snapshot", admin, ""); res.StatusCode != http.StatusOK {
		t.Fatalf("snapshot = %d", res.StatusCode)
	}
	lastOpen := func(id string) float64 {
		t.Helper()
		_, b := req(t, app, http.MethodGet, "/api/v1/projects/"+id+"/metrics/trends?days=1", admin, "")
		points, _ := b["points"].([]any)
		if len(points) != 1 {
			t.Fatalf("trend of %s = %v", id, b)
		}
		return num(points[0].(map[string]any), "open_total")
	}
	if lp, lw, la := lastOpen(platform), lastOpen(web), lastOpen(api); lp != lw+la || lp == 0 {
		t.Errorf("platform trend open = %v, want %v + %v", lp, lw, la)
	}

	// A grant on the parent opens the children.
	if res, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+platform+"/members", admin, `{"email":"dana@xila.io","role":"viewer"}`); res.StatusCode >= 300 {
		t.Fatalf("grant dana = %d", res.StatusCode)
	}
	for _, id := range []string{web, api} {
		if res, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+id+"/summary", dana, ""); res.StatusCode != http.StatusOK {
			t.Errorf("dana (viewer on platform) GET child summary = %d, want 200", res.StatusCode)
		}
		if res, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+id+"/summary", outsider, ""); res.StatusCode != http.StatusForbidden {
			t.Errorf("outsider GET child summary = %d, want 403", res.StatusCode)
		}
	}
	listed := func(token string) []string {
		t.Helper()
		_, b := req(t, app, http.MethodGet, "/api/v1/projects", token, "")
		items, _ := b["projects"].([]any)
		var ids []string
		for _, it := range items {
			p := it.(map[string]any)
			ids = append(ids, p["id"].(string))
			if p["id"] == web && p["parent_id"] != platform {
				t.Errorf("web's parent_id = %v", p["parent_id"])
			}
		}
		slices.Sort(ids)
		return ids
	}
	want := []string{platform, web, api}
	slices.Sort(want)
	if got := listed(dana); !slices.Equal(got, want) {
		t.Errorf("dana's projects = %v, want %v", got, want)
	}
	if n := count("/api/v1/projects/"+platform+"/children", "projects"); n != 2 {
		t.Errorf("platform children = %d, want 2", n)
	}
	// The audit names the parent behind dana's access to web.
	_, acc := req(t, app, http.MethodGet, "/api/v1/projects/"+web+"/access", admin, "")
	entries, _ := acc["entries"].([]any)
	named := false
	for _, e := range entries {
		e := e.(map[string]any)
		if e["email"] != "dana@xila.io" {
			continue
		}
		for _, g := range e["grants"].([]any) {
			g := g.(map[string]any)
			named = g["kind"] == "parent_project" && g["via_id"] == platform && g["via_name"] == "Platform"
		}
	}
	if !named {
		t.Errorf("web's access audit doesn't name the parent for dana: %v", entries)
	}

	// The tree's rules: no cycle, no other org, no deeper than 5 levels.
	for _, tc := range []struct{ id, body string }{
		{platform, `{"parent_id":"` + web + `"}`},
		{platform, `{"parent_id":"` + platform + `"}`},
		{web, `{"parent_id":"` + foreign + `"}`},
	} {
		if res, b := req(t, app, http.MethodPatch, "/api/v1/projects/"+tc.id, admin, tc.body); res.StatusCode != http.StatusBadRequest {
			t.Errorf("PATCH %s = %d %v, want 400", tc.body, res.StatusCode, b)
		}
	}
	parent := web
	for i, slug := range []string{"l3", "l4", "l5", "l6"} {
		res, b := req(t, app, http.MethodPost, "/api/v1/teams/"+core+"/projects", admin, `{"slug":"`+slug+`","name":"`+slug+`","parent_id":"`+parent+`"}`)
		if i < 3 && res.StatusCode != http.StatusCreated {
			t.Fatalf("level %s = %d %v", slug, res.StatusCode, b)
		}
		if i == 3 && res.StatusCode != http.StatusBadRequest {
			t.Errorf("6th level = %d, want 400", res.StatusCode)
		}
		parent, _ = b["id"].(string)
	}

	// Moving needs owner on the project and on the new parent.
	req(t, app, http.MethodPost, "/api/v1/projects/"+api+"/members", admin, `{"email":"lead@xila.io","role":"owner"}`)
	if res, _ := req(t, app, http.MethodPatch, "/api/v1/projects/"+api, dana, `{"parent_id":null}`); res.StatusCode != http.StatusForbidden {
		t.Errorf("viewer moving api = %d, want 403", res.StatusCode)
	}
	if res, _ := req(t, app, http.MethodPatch, "/api/v1/projects/"+api, lead, `{"parent_id":"`+web+`"}`); res.StatusCode != http.StatusNotFound {
		t.Errorf("owner of api moving it under web (invisible to them) = %d, want 404", res.StatusCode)
	}
	req(t, app, http.MethodPost, "/api/v1/projects/"+web+"/members", admin, `{"email":"lead@xila.io","role":"editor"}`)
	if res, _ := req(t, app, http.MethodPatch, "/api/v1/projects/"+api, lead, `{"parent_id":"`+web+`"}`); res.StatusCode != http.StatusForbidden {
		t.Errorf("owner of api moving it under web (editor there) = %d, want 403", res.StatusCode)
	}
	// Moving api out of the collection takes dana's access to it away.
	if res, b := req(t, app, http.MethodPatch, "/api/v1/projects/"+api, lead, `{"parent_id":null}`); res.StatusCode != http.StatusOK || b["parent_id"] != nil {
		t.Fatalf("lead detaching api = %d %v", res.StatusCode, b)
	}
	if res, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+api+"/summary", dana, ""); res.StatusCode != http.StatusForbidden {
		t.Errorf("dana GET api after the move = %d, want 403", res.StatusCode)
	}
	if slices.Contains(listed(dana), api) {
		t.Error("dana still lists api after the move")
	}
	if s := summary(platform, ""); num(s, "total") != num(sw, "total") {
		t.Errorf("platform total after the move = %v, want web's %v", num(s, "total"), num(sw, "total"))
	}
}
