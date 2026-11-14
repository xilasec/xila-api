package server

import (
	"net/http"
	"strings"
	"testing"
)

// TestLicenseCatalogAndGroups: the catalog and groups are readable by any
// signed-in user, group mutations are instance-admin only, members are
// validated and canonicalized, and component lists filter by license.
func TestLicenseCatalogAndGroups(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "admin@xila.io")
	bob := rbacUser(t, app, "bob@xila.io")

	// Catalog: search + category filter, paginated, open to non-admins.
	resp, body := req(t, app, http.MethodGet, "/api/v1/licenses?q=apache&category=permissive&limit=5", bob, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /licenses = %d", resp.StatusCode)
	}
	lics, _ := body["licenses"].([]any)
	if len(lics) == 0 || len(lics) > 5 || body["list_version"] == "" {
		t.Fatalf("licenses = %v", body)
	}
	for _, l := range lics {
		m := l.(map[string]any)
		if m["category"] != "Permissive" || !strings.Contains(strings.ToLower(m["id"].(string)+m["name"].(string)), "apache") {
			t.Errorf("filtered license %v", m)
		}
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/licenses?category=nope", bob, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown category = %d, want 400", resp.StatusCode)
	}
	resp, body = req(t, app, http.MethodGet, "/api/v1/licenses/gpl-2.0", bob, "")
	if resp.StatusCode != http.StatusOK || body["id"] != "GPL-2.0" || body["deprecated"] != true || body["category"] != "Copyleft" {
		t.Errorf("GET /licenses/gpl-2.0 = %d %v", resp.StatusCode, body)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/licenses/Nope-1.0", bob, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown license = %d, want 404", resp.StatusCode)
	}

	// Groups: non-admins can't create; admins can, with validated ids.
	group := `{"name":"Approved","description":"ok to ship","license_ids":["mit","Apache-2.0","LicenseRef-internal","MIT"]}`
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/license-groups", bob, group); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin create group = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/license-groups", admin, `{"name":"Bad","license_ids":["Nope-1.0"]}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown member = %d, want 400", resp.StatusCode)
	}
	resp, body = req(t, app, http.MethodPost, "/api/v1/license-groups", admin, group)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create group = %d %v", resp.StatusCode, body)
	}
	groupID, _ := body["id"].(string)
	if ids, _ := body["license_ids"].([]any); len(ids) != 3 || ids[0] != "Apache-2.0" || ids[1] != "LicenseRef-internal" || ids[2] != "MIT" {
		t.Errorf("members = %v, want canonical, deduplicated, sorted", body["license_ids"])
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/license-groups", admin, group); resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate name = %d, want 409", resp.StatusCode)
	}
	resp, body = req(t, app, http.MethodGet, "/api/v1/license-groups", bob, "")
	if groups, _ := body["groups"].([]any); resp.StatusCode != http.StatusOK || len(groups) != 1 {
		t.Errorf("list groups = %d %v", resp.StatusCode, body)
	}
	if builtin, _ := body["builtin"].([]any); len(builtin) == 0 {
		t.Error("no built-in category groups")
	}
	resp, body = req(t, app, http.MethodGet, "/api/v1/license-groups/category:copyleft", bob, "")
	if ids, _ := body["license_ids"].([]any); resp.StatusCode != http.StatusOK || body["category"] != "Copyleft" || len(ids) == 0 {
		t.Errorf("builtin group = %d %v", resp.StatusCode, body["category"])
	}
	// The license detail names the groups it's in.
	_, body = req(t, app, http.MethodGet, "/api/v1/licenses/MIT", bob, "")
	if gs, _ := body["groups"].([]any); len(gs) != 1 {
		t.Errorf("MIT groups = %v", body["groups"])
	}

	upd := `{"name":"Approved","license_ids":["ISC"]}`
	if resp, _ := req(t, app, http.MethodPut, "/api/v1/license-groups/"+groupID, bob, upd); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin update = %d, want 403", resp.StatusCode)
	}
	resp, body = req(t, app, http.MethodPut, "/api/v1/license-groups/"+groupID, admin, upd)
	if ids, _ := body["license_ids"].([]any); resp.StatusCode != http.StatusOK || len(ids) != 1 || ids[0] != "ISC" {
		t.Errorf("update = %d %v", resp.StatusCode, body)
	}
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/license-groups/"+groupID, bob, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin delete = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/license-groups/"+groupID, admin, ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete = %d", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/license-groups/"+groupID, admin, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("deleted group = %d, want 404", resp.StatusCode)
	}

	// Component filters, end to end: an uploaded SBOM resolves on ingest.
	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"lic","name":"Lic"}`)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgBody["id"].(string)+"/teams", admin, `{"slug":"lic","name":"Lic"}`)
	_, projBody := req(t, app, http.MethodPost, "/api/v1/teams/"+teamBody["id"].(string)+"/projects", admin, `{"slug":"lic","name":"Lic"}`)
	projectID, _ := projBody["id"].(string)
	bom := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
		{"type":"library","name":"left","version":"1","licenses":[{"expression":"mit OR gpl-3.0-only"}]},
		{"type":"library","name":"right","version":"1","licenses":[{"license":{"name":"Some Vendor EULA"}}]}]}`
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/sboms", admin, bom); resp.StatusCode != http.StatusCreated {
		t.Fatalf("upload sbom = %d", resp.StatusCode)
	}
	resp, body = req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/components?license=GPL-3.0-only", admin, "")
	comps, _ := body["components"].([]any)
	if resp.StatusCode != http.StatusOK || len(comps) != 1 {
		t.Fatalf("license filter = %d %v", resp.StatusCode, body)
	}
	left := comps[0].(map[string]any)
	if left["name"] != "left" || left["license_expression"] != "MIT OR GPL-3.0-only" || left["license_resolved"] != true {
		t.Errorf("component = %v", left)
	}
	_, body = req(t, app, http.MethodGet, "/api/v1/components?license_category=Copyleft", admin, "")
	if comps, _ := body["components"].([]any); len(comps) != 1 {
		t.Errorf("global license_category filter = %v", body["components"])
	}
	_, body = req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/components?search=right", admin, "")
	if comps, _ := body["components"].([]any); len(comps) != 1 || comps[0].(map[string]any)["license_resolved"] != false ||
		comps[0].(map[string]any)["license_ids"] == nil {
		t.Errorf("unresolved component = %v", body["components"])
	}
}
