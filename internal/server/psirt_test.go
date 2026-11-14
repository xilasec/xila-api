package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/config"
)

// get returns the status and body of an unauthenticated GET.
func publicGet(t *testing.T, app *fiber.App, path string) (int, string) {
	t.Helper()
	res, err := app.Test(httptest.NewRequest(http.MethodGet, path, nil), -1)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// csafMandatory checks the CSAF 2.0 mandatory structure (§4 / the schema's
// required properties) of a csaf_security_advisory document.
func csafMandatory(t *testing.T, doc map[string]any) {
	t.Helper()
	d, _ := doc["document"].(map[string]any)
	if d == nil {
		t.Fatal("no document")
	}
	for _, k := range []string{"category", "csaf_version", "publisher", "title", "tracking"} {
		if d[k] == nil {
			t.Errorf("document.%s missing", k)
		}
	}
	if d["category"] != "csaf_security_advisory" || d["csaf_version"] != "2.0" {
		t.Errorf("category/version = %v / %v", d["category"], d["csaf_version"])
	}
	pub, _ := d["publisher"].(map[string]any)
	for _, k := range []string{"category", "name", "namespace"} {
		if pub[k] == nil || pub[k] == "" {
			t.Errorf("publisher.%s missing", k)
		}
	}
	tr, _ := d["tracking"].(map[string]any)
	for _, k := range []string{"id", "status", "version", "revision_history", "initial_release_date", "current_release_date"} {
		if tr[k] == nil {
			t.Errorf("tracking.%s missing", k)
		}
	}
	if rh, _ := tr["revision_history"].([]any); len(rh) == 0 {
		t.Error("revision_history empty")
	}
	if doc["product_tree"] == nil {
		t.Error("product_tree missing")
	}
	vulns, _ := doc["vulnerabilities"].([]any)
	if len(vulns) == 0 {
		t.Fatal("no vulnerabilities")
	}
	if v := vulns[0].(map[string]any); v["product_status"] == nil {
		t.Error("vulnerabilities[0].product_status missing")
	}
}

// Publish → a valid CSAF document; republish bumps the version with a
// revision; withdraw finalizes. The public provider directory is 404 unless
// PSIRT_PUBLIC, then lists the published advisory. Admin only.
func TestPSIRTPublishing(t *testing.T) {
	off := newTestApp(t)
	if code, _ := publicGet(t, off, "/.well-known/csaf/provider-metadata.json"); code != http.StatusNotFound {
		t.Errorf("provider metadata with PSIRT_PUBLIC off = %d, want 404", code)
	}

	app := newTestApp(t, func(c *config.Config) {
		c.PSIRT = config.PSIRT{Public: true, AdvisoryPrefix: "ACME-SA", PublisherName: "Acme PSIRT",
			PublisherNamespace: "https://acme.example", PublisherContact: "psirt@acme.example"}
	})
	admin := rbacUser(t, app, "founder@xila.io")
	other := rbacUser(t, app, "dev@xila.io")
	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", admin, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", admin, `{"slug":"router","name":"Router OS"}`)
	pid := p["id"].(string)

	if res, _ := req(t, app, http.MethodGet, "/api/v1/psirt/advisories", other, ""); res.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin list = %d, want 403", res.StatusCode)
	}
	res, a := req(t, app, http.MethodPost, "/api/v1/psirt/advisories", admin, `{"project_id":"`+pid+`","title":"Auth bypass in the admin UI",
		"product_name":"Router OS","summary":"An unauthenticated attacker can reach admin pages.","cve":"CVE-2026-12345","cwe":"CWE-287","cwe_name":"Improper Authentication",
		"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"affected":[{"range":"<2.4.1"}],"fixed":[{"version":"2.4.1"}],"remediation":"Upgrade to 2.4.1."}`)
	if res.StatusCode != http.StatusCreated || a["state"] != "draft" {
		t.Fatalf("create: %d %v", res.StatusCode, a)
	}
	id := a["id"].(string)
	tracking := a["tracking_id"].(string)
	if !strings.HasPrefix(tracking, "ACME-SA-") {
		t.Errorf("tracking id %q", tracking)
	}

	if res, a = req(t, app, http.MethodPost, "/api/v1/psirt/advisories/"+id+"/publish", admin, `{"note":"Initial release"}`); res.StatusCode != http.StatusOK || a["version"].(float64) != 1 {
		t.Fatalf("publish: %d %v", res.StatusCode, a)
	}
	_, doc := req(t, app, http.MethodGet, "/api/v1/psirt/advisories/"+id+"/csaf", admin, "")
	csafMandatory(t, doc)

	// Edit + republish: version 2, two revisions.
	req(t, app, http.MethodPut, "/api/v1/psirt/advisories/"+id, admin, asJSON(t, map[string]any{
		"project_id": pid, "title": "Auth bypass in the admin UI", "product_name": "Router OS",
		"summary": "Also affects the REST API.", "cve": "CVE-2026-12345", "cwe": "CWE-287", "cwe_name": "Improper Authentication",
		"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"affected":    []any{map[string]any{"range": "<2.4.1"}}, "fixed": []any{map[string]any{"version": "2.4.1"}},
		"remediation": "Upgrade to 2.4.1."}))
	if res, a = req(t, app, http.MethodPost, "/api/v1/psirt/advisories/"+id+"/publish", admin, `{"note":"REST API also affected"}`); res.StatusCode != http.StatusOK || a["version"].(float64) != 2 {
		t.Fatalf("republish: %d %v", res.StatusCode, a)
	}
	_, doc = req(t, app, http.MethodGet, "/api/v1/psirt/advisories/"+id+"/csaf", admin, "")
	csafMandatory(t, doc)
	rh := doc["document"].(map[string]any)["tracking"].(map[string]any)["revision_history"].([]any)
	if len(rh) != 2 {
		t.Errorf("revision_history = %d entries, want 2", len(rh))
	}

	// Public directory: provider metadata, index lists the file, the file is the document.
	code, meta := publicGet(t, app, "/.well-known/csaf/provider-metadata.json")
	if code != http.StatusOK || !strings.Contains(meta, "Acme PSIRT") {
		t.Errorf("provider metadata: %d %.200s", code, meta)
	}
	code, index := publicGet(t, app, "/csaf/advisories/index.txt")
	file := strings.TrimSpace(index)
	if code != http.StatusOK || !strings.HasSuffix(file, strings.ToLower(strings.ReplaceAll(tracking, "_", "_"))+".json") {
		t.Fatalf("index: %d %q", code, index)
	}
	code, body := publicGet(t, app, "/csaf/advisories/"+file)
	var pub map[string]any
	if code != http.StatusOK || json.Unmarshal([]byte(body), &pub) != nil {
		t.Fatalf("published file %s: %d", file, code)
	}
	csafMandatory(t, pub)

	if res, a = req(t, app, http.MethodPost, "/api/v1/psirt/advisories/"+id+"/withdraw", admin, `{"note":"Duplicate of ACME-SA-2026-0001"}`); res.StatusCode != http.StatusOK || a["state"] != "withdrawn" {
		t.Errorf("withdraw: %d %v", res.StatusCode, a)
	}
}
