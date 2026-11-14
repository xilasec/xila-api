package server

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// TestSmokePrivateAdvisories: the private vulnerability database over HTTP —
// admin-only writes, reads for everyone, matching an internal package in an
// uploaded SBOM into a finding, and withdrawal auto-closing it.
func TestSmokePrivateAdvisories(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "admin@xila.io")
	bob := rbacUser(t, app, "bob@xila.io")

	_, org := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"acme","name":"Acme"}`)
	_, team := req(t, app, http.MethodPost, "/api/v1/orgs/"+org["id"].(string)+"/teams", admin, `{"slug":"t","name":"T"}`)
	_, proj := req(t, app, http.MethodPost, "/api/v1/teams/"+team["id"].(string)+"/projects", admin, `{"slug":"web","name":"Web"}`)
	projectID := proj["id"].(string)
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/sboms?artifact=web", admin, smokeCycloneDX); resp.StatusCode != http.StatusCreated {
		t.Fatalf("sbom upload = %d", resp.StatusCode)
	}

	// pkgA@1.0 in the SBOM is an internal package (pkg:generic).
	advisory := `{"summary":"pkgA deserializes untrusted input","severity":"critical",
		"aliases":["CVE-2026-4242"],
		"affected":[{"package":{"purl":"pkg:generic/pkgA"},
			"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.1"}]}]}]}`
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/advisories", bob, advisory); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin create = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/advisories", admin,
		`{"summary":"x","severity":"high","affected":[{"package":{"purl":"pkg:generic/pkgA"},"ranges":[{"type":"ECOSYSTEM","events":[{"fixed":"1.1"}]}]}]}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("range without introduced = %d, want 400", resp.StatusCode)
	}
	resp, created := req(t, app, http.MethodPost, "/api/v1/advisories", admin, advisory)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d %v", resp.StatusCode, created)
	}
	id, _ := created["id"].(string)

	// Everyone signed in can read the database.
	if resp, list := req(t, app, http.MethodGet, "/api/v1/advisories", bob, ""); resp.StatusCode != http.StatusOK ||
		len(list["advisories"].([]any)) != 1 {
		t.Errorf("bob's list = %d %v", resp.StatusCode, list)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/advisories/"+id, bob, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("bob's get = %d", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodDelete, "/api/v1/advisories/"+id, bob, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin delete = %d, want 403", resp.StatusCode)
	}
	// Re-matching is an admin action too.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/vulnmatch", bob, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin vulnmatch = %d, want 403", resp.StatusCode)
	}

	resp, run := req(t, app, http.MethodPost, "/api/v1/vulnmatch", admin, "")
	if resp.StatusCode != http.StatusOK || run["findings"] != float64(1) || run["partial"] != false {
		t.Fatalf("vulnmatch = %d %v, want 1 finding", resp.StatusCode, run)
	}
	_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings?status=open&scanner=osv", admin, "")
	fs, _ := list["findings"].([]any)
	if len(fs) != 1 {
		t.Fatalf("open findings = %d, want 1", len(fs))
	}
	f := fs[0].(map[string]any)
	if f["rule_id"] != id || f["severity"] != "critical" || f["scanner"] != "osv" || f["fixed_version"] != "1.1" {
		t.Errorf("finding = %v", f)
	}

	// Withdraw it: the next match closes the finding.
	created["withdrawn"] = "2026-01-01T00:00:00Z"
	if resp, body := req(t, app, http.MethodPut, "/api/v1/advisories/"+id, admin, mustJSON(t, created)); resp.StatusCode != http.StatusOK {
		t.Fatalf("withdraw = %d %v", resp.StatusCode, body)
	}
	req(t, app, http.MethodPost, "/api/v1/vulnmatch", admin, "")
	_, list = req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings?status=open&scanner=osv", admin, "")
	if fs, _ := list["findings"].([]any); len(fs) != 0 {
		t.Errorf("open findings after withdrawal = %d, want 0", len(fs))
	}

	// OSV JSON import (one document) creates by id.
	resp, imp := req(t, app, http.MethodPost, "/api/v1/advisories/import", admin,
		`{"id":"XILA-2026-0500","modified":"2026-01-01T00:00:00Z","summary":"imported",
		  "database_specific":{"severity":"LOW"},
		  "affected":[{"package":{"ecosystem":"npm","name":"express"},"versions":["4.18.2"]}]}`)
	if resp.StatusCode != http.StatusOK || imp["created"] != float64(1) {
		t.Errorf("import = %d %v", resp.StatusCode, imp)
	}

	// The local mirror: upload rejects garbage, imports a real export (one OSV
	// record, as OSV's all.zip carries it), and is idempotent.
	if code := uploadZip(t, app, admin, []byte("not a zip")); code != http.StatusBadRequest {
		t.Errorf("garbage osv-import = %d, want 400", code)
	}
	record, err := os.ReadFile("../vulnmatch/testdata/osv/GHSA-29mw-wpgm-hmr9.json")
	if err != nil {
		t.Fatal(err)
	}
	var zbuf bytes.Buffer
	zw := zip.NewWriter(&zbuf)
	w, _ := zw.Create("GHSA-29mw-wpgm-hmr9.json")
	w.Write(record)
	zw.Close()
	if code := uploadZip(t, app, bob, zbuf.Bytes()); code != http.StatusForbidden {
		t.Errorf("non-admin osv-import = %d, want 403", code)
	}
	for range 2 {
		if code := uploadZip(t, app, admin, zbuf.Bytes()); code != http.StatusOK {
			t.Fatalf("osv-import = %d, want 200", code)
		}
	}
	resp, src := req(t, app, http.MethodGet, "/api/v1/vulnmatch/sources", admin, "")
	mirror, _ := src["mirror"].(map[string]any)
	if resp.StatusCode != http.StatusOK || len(src["sources"].([]any)) != 2 || mirror["advisories"] != float64(1) {
		t.Errorf("sources = %d %v, want 2 sources and 1 mirrored advisory", resp.StatusCode, src)
	}
}

func uploadZip(t *testing.T, app interface {
	Test(*http.Request, ...int) (*http.Response, error)
}, token string, data []byte) int {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	w, _ := mw.CreateFormFile("file", "all.zip")
	w.Write(data)
	mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/vulnmatch/osv-import", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.Header.Set("Authorization", "Bearer "+token)
	resp, err := app.Test(r, -1)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
