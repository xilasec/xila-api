package server

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The analyst workflow over HTTP: bulk triage authorizes every finding on its
// own project, assignees must be able to see the project, evidence downloads
// can't run in our origin, and every change lands in the finding's history.
func TestAnalystWorkflow(t *testing.T) {
	app := newTestApp(t)
	owner := rbacUser(t, app, "founder@xila.io") // first user: instance admin
	lead := rbacUser(t, app, "lead@xila.io")
	dana := rbacUser(t, app, "dana@xila.io")
	_ = rbacUser(t, app, "outsider@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", lead, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)
	project := func(slug string) (projectID, findingID string) {
		t.Helper()
		_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", lead, `{"slug":"`+slug+`","name":"`+slug+`"}`)
		projectID, _ = p["id"].(string)
		req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/scans?scanner=trivy", lead, smokeTrivyReport)
		_, list := req(t, app, http.MethodGet, "/api/v1/projects/"+projectID+"/findings?severity=critical", lead, "")
		fs, _ := list["findings"].([]any)
		if len(fs) != 1 {
			t.Fatalf("seed %s: %d critical findings", slug, len(fs))
		}
		findingID, _ = fs[0].(map[string]any)["id"].(string)
		return projectID, findingID
	}
	projectA, findingA := project("alpha")
	_, findingB := project("beta")
	req(t, app, http.MethodPost, "/api/v1/projects/"+projectA+"/members", lead, `{"email":"dana@xila.io","role":"editor"}`)
	danaID := userIDOf(t, app, owner, "dana@xila.io")
	outsiderID := userIDOf(t, app, owner, "outsider@xila.io")

	// Bulk across two projects: Dana edits A only; B is reported, not touched,
	// and indistinguishable from a finding that doesn't exist.
	resp, bulk := req(t, app, http.MethodPost, "/api/v1/findings/bulk", dana,
		`{"ids":["`+findingA+`","`+findingB+`","not-an-id"],"status":"false_positive","reason":"test fixture"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bulk = %d %v", resp.StatusCode, bulk)
	}
	updated, _ := bulk["updated"].([]any)
	failed, _ := bulk["failed"].([]any)
	if len(updated) != 1 || len(failed) != 2 {
		t.Fatalf("bulk updated %d failed %d, want 1 / 2", len(updated), len(failed))
	}
	for _, raw := range failed {
		if f, _ := raw.(map[string]any); f["id"] == findingB && f["error"] != "finding not found" {
			t.Errorf("unauthorized finding reported as %q, want the same as a missing one", f["error"])
		}
	}
	_, gotB := req(t, app, http.MethodGet, "/api/v1/findings/"+findingB, lead, "")
	if gotB["status"] != "open" {
		t.Errorf("finding B = %v after a bulk edit Dana can't make, want open", gotB["status"])
	}

	// Assignment: the assignee must be able to see the project.
	if resp, _ := req(t, app, http.MethodPut, "/api/v1/findings/"+findingA+"/assignee", dana,
		`{"assignee_id":"`+outsiderID+`"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("assigning to someone without access = %d, want 400", resp.StatusCode)
	}
	resp, assigned := req(t, app, http.MethodPut, "/api/v1/findings/"+findingA+"/assignee", dana, `{"assignee_id":"`+danaID+`"}`)
	if resp.StatusCode != http.StatusOK || assigned["assignee_email"] != "dana@xila.io" {
		t.Fatalf("self-assign = %d %v", resp.StatusCode, assigned["assignee_email"])
	}
	_, mine := req(t, app, http.MethodGet, "/api/v1/findings?assignee=me&status=false_positive", dana, "")
	if fs, _ := mine["findings"].([]any); len(fs) != 1 {
		t.Errorf("?assignee=me = %d findings, want 1", len(fs))
	}
	_, assignees := req(t, app, http.MethodGet, "/api/v1/projects/"+projectA+"/assignees", dana, "")
	if as, _ := assignees["assignees"].([]any); len(as) != 3 { // lead (owner), dana (editor), founder (admin)
		t.Errorf("assignees = %v, want lead, dana and the instance admin", assignees["assignees"])
	}

	// Comments: editors write; the author or a project owner may delete.
	resp, comment := req(t, app, http.MethodPost, "/api/v1/findings/"+findingA+"/comments", dana, `{"body":"repro in staging"}`)
	if resp.StatusCode != http.StatusCreated || comment["author"] != "dana@xila.io" {
		t.Fatalf("comment = %d %v", resp.StatusCode, comment)
	}

	// Evidence: an uploaded HTML file is served as an opaque download.
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "../../poc.html")
	io.WriteString(fw, "<html><script>alert(1)</script></html>")
	mw.Close()
	upload := httptest.NewRequest(http.MethodPost, "/api/v1/findings/"+findingA+"/attachments", &buf)
	upload.Header.Set("Content-Type", mw.FormDataContentType())
	upload.Header.Set("Authorization", "Bearer "+dana)
	upResp, err := app.Test(upload, -1)
	if err != nil || upResp.StatusCode != http.StatusCreated {
		t.Fatalf("upload = %v %v", upResp.StatusCode, err)
	}
	_, list := req(t, app, http.MethodGet, "/api/v1/findings/"+findingA+"/attachments", dana, "")
	atts, _ := list["attachments"].([]any)
	if len(atts) != 1 {
		t.Fatalf("attachments = %v", list)
	}
	att, _ := atts[0].(map[string]any)
	if att["filename"] != "poc.html" {
		t.Errorf("stored filename = %v, want the path stripped", att["filename"])
	}
	dl := httptest.NewRequest(http.MethodGet, "/api/v1/findings/"+findingA+"/attachments/"+att["id"].(string), nil)
	dl.Header.Set("Authorization", "Bearer "+dana)
	dlResp, _ := app.Test(dl, -1)
	if ct := dlResp.Header.Get("Content-Type"); ct != "application/octet-stream" ||
		dlResp.Header.Get("X-Content-Type-Options") != "nosniff" ||
		!strings.HasPrefix(dlResp.Header.Get("Content-Disposition"), "attachment") {
		t.Errorf("html download headers = %q / %q / %q", ct, dlResp.Header.Get("X-Content-Type-Options"), dlResp.Header.Get("Content-Disposition"))
	}

	// The history has it all, attributed.
	_, hist := req(t, app, http.MethodGet, "/api/v1/findings/"+findingA+"/history", dana, "")
	events, _ := hist["events"].([]any)
	var kinds []string
	for _, raw := range events {
		e, _ := raw.(map[string]any)
		kinds = append(kinds, e["kind"].(string))
		if e["kind"] == "status" && (e["actor_name"] != "dana@xila.io" || e["note"] != "test fixture") {
			t.Errorf("status event = %v, want Dana with her reason", e)
		}
	}
	if strings.Join(kinds, ",") != "created,status,assignee,comment,attachment" {
		t.Errorf("history kinds = %v", kinds)
	}

	// A project-scoped bulk call with nothing to change is a 400, not a no-op 200.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/findings/bulk", dana, `{"ids":["`+findingA+`"]}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("empty bulk change = %d, want 400", resp.StatusCode)
	}
	// Bulk by filter: "everything open I can see" never reaches project B.
	_, openA := req(t, app, http.MethodGet, "/api/v1/projects/"+projectA+"/findings?status=open&limit=200", lead, "")
	wantA, _ := openA["findings"].([]any)
	resp, byFilter := req(t, app, http.MethodPost, "/api/v1/findings/bulk", dana,
		`{"filter":{"status":"open"},"severity":"low","reason":"bulk by filter"}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bulk by filter = %d %v", resp.StatusCode, byFilter)
	}
	if got, _ := byFilter["updated"].([]any); len(wantA) == 0 || len(got) != len(wantA) {
		t.Errorf("bulk by filter updated %d, want project A's %d open findings", len(got), len(wantA))
	}
	if _, b := req(t, app, http.MethodGet, "/api/v1/findings/"+findingB, lead, ""); b["severity"] != "critical" {
		t.Errorf("finding B severity = %v after Dana's filter bulk, want untouched", b["severity"])
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/findings/bulk", dana,
		`{"ids":["`+findingA+`"],"filter":{"status":"open"},"severity":"low"}`); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("ids and filter together = %d, want 400", resp.StatusCode)
	}
}
