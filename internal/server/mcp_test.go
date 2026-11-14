package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/config"
)

// rpc posts one JSON-RPC message to /api/v1/mcp.
func rpc(t *testing.T, app *fiber.App, token, method string, params any) (int, map[string]any) {
	t.Helper()
	p, _ := json.Marshal(params)
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":%q,"params":%s}`, method, p)
	res, out := req(t, app, http.MethodPost, "/api/v1/mcp", token, body)
	return res.StatusCode, out
}

// toolCall runs one tool; it returns the result's text and isError.
func toolCall(t *testing.T, app *fiber.App, token, name string, args map[string]any) (string, bool) {
	t.Helper()
	_, out := rpc(t, app, token, "tools/call", map[string]any{"name": name, "arguments": args})
	result, ok := out["result"].(map[string]any)
	if !ok {
		t.Fatalf("%s: no result: %v", name, out)
	}
	content := result["content"].([]any)[0].(map[string]any)
	return content["text"].(string), result["isError"].(bool)
}

// The MCP server runs every tool as the caller: a viewer of one project can't
// read another's findings or triage; an editor can, and the finding's history
// and the audit log name the editor (and the tool). Off, the endpoint is a 404.
func TestMCPServer(t *testing.T) {
	if code, _ := rpc(t, newTestApp(t), "", "ping", nil); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", code)
	}
	off := newTestApp(t)
	tok := rbacUser(t, off, "founder@xila.io")
	if code, _ := rpc(t, off, tok, "ping", nil); code != http.StatusNotFound {
		t.Fatalf("disabled: %d, want 404", code)
	}

	app := newTestApp(t, func(c *config.Config) { c.MCPEnabled = true })
	admin := rbacUser(t, app, "founder@xila.io")
	editor := rbacUser(t, app, "editor@xila.io")
	viewer := rbacUser(t, app, "viewer@xila.io")
	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", admin, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)
	project := func(slug string) string {
		_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", admin, `{"slug":"`+slug+`","name":"`+slug+`"}`)
		return p["id"].(string)
	}
	a, b := project("a"), project("b")
	req(t, app, http.MethodPost, "/api/v1/projects/"+a+"/members", admin, `{"email":"editor@xila.io","role":"editor"}`)
	req(t, app, http.MethodPost, "/api/v1/projects/"+a+"/members", admin, `{"email":"viewer@xila.io","role":"viewer"}`)
	if res, body := req(t, app, http.MethodPost, "/api/v1/projects/"+b+"/scans?scanner=trivy", admin, fixPlanTrivy); res.StatusCode != http.StatusCreated {
		t.Fatalf("seed b: %d %v", res.StatusCode, body)
	}

	// Handshake.
	_, init := rpc(t, app, viewer, "initialize", map[string]any{"protocolVersion": "2025-03-26",
		"capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "test", "version": "1"}})
	if r := init["result"].(map[string]any); r["protocolVersion"] != "2025-03-26" {
		t.Errorf("initialize = %v", r)
	}
	r := httptestPost(t, app, viewer, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if r != http.StatusAccepted {
		t.Errorf("notification answered %d, want 202", r)
	}
	_, list := rpc(t, app, viewer, "tools/list", nil)
	tools := list["result"].(map[string]any)["tools"].([]any)
	names := map[string]map[string]any{}
	for _, x := range tools {
		tl := x.(map[string]any)
		names[tl["name"].(string)] = tl
	}
	for _, n := range []string{"search_findings", "get_finding", "triage_finding", "list_projects", "get_fix_plan",
		"list_remediation_actions", "upload_scan", "upload_sbom", "generate_vex", "get_gate_result", "ask_ai"} {
		if names[n] == nil {
			t.Errorf("tools/list lacks %s", n)
		}
	}
	if ann := names["triage_finding"]["annotations"].(map[string]any); ann["readOnlyHint"] != false {
		t.Errorf("triage_finding annotations = %v", ann)
	}
	if ann := names["upload_scan"]["annotations"].(map[string]any); ann["destructiveHint"] != true {
		t.Errorf("upload_scan annotations = %v", ann)
	}

	// The editor uploads to a through MCP; the viewer sees a's findings only.
	if text, isErr := toolCall(t, app, editor, "upload_scan", map[string]any{"project_id": a, "scanner": "trivy", "report": fixPlanTrivy}); isErr {
		t.Fatalf("upload_scan: %s", text)
	}
	text, isErr := toolCall(t, app, viewer, "search_findings", map[string]any{"limit": 100})
	var page struct {
		Findings []struct {
			ID        string `json:"id"`
			ProjectID string `json:"project_id"`
		} `json:"findings"`
	}
	if isErr || json.Unmarshal([]byte(text), &page) != nil || len(page.Findings) == 0 {
		t.Fatalf("viewer search: %v %.300s", isErr, text)
	}
	for _, f := range page.Findings {
		if f.ProjectID != a {
			t.Errorf("viewer of a sees a finding of %s", f.ProjectID)
		}
	}
	if text, isErr := toolCall(t, app, viewer, "search_findings", map[string]any{"project_id": b}); !isErr {
		t.Errorf("viewer read project b through MCP: %.200s", text)
	}

	// Triage: the viewer is refused; the editor's change lands as theirs.
	fid := page.Findings[0].ID
	if text, isErr := toolCall(t, app, viewer, "triage_finding", map[string]any{"finding_id": fid, "status": "confirmed"}); !isErr {
		t.Errorf("viewer triaged through MCP: %s", text)
	}
	if text, isErr := toolCall(t, app, editor, "triage_finding", map[string]any{"finding_id": fid, "status": "confirmed",
		"comment": "seen in prod"}); isErr {
		t.Fatalf("editor triage: %s", text)
	}
	_, f := req(t, app, http.MethodGet, "/api/v1/findings/"+fid, editor, "")
	if f["status"] != "confirmed" {
		t.Errorf("status after triage = %v", f["status"])
	}
	_, hist := req(t, app, http.MethodGet, "/api/v1/findings/"+fid+"/history", editor, "")
	if !strings.Contains(fmt.Sprint(hist), "editor@xila.io") {
		t.Errorf("history doesn't name the editor: %v", hist)
	}
	_, logs := req(t, app, http.MethodGet, "/api/v1/audit-log?action=findings&limit=50", admin, "")
	if !strings.Contains(fmt.Sprint(logs), "mcp:triage_finding") {
		t.Errorf("audit log doesn't name the MCP tool: %.600v", logs)
	}
	// The envelope isn't an action: read-only tool calls leave no audit entry.
	if _, all := req(t, app, http.MethodGet, "/api/v1/audit-log?limit=200", admin, ""); strings.Contains(fmt.Sprint(all), "path:/api/v1/mcp ") {
		t.Error("the MCP envelope itself was audited")
	}

	// The gate's "fail" is a result, not a tool error.
	if text, isErr := toolCall(t, app, editor, "get_gate_result", map[string]any{"project_id": a}); isErr || !strings.Contains(text, "passed") {
		t.Errorf("gate: %v %.200s", isErr, text)
	}
	// Unknown tools and missing arguments are reported, not crashed on.
	if _, out := rpc(t, app, viewer, "tools/call", map[string]any{"name": "rm_rf"}); out["error"] == nil {
		t.Errorf("unknown tool: %v", out)
	}
	if text, isErr := toolCall(t, app, viewer, "get_finding", map[string]any{}); !isErr || !strings.Contains(text, "finding_id") {
		t.Errorf("missing argument: %v %s", isErr, text)
	}
}

func httptestPost(t *testing.T, app *fiber.App, token, body string) int {
	t.Helper()
	res, _ := req(t, app, http.MethodPost, "/api/v1/mcp", token, body)
	return res.StatusCode
}
