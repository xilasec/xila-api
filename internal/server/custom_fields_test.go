package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Typed custom fields end to end: definitions are admin-only; values are
// written by editors (not viewers) and validated against the definition
// (type, enum membership, unknown key, a user who can see the project);
// ?cf.<key>= filters the lists and the export, which carries one column per
// field; a change lands in the finding's history; a triage rule reads
// finding.custom / project.custom in CEL and sets a field with
// set_custom_field, idempotently.
func TestCustomFields(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "founder@xila.io")
	editor := rbacUser(t, app, "editor@xila.io")
	viewer := rbacUser(t, app, "viewer@xila.io")
	outsider := rbacUser(t, app, "outsider@xila.io")
	userID := func(tok string) string {
		t.Helper()
		_, me := req(t, app, http.MethodGet, "/api/v1/me", tok, "")
		id, _ := me["id"].(string)
		if id == "" {
			t.Fatalf("GET /me: %v", me)
		}
		return id
	}

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", admin, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", admin, `{"slug":"web","name":"web"}`)
	pid := p["id"].(string)
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/members", admin, `{"email":"editor@xila.io","role":"editor"}`)
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/members", admin, `{"email":"viewer@xila.io","role":"viewer"}`)

	// Definitions: admin-only to change, readable by anyone signed in.
	if res, _ := req(t, app, http.MethodPost, "/api/v1/custom-fields", editor,
		`{"entity":"finding","key":"team","label":"Team","type":"enum","options":["payments","web"]}`); res.StatusCode != http.StatusForbidden {
		t.Errorf("editor creating a definition = %d, want 403", res.StatusCode)
	}
	// Created in order: an export's custom columns follow definition order.
	defs := [][2]string{
		{"team", `{"entity":"finding","key":"team","label":"Owning team","type":"enum","options":["payments","web"]}`},
		{"score", `{"entity":"finding","key":"score","label":"Risk score","type":"number"}`},
		{"due", `{"entity":"finding","key":"due","label":"Fix by","type":"date"}`},
		{"owner", `{"entity":"finding","key":"owner","label":"Risk owner","type":"user"}`},
		{"tier", `{"entity":"project","key":"tier","label":"Tier","type":"enum","options":["gold","silver"]}`},
		{"env", `{"entity":"asset","key":"env","label":"Environment","type":"text"}`},
	}
	fieldIDs := map[string]string{}
	for _, d := range defs {
		res, out := req(t, app, http.MethodPost, "/api/v1/custom-fields", admin, d[1])
		if res.StatusCode != http.StatusCreated {
			t.Fatalf("create %s: %d %v", d[0], res.StatusCode, out)
		}
		fieldIDs[d[0]] = out["id"].(string)
	}
	for name, body := range map[string]string{
		"enum without options": `{"entity":"finding","key":"x","label":"X","type":"enum"}`,
		"bad key":              `{"entity":"finding","key":"Bad-Key","label":"X","type":"text"}`,
		"bad type":             `{"entity":"finding","key":"y","label":"Y","type":"blob"}`,
	} {
		if res, _ := req(t, app, http.MethodPost, "/api/v1/custom-fields", admin, body); res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d, want 400", name, res.StatusCode)
		}
	}
	if res, _ := req(t, app, http.MethodPost, "/api/v1/custom-fields", admin, defs[0][1]); res.StatusCode != http.StatusConflict {
		t.Errorf("duplicate key = %d, want 409", res.StatusCode)
	}
	res, list := req(t, app, http.MethodGet, "/api/v1/custom-fields?entity=finding&project_id="+pid, viewer, "")
	if fields, _ := list["custom_fields"].([]any); res.StatusCode != http.StatusOK || len(fields) != 4 {
		t.Errorf("viewer listing finding fields: %d %v", res.StatusCode, list)
	}
	if res, _ := req(t, app, http.MethodPatch, "/api/v1/custom-fields/"+fieldIDs["score"], editor, `{"label":"x"}`); res.StatusCode != http.StatusForbidden {
		t.Errorf("editor editing a definition = %d, want 403", res.StatusCode)
	}

	// Two findings.
	const semgrep = `{"results":[
		{"check_id":"go.sqli","path":"db/query.go","start":{"line":42},"end":{"line":42},"extra":{"message":"SQL injection","severity":"ERROR"}},
		{"check_id":"go.xss","path":"web/page.go","start":{"line":7},"end":{"line":7},"extra":{"message":"XSS","severity":"WARNING"}}]}`
	if res, body := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=semgrep", editor, semgrep); res.StatusCode != http.StatusCreated {
		t.Fatalf("upload: %d %v", res.StatusCode, body)
	}
	_, fl := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/findings", editor, "")
	var sqli, xss string
	for _, x := range fl["findings"].([]any) {
		f := x.(map[string]any)
		if f["custom"] == nil {
			t.Errorf("custom must serialize as {}, got null")
		}
		if f["rule_id"] == "go.sqli" {
			sqli = f["id"].(string)
		} else {
			xss = f["id"].(string)
		}
	}
	if sqli == "" || xss == "" {
		t.Fatalf("findings: %v", fl)
	}

	// Value validation.
	path := "/api/v1/findings/" + sqli + "/custom"
	for name, body := range map[string]string{
		"enum value not an option":    `{"team":"marketing"}`,
		"number given text":           `{"score":"high"}`,
		"date not YYYY-MM-DD":         `{"due":"next week"}`,
		"unknown key":                 `{"nope":"x"}`,
		"project field on a finding":  `{"tier":"gold"}`,
		"user who can't see project":  `{"owner":"` + userID(outsider) + `"}`,
		"user field that's not an id": `{"owner":"bob"}`,
	} {
		if res, out := req(t, app, http.MethodPatch, path, editor, body); res.StatusCode != http.StatusBadRequest {
			t.Errorf("%s = %d %v, want 400", name, res.StatusCode, out)
		}
	}
	if res, _ := req(t, app, http.MethodPatch, path, viewer, `{"team":"payments"}`); res.StatusCode != http.StatusForbidden {
		t.Errorf("viewer setting a value = %d, want 403", res.StatusCode)
	}
	editorID := userID(editor)
	res, out := req(t, app, http.MethodPatch, path, editor,
		`{"team":"payments","score":7,"due":"2026-12-01","owner":"`+editorID+`"}`)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("editor setting values: %d %v", res.StatusCode, out)
	}
	if c := out["custom"].(map[string]any); c["team"] != "payments" || c["score"] != 7.0 || c["owner"] != editorID {
		t.Errorf("stored values = %v", c)
	}
	_, got := req(t, app, http.MethodGet, "/api/v1/findings/"+sqli, viewer, "")
	if c, _ := got["custom"].(map[string]any); c["due"] != "2026-12-01" {
		t.Errorf("GET finding custom = %v", got["custom"])
	}

	// Filters.
	count := func(url string) int {
		t.Helper()
		res, body := req(t, app, http.MethodGet, url, viewer, "")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: %d %v", url, res.StatusCode, body)
		}
		n := 0
		for _, k := range []string{"findings", "projects", "assets"} {
			if xs, ok := body[k].([]any); ok {
				n = len(xs)
			}
		}
		return n
	}
	base := "/api/v1/projects/" + pid + "/findings?"
	for q, want := range map[string]int{
		"cf.team=payments":           1,
		"cf.team=web":                0,
		"cf.score=7":                 1,
		"cf.score.gte=5":             1,
		"cf.score.gt=7":              0,
		"cf.due.lt=2027-01-01":       1,
		"cf.due.gte=2027-01-01":      0,
		"cf.team.set=false":          1,
		"cf.score.lte=9&cf.team=web": 0,
	} {
		if got := count(base + q); got != want {
			t.Errorf("?%s: %d findings, want %d", q, got, want)
		}
	}
	if got := count("/api/v1/findings?cf.owner=" + editorID); got != 1 {
		t.Errorf("portfolio ?cf.owner: %d, want 1", got)
	}
	for _, q := range []string{"cf.score.between=1", "cf.score.gte=soon", "cf.Bad=1"} {
		if res, _ := req(t, app, http.MethodGet, base+q, viewer, ""); res.StatusCode != http.StatusBadRequest {
			t.Errorf("?%s = %d, want 400", q, res.StatusCode)
		}
	}

	// Export: one column per field, through the same filter.
	r := httptest.NewRequest(http.MethodGet, "/api/v1/projects/"+pid+"/findings/export?format=csv&cf.team=payments", nil)
	r.Header.Set("Authorization", "Bearer "+viewer)
	resp, err := app.Test(r, -1)
	if err != nil {
		t.Fatal(err)
	}
	csv, _ := io.ReadAll(resp.Body)
	lines := strings.Split(strings.TrimSpace(string(csv)), "\n")
	if resp.StatusCode != http.StatusOK || len(lines) != 2 ||
		!strings.HasSuffix(strings.TrimSpace(lines[0]), "Owning team,Risk score,Fix by,Risk owner") ||
		!strings.HasSuffix(strings.TrimSpace(lines[1]), "payments,7,2026-12-01,editor@xila.io") {
		t.Errorf("export (%d):\n%s", resp.StatusCode, csv)
	}

	// History: one event per changed field, credited to the editor.
	_, hist := req(t, app, http.MethodGet, "/api/v1/findings/"+sqli+"/history", viewer, "")
	var teamEvent, ownerEvent map[string]any
	for _, x := range hist["events"].([]any) {
		e := x.(map[string]any)
		if e["kind"] == "custom_field" && e["field"] == "team" {
			teamEvent = e
		}
		if e["kind"] == "custom_field" && e["field"] == "owner" {
			ownerEvent = e
		}
	}
	if teamEvent == nil || teamEvent["to"] != "payments" || teamEvent["from"] != nil || teamEvent["actor_name"] != "editor@xila.io" {
		t.Errorf("team history event = %v (history %v)", teamEvent, hist)
	}
	if ownerEvent == nil || ownerEvent["to"] != "editor@xila.io" {
		t.Errorf("user field history shows the email: %v", ownerEvent)
	}

	// Project and asset values; project list filter.
	if res, out := req(t, app, http.MethodPatch, "/api/v1/projects/"+pid+"/custom", editor, `{"tier":"gold"}`); res.StatusCode != http.StatusOK {
		t.Fatalf("project custom: %d %v", res.StatusCode, out)
	}
	if res, _ := req(t, app, http.MethodPatch, "/api/v1/projects/"+pid+"/custom", editor, `{"tier":"bronze"}`); res.StatusCode != http.StatusBadRequest {
		t.Errorf("bad project enum = %d, want 400", res.StatusCode)
	}
	if got := count("/api/v1/projects?cf.tier=gold"); got != 1 {
		t.Errorf("projects ?cf.tier=gold: %d", got)
	}
	if got := count("/api/v1/projects?cf.tier=silver"); got != 0 {
		t.Errorf("projects ?cf.tier=silver: %d", got)
	}
	_, a := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/assets", editor, `{"type":"host","name":"db-1","identifier":"db-1"}`)
	aid, _ := a["id"].(string)
	if res, out := req(t, app, http.MethodPatch, "/api/v1/assets/"+aid+"/custom", editor, `{"env":"prod"}`); res.StatusCode != http.StatusOK {
		t.Fatalf("asset custom: %d %v", res.StatusCode, out)
	}
	if got := count("/api/v1/projects/" + pid + "/assets?cf.env=prod"); got != 1 {
		t.Errorf("assets ?cf.env=prod: %d", got)
	}

	// Triage: CEL reads finding.custom and project.custom; set_custom_field
	// writes, validated against the field.
	if res, _ := req(t, app, http.MethodPost, "/api/v1/triage-rules", admin,
		`{"name":"r","action":"set_custom_field","custom_field":"team","custom_value":"marketing"}`); res.StatusCode != http.StatusBadRequest {
		t.Errorf("rule with a bad enum value = %d, want 400", res.StatusCode)
	}
	if res, _ := req(t, app, http.MethodPost, "/api/v1/triage-rules", admin,
		`{"name":"r","action":"false_positive","expression":"finding.custom.nope == 1"}`); res.StatusCode != http.StatusBadRequest {
		t.Errorf("rule reading an undefined field = %d, want 400", res.StatusCode)
	}
	res, rule := req(t, app, http.MethodPost, "/api/v1/triage-rules", admin,
		`{"name":"route to web","enabled":true,"action":"set_custom_field","custom_field":"team","custom_value":"web",
		  "expression":"finding.custom.score >= 5 && project.custom.tier == \"gold\""}`)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create rule: %d %v", res.StatusCode, rule)
	}
	_, applied := req(t, app, http.MethodPost, "/api/v1/triage-rules/apply?project_id="+pid, admin, "")
	if applied["applied"] != 1.0 {
		t.Errorf("first apply = %v, want 1", applied)
	}
	_, got = req(t, app, http.MethodGet, "/api/v1/findings/"+sqli, viewer, "")
	if c := got["custom"].(map[string]any); c["team"] != "web" {
		t.Errorf("rule didn't set team: %v", c)
	}
	_, got = req(t, app, http.MethodGet, "/api/v1/findings/"+xss, viewer, "")
	if c := got["custom"].(map[string]any); len(c) != 0 {
		t.Errorf("finding without a score was changed: %v", c)
	}
	if _, again := req(t, app, http.MethodPost, "/api/v1/triage-rules/apply?project_id="+pid, admin, ""); again["applied"] != 0.0 {
		t.Errorf("second apply = %v, want 0 (idempotent)", again)
	}
	_, hist = req(t, app, http.MethodGet, "/api/v1/findings/"+sqli+"/history", viewer, "")
	events := hist["events"].([]any)
	last := events[len(events)-1].(map[string]any)
	if last["kind"] != "custom_field" || last["from"] != "payments" || last["to"] != "web" || last["actor"] != "triage-rule:route to web" {
		t.Errorf("rule's history event = %v", last)
	}

	// Deleting a definition removes its values (recorded) and its filter
	// matches nothing.
	if res, _ := req(t, app, http.MethodDelete, "/api/v1/custom-fields/"+fieldIDs["score"], admin, ""); res.StatusCode != http.StatusNoContent {
		t.Errorf("delete definition = %d", res.StatusCode)
	}
	if got := count(base + "cf.score=7"); got != 0 {
		t.Errorf("values survived their definition: %d", got)
	}
}
