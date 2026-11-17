package server

import (
	"net/http"
	"testing"
)

// Computed custom fields: a definition with an expression instead of a
// person's write. Values are computed from the entity's facts on ingest,
// recomputed when the definition's expression changes, refused as a direct
// write, filterable like any field, and recorded in a finding's history as a
// system change.
func TestComputedCustomFields(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "founder@xila.io")
	editor := rbacUser(t, app, "editor@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", admin, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", admin, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)
	_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", admin, `{"slug":"web","name":"web"}`)
	pid := p["id"].(string)
	req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/members", admin, `{"email":"editor@xila.io","role":"editor"}`)

	// An invalid expression is refused on save.
	if res, out := req(t, app, http.MethodPost, "/api/v1/custom-fields", admin,
		`{"entity":"finding","key":"bad","label":"Bad","type":"text","computed":true,"expression":"finding.nope +"}`); res.StatusCode != http.StatusBadRequest {
		t.Errorf("syntax error = %d %v, want 400", res.StatusCode, out)
	}
	if res, out := req(t, app, http.MethodPost, "/api/v1/custom-fields", admin,
		`{"entity":"finding","key":"bad2","label":"Bad2","type":"number","computed":true,"expression":"\"x\""}`); res.StatusCode != http.StatusBadRequest {
		t.Errorf("result never fits number = %d %v, want 400", res.StatusCode, out)
	}

	// A computed finding field: urgent when KEV and critical, else normal.
	res, urgency := req(t, app, http.MethodPost, "/api/v1/custom-fields", admin,
		`{"entity":"finding","key":"urgency","label":"Urgency","type":"enum","options":["urgent","normal"],
		  "computed":true,"expression":"finding.kev && finding.severity == 'critical' ? 'urgent' : 'normal'"}`)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create computed field: %d %v", res.StatusCode, urgency)
	}
	urgencyID := urgency["id"].(string)

	// A computed project field: label by criticality.
	res, tier := req(t, app, http.MethodPost, "/api/v1/custom-fields", admin,
		`{"entity":"project","key":"tier","label":"Tier","type":"text","computed":true,
		  "expression":"project.criticality == 'critical' ? 'tier-0' : 'tier-1'"}`)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create project computed field: %d %v", res.StatusCode, tier)
	}

	// A computed asset field reading asset.* and project.*.
	res, envField := req(t, app, http.MethodPost, "/api/v1/custom-fields", admin,
		`{"entity":"asset","key":"risk","label":"Risk","type":"text","computed":true,
		  "expression":"asset.exposure == 'internet' ? 'high' : 'low'"}`)
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("create asset computed field: %d %v", res.StatusCode, envField)
	}

	// Ingest: a KEV critical finding. Grype reports KEV via relatedVulnerabilities.
	const grype = `{"matches":[{"vulnerability":{"id":"CVE-2021-44228","severity":"Critical",
		"cvss":[{"metrics":{"baseScore":10.0}}],
		"dataSource":"https://example/CVE-2021-44228",
		"fix":{"versions":["2.15.0"]},
		"description":"Log4Shell"},
		"artifact":{"name":"log4j-core","version":"2.14.1","type":"java","purl":"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"}}]}`
	if res, body := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/scans?scanner=grype", editor, grype); res.StatusCode != http.StatusCreated {
		t.Fatalf("upload: %d %v", res.StatusCode, body)
	}
	_, fl := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/findings", editor, "")
	findings, _ := fl["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("findings: %v", fl)
	}
	f := findings[0].(map[string]any)
	fid := f["id"].(string)
	// KEV is only set by a KEV catalog sync, not by the scanner report, so this
	// finding is not actually KEV — the computed field should read "normal".
	custom, _ := f["custom"].(map[string]any)
	if custom["urgency"] != "normal" {
		t.Errorf("computed field on ingest = %v, want normal (not KEV)", custom)
	}

	// Can't be written directly, even by an editor.
	if res, out := req(t, app, http.MethodPatch, "/api/v1/findings/"+fid+"/custom", editor, `{"urgency":"urgent"}`); res.StatusCode != http.StatusBadRequest {
		t.Errorf("direct write to a computed field = %d %v, want 400", res.StatusCode, out)
	}

	// Filters with ?cf.<key>= like any field.
	res, list := req(t, app, http.MethodGet, "/api/v1/projects/"+pid+"/findings?cf.urgency=normal", editor, "")
	if ff, _ := list["findings"].([]any); res.StatusCode != http.StatusOK || len(ff) != 1 {
		t.Errorf("?cf.urgency=normal: %d %v", res.StatusCode, list)
	}

	// Changing the expression recomputes immediately (synchronously, within
	// the PATCH response): now every finding is "urgent".
	if res, out := req(t, app, http.MethodPatch, "/api/v1/custom-fields/"+urgencyID, admin,
		`{"expression":"'urgent'"}`); res.StatusCode != http.StatusOK {
		t.Fatalf("update expression: %d %v", res.StatusCode, out)
	}
	_, got := req(t, app, http.MethodGet, "/api/v1/findings/"+fid, editor, "")
	if c, _ := got["custom"].(map[string]any); c["urgency"] != "urgent" {
		t.Errorf("recompute after definition change = %v, want urgent", got["custom"])
	}

	// Shows in history as a system change, not attributed to any person.
	_, hist := req(t, app, http.MethodGet, "/api/v1/findings/"+fid+"/history", editor, "")
	var event map[string]any
	for _, x := range hist["events"].([]any) {
		e := x.(map[string]any)
		if e["kind"] == "custom_field" && e["field"] == "urgency" {
			event = e
		}
	}
	if event == nil || event["to"] != "urgent" || event["actor"] != "computed-fields" {
		t.Errorf("urgency history event = %v", event)
	}

	// Project computed field: the project isn't critical by default, so tier-1.
	_, proj := req(t, app, http.MethodGet, "/api/v1/projects/"+pid, editor, "")
	if c, _ := proj["custom"].(map[string]any); c["tier"] != "tier-1" {
		t.Errorf("project computed field = %v, want tier-1", proj["custom"])
	}

	// Asset computed field.
	_, a := req(t, app, http.MethodPost, "/api/v1/projects/"+pid+"/assets", editor, `{"type":"host","name":"db-1","identifier":"db-1"}`)
	aid, _ := a["id"].(string)
	if res, out := req(t, app, http.MethodPut, "/api/v1/assets/"+aid+"/exposure", editor, `{"exposure":"internet"}`); res.StatusCode != http.StatusOK {
		t.Fatalf("set exposure: %d %v", res.StatusCode, out)
	}
	// Exposure was set after the field's own creation, so it isn't reflected
	// yet — one interval (or a definition change) away, not instant. Editing
	// the expression (even just rewording it) backfills every asset.
	riskFieldID := envField["id"].(string)
	if res, out := req(t, app, http.MethodPatch, "/api/v1/custom-fields/"+riskFieldID, admin,
		`{"expression":"asset.exposure == \"internet\" ? \"high\" : \"low\""}`); res.StatusCode != http.StatusOK {
		t.Fatalf("edit asset field expression: %d %v", res.StatusCode, out)
	}
	_, gotAsset := req(t, app, http.MethodGet, "/api/v1/assets/"+aid, editor, "")
	if c, _ := gotAsset["custom"].(map[string]any); c["risk"] != "high" {
		t.Errorf("asset computed field = %v, want high", gotAsset["custom"])
	}
}
