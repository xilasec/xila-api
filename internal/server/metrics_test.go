package server

import (
	"net/http"
	"testing"
)

// TestMetricsTrendScoping checks the trend API end-to-end: snapshotting is
// admin-only, the portfolio and org trends only sum what the caller can see,
// and a project's latest point agrees with its live summary.
func TestMetricsTrendScoping(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "admin@xila.io") // first user = instance admin
	bob := rbacUser(t, app, "bob@xila.io")
	carol := rbacUser(t, app, "carol@xila.io")

	// Each of admin and bob owns an org → team → project with the same two
	// open findings (critical + high).
	setup := func(token, slug string) (orgID, projectID string) {
		t.Helper()
		_, o := req(t, app, http.MethodPost, "/api/v1/orgs", token, `{"slug":"`+slug+`","name":"`+slug+`"}`)
		orgID, _ = o["id"].(string)
		_, tm := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", token, `{"slug":"`+slug+`-t","name":"T"}`)
		teamID, _ := tm["id"].(string)
		_, p := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", token, `{"slug":"`+slug+`-p","name":"P"}`)
		projectID, _ = p["id"].(string)
		if orgID == "" || teamID == "" || projectID == "" {
			t.Fatalf("setup %s failed", slug)
		}
		if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/scans?scanner=trivy", token, smokeTrivyReport); resp.StatusCode != http.StatusCreated {
			t.Fatalf("upload %s = %d", slug, resp.StatusCode)
		}
		return orgID, projectID
	}
	adminOrg, _ := setup(admin, "alpha")
	bobOrg, bobProject := setup(bob, "beta")

	if resp, _ := req(t, app, http.MethodPost, "/api/v1/metrics/snapshot", bob, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("bob POST /metrics/snapshot = %d, want 403", resp.StatusCode)
	}
	resp, run := req(t, app, http.MethodPost, "/api/v1/metrics/snapshot", admin, "")
	if resp.StatusCode != http.StatusOK || run["backfilled"] != float64(88) {
		t.Fatalf("admin snapshot = %d %v, want 200 with 88 backfilled days", resp.StatusCode, run)
	}

	// latest returns a trend's point count and its newest point.
	latest := func(token, path string) (int, map[string]any) {
		t.Helper()
		resp, body := req(t, app, http.MethodGet, path, token, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d", path, resp.StatusCode)
		}
		points, _ := body["points"].([]any)
		if len(points) == 0 {
			return 0, nil
		}
		last, _ := points[len(points)-1].(map[string]any)
		return len(points), last
	}

	if n, last := latest(admin, "/api/v1/metrics/trends"); n != 90 || last["open_total"] != float64(4) {
		t.Errorf("admin portfolio trend: %d points, latest open %v; want 90 / 4", n, last["open_total"])
	}
	// Bob sees only his project in the portfolio trend.
	if n, last := latest(bob, "/api/v1/metrics/trends"); n != 90 || last["open_total"] != float64(2) {
		t.Errorf("bob portfolio trend: %d points, latest open %v; want 90 / 2", n, last["open_total"])
	}
	// Carol can see nothing, so her trend is empty — not the instance's.
	if n, _ := latest(carol, "/api/v1/metrics/trends"); n != 0 {
		t.Errorf("carol portfolio trend has %d points, want 0", n)
	}

	// Org trends: members only, summed over what they can see.
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/orgs/"+adminOrg+"/metrics/trends", bob, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("bob GET other org trend = %d, want 403", resp.StatusCode)
	}
	if _, last := latest(bob, "/api/v1/orgs/"+bobOrg+"/metrics/trends"); last["open_total"] != float64(2) {
		t.Errorf("bob org trend latest open = %v, want 2", last["open_total"])
	}
	if _, last := latest(admin, "/api/v1/orgs/"+adminOrg+"/metrics/trends"); last["open_total"] != float64(2) {
		t.Errorf("admin org trend latest open = %v, want 2", last["open_total"])
	}

	// Project trends ride the project's RBAC.
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+bobProject+"/metrics/trends", carol, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("carol GET bob's project trend = %d, want 403", resp.StatusCode)
	}
	n, last := latest(bob, "/api/v1/projects/"+bobProject+"/metrics/trends?days=1")
	_, summary := req(t, app, http.MethodGet, "/api/v1/projects/"+bobProject+"/summary", bob, "")
	if n != 1 || last["risk_score"] != summary["risk_score"] || last["open_total"] != summary["total_open"] {
		t.Errorf("project trend today (%d points) = risk %v open %v; summary risk %v open %v",
			n, last["risk_score"], last["open_total"], summary["risk_score"], summary["total_open"])
	}

	if resp, _ := req(t, app, http.MethodGet, "/api/v1/metrics/trends?days=0", bob, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("days=0 = %d, want 400", resp.StatusCode)
	}
	if _, body := req(t, app, http.MethodGet, "/api/v1/metrics/trends?days=5000", bob, ""); body["days"] != float64(365) {
		t.Errorf("days=5000 window = %v, want capped at 365", body["days"])
	}
}
