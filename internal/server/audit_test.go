package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/audit"
	"github.com/xilasec/xila-api/internal/config"
	"github.com/xilasec/xila-api/internal/pgtest"
)

type auditRow struct {
	ActorKind    string
	ActorUserID  *string
	ActorTokenID *string
	ActorEmail   string
	Action       string
	ResourceType string
	ResourceID   string
	ProjectID    *string
	TeamID       *string
	OrgID        *string
	Status       int
	Outcome      string
	Changes      string
}

func auditRows(t *testing.T, pool *pgxpool.Pool, method, path string) []auditRow {
	t.Helper()
	return auditWhere(t, pool, "method = $1 AND path = $2", method, path)
}

func auditWhere(t *testing.T, pool *pgxpool.Pool, cond string, args ...any) []auditRow {
	t.Helper()
	rows, err := pool.Query(context.Background(), `
		SELECT actor_kind, actor_user_id::text, actor_token_id::text, actor_email, action, resource_type, resource_id,
		       project_id::text, team_id::text, org_id::text, status, outcome, changes::text
		FROM audit_log WHERE `+cond+` ORDER BY id`, args...)
	if err != nil {
		t.Fatalf("audit rows: %v", err)
	}
	defer rows.Close()
	var out []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(&r.ActorKind, &r.ActorUserID, &r.ActorTokenID, &r.ActorEmail, &r.Action, &r.ResourceType,
			&r.ResourceID, &r.ProjectID, &r.TeamID, &r.OrgID, &r.Status, &r.Outcome, &r.Changes); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// TestAuditLogCoversEveryMutatingRoute walks Fiber's real route table, like
// the OpenAPI drift test: every mutating route on the authenticated API, hit
// by an instance admin, must leave exactly one audit entry naming that admin
// and the resource in the path, with the status the client saw. A new route
// is covered the moment it is registered — or this test says which isn't.
func TestAuditLogCoversEveryMutatingRoute(t *testing.T) {
	pool := pgtest.Pool(t)
	app := newTestAppOn(t, pool)
	token := rbacUser(t, app, "root@xila.io")
	login := func() string {
		t.Helper()
		_, body := req(t, app, http.MethodPost, "/api/v1/auth/login", "", `{"email":"root@xila.io","password":"supersecret"}`)
		tok, _ := body["token"].(string)
		if tok == "" {
			t.Fatalf("sign in again: %v", body)
		}
		return tok
	}
	_, me := req(t, app, http.MethodGet, "/api/v1/me", token, "")
	adminID, _ := me["id"].(string)

	type route struct{ method, path string }
	seen := map[route]bool{}
	var routes []route
	for _, r := range app.GetRoutes() {
		switch r.Method {
		case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		default:
			continue
		}
		if !strings.HasPrefix(r.Path, "/api/v1/") || r.Path == "/api/v1/auth" || strings.HasPrefix(r.Path, "/api/v1/auth/") ||
			strings.HasPrefix(r.Path, "/api/v1/scim/") {
			continue // group mounts; the public sign-in endpoints and SCIM (its own tokens) have their own tests
		}
		if audit.Envelope(r.Path) {
			continue // its inner requests are audited (TestMCPServer)
		}
		k := route{r.Method, r.Path}
		if !seen[k] {
			seen[k] = true
			routes = append(routes, k)
		}
	}
	sort.Slice(routes, func(i, j int) bool { return routes[i].path+routes[i].method < routes[j].path+routes[j].method })
	if len(routes) < 50 {
		t.Fatalf("found only %d mutating routes — the route walker is broken", len(routes))
	}

	for _, r := range routes {
		// Every param becomes a fresh id: the path is unique, so its entry is too.
		segs := strings.Split(r.path, "/")
		wantType, wantID := "", ""
		lastStatic := ""
		for i, s := range segs {
			if strings.HasPrefix(s, ":") {
				segs[i] = uuid.NewString()
				wantType, wantID = lastStatic, segs[i]
			} else {
				lastStatic = s
			}
		}
		endsInParam := strings.HasPrefix(strings.Split(r.path, "/")[len(segs)-1], ":")
		path := strings.Join(segs, "/")

		resp, _ := req(t, app, r.method, path, token, `{}`)
		rows := auditRows(t, pool, r.method, path)
		if len(rows) != 1 {
			t.Errorf("%s %s: %d audit entries, want 1", r.method, r.path, len(rows))
		} else {
			e := rows[0]
			if e.ActorKind != "user" || deref(e.ActorUserID) != adminID || e.ActorEmail != "root@xila.io" {
				t.Errorf("%s %s: actor = %s %s %q, want user %s", r.method, r.path, e.ActorKind, deref(e.ActorUserID), e.ActorEmail, adminID)
			}
			if e.Status != resp.StatusCode {
				t.Errorf("%s %s: recorded status %d, client saw %d", r.method, r.path, e.Status, resp.StatusCode)
			}
			if e.Action == "" {
				t.Errorf("%s %s: no action", r.method, r.path)
			}
			// The resource the path names: its last id, unless the route
			// creates something under it (POST …/:id/members).
			createsUnder := !endsInParam && r.method == http.MethodPost && strings.HasSuffix(lastStatic, "s")
			if wantID != "" && !createsUnder && (e.ResourceType != wantType || e.ResourceID != wantID) {
				t.Errorf("%s %s: resource = %s/%s, want %s/%s", r.method, r.path, e.ResourceType, e.ResourceID, wantType, wantID)
			}
		}
		// Some routes end the admin's sessions (sign out everywhere, password
		// change): sign in again for the next one.
		if resp, _ := req(t, app, http.MethodGet, "/api/v1/me", token, ""); resp.StatusCode == http.StatusUnauthorized {
			token = login()
		}
	}
	t.Logf("audited %d mutating routes", len(routes))
}

// The log itself: admin only, sign-ins recorded without their password, API
// tokens named, scope and before/after filled, CSV formula-escaped.
func TestAuditLogEndpointsAndActors(t *testing.T) {
	pool := pgtest.Pool(t)
	app := newTestAppOn(t, pool)
	admin := rbacUser(t, app, "root@xila.io")
	bob := rbacUser(t, app, "bob@xila.io")
	_, bobMe := req(t, app, http.MethodGet, "/api/v1/me", bob, "")
	bobID, _ := bobMe["id"].(string)

	// Non-admins can't read or export it.
	for _, p := range []string{"/api/v1/audit-log", "/api/v1/audit-log/export"} {
		if resp, _ := req(t, app, http.MethodGet, p, bob, ""); resp.StatusCode != http.StatusForbidden {
			t.Errorf("non-admin GET %s = %d, want 403", p, resp.StatusCode)
		}
	}

	// A failed sign-in: anonymous, names the address tried, never the password.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/auth/login", "", `{"email":"=1+1@x.io","password":"Wrong-Pa55word!"}`); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login = %d", resp.StatusCode)
	}
	resp, list := req(t, app, http.MethodGet, "/api/v1/audit-log?action=auth.login&outcome=failure", admin, "")
	entries, _ := list["entries"].([]any)
	if resp.StatusCode != http.StatusOK || len(entries) != 1 {
		t.Fatalf("failed logins = %d %v", resp.StatusCode, list)
	}
	failed := entries[0].(map[string]any)
	raw, _ := json.Marshal(failed)
	if failed["actor_kind"] != "anonymous" || failed["actor_email"] != "=1+1@x.io" || failed["status"] != float64(401) ||
		strings.Contains(string(raw), "Wrong-Pa55word") || !strings.Contains(string(raw), "[REDACTED]") {
		t.Errorf("failed login entry = %s", raw)
	}
	if pg, _ := list["pagination"].(map[string]any); pg["has_more"] != false || pg["count"] != float64(1) {
		t.Errorf("pagination = %v", list["pagination"])
	}
	// Successful sign-ins name the user (bob signed in through rbacUser).
	_, list = req(t, app, http.MethodGet, "/api/v1/audit-log?action=auth.login&outcome=success&actor_id="+bobID, admin, "")
	if entries, _ := list["entries"].([]any); len(entries) != 1 || entries[0].(map[string]any)["actor_email"] != "bob@xila.io" {
		t.Errorf("bob's sign-ins = %v", list["entries"])
	}
	_, list = req(t, app, http.MethodGet, "/api/v1/audit-log?action=auth.register", admin, "")
	if entries, _ := list["entries"].([]any); len(entries) != 2 {
		t.Errorf("registrations = %d, want 2", len(entries))
	}

	// Creating an org → team → project fills the scope from the new ids.
	_, org := req(t, app, http.MethodPost, "/api/v1/orgs", bob, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := org["id"].(string)
	_, team := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", bob, `{"slug":"core","name":"Core"}`)
	teamID, _ := team["id"].(string)
	_, proj := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", bob, `{"slug":"web","name":"Web"}`)
	projID, _ := proj["id"].(string)
	rows := auditRows(t, pool, http.MethodPost, "/api/v1/teams/"+teamID+"/projects")
	if len(rows) != 1 || rows[0].Action != "teams.projects.create" || rows[0].ResourceType != "projects" || rows[0].ResourceID != projID ||
		deref(rows[0].ProjectID) != projID || deref(rows[0].TeamID) != teamID || deref(rows[0].OrgID) != orgID {
		t.Errorf("project create entry = %+v", rows)
	}

	// An API token acting is named as the token, on behalf of its creator, and
	// a refused mutation is recorded as a failure.
	_, tok := req(t, app, http.MethodPost, "/api/v1/tokens", bob, `{"name":"ci","project_id":"`+projID+`"}`)
	secret, _ := tok["secret"].(string)
	tokenID, _ := tok["token"].(map[string]any)["id"].(string)
	if rows := auditRows(t, pool, http.MethodPost, "/api/v1/tokens"); len(rows) != 1 || strings.Contains(rows[0].Changes, secret) {
		t.Errorf("token create entry = %+v", rows)
	}
	req(t, app, http.MethodPatch, "/api/v1/projects/"+projID, secret, `{"description":"from CI"}`)
	rows = auditRows(t, pool, http.MethodPatch, "/api/v1/projects/"+projID)
	if len(rows) != 1 || rows[0].ActorKind != "api_token" || deref(rows[0].ActorTokenID) != tokenID ||
		deref(rows[0].ActorUserID) != bobID || deref(rows[0].ProjectID) != projID {
		t.Errorf("token mutation entry = %+v", rows)
	}
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/users/"+bobID, bob, `{"is_admin":true}`); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("self-promotion = %d", resp.StatusCode)
	}
	// The admin's promotion records before → after.
	req(t, app, http.MethodPatch, "/api/v1/users/"+bobID, admin, `{"is_admin":true}`)
	rows = auditRows(t, pool, http.MethodPatch, "/api/v1/users/"+bobID)
	if len(rows) != 2 || rows[0].Outcome != "failure" || rows[0].Status != 403 || deref(rows[0].ActorUserID) != bobID ||
		rows[1].Outcome != "success" || rows[1].Action != "users.update" || rows[1].ResourceID != bobID {
		t.Fatalf("promotion entries = %+v", rows)
	}
	var changes map[string]map[string]any
	_ = json.Unmarshal([]byte(rows[1].Changes), &changes)
	if changes["before"]["is_admin"] != false || changes["after"]["is_admin"] != true {
		t.Errorf("promotion changes = %s, want is_admin false → true", rows[1].Changes)
	}

	// Filter by project, and the CSV export of the same filter.
	_, list = req(t, app, http.MethodGet, "/api/v1/audit-log?project_id="+projID, admin, "")
	if entries, _ := list["entries"].([]any); len(entries) != 3 { // project create, token create, PATCH
		t.Errorf("project entries = %d, want 3: %v", len(entries), list["entries"])
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/audit-log?from=yesterday", admin, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad from = %d, want 400", resp.StatusCode)
	}
	hr := httptest.NewRequest(http.MethodGet, "/api/v1/audit-log/export?action=auth.login&outcome=failure", nil)
	hr.Header.Set("Authorization", "Bearer "+admin)
	eresp, err := app.Test(hr, -1)
	if err != nil {
		t.Fatal(err)
	}
	csv, _ := io.ReadAll(eresp.Body)
	lines := strings.Split(strings.TrimSpace(string(csv)), "\n")
	if eresp.StatusCode != http.StatusOK || len(lines) != 2 || !strings.HasPrefix(lines[0], "Time,Actor kind,Actor,") ||
		!strings.Contains(lines[1], ",anonymous,'=1+1@x.io,") || strings.Contains(string(csv), "Wrong-Pa55word") {
		t.Errorf("export = %d\n%s", eresp.StatusCode, csv)
	}
}

// The public sign-in endpoints: two-factor, password reset and SSO logins are
// recorded with the user they concern, success or failure, and no credential.
func TestAuditLogSignInEvents(t *testing.T) {
	pool := pgtest.Pool(t)
	idp := newOIDCIdP(t)
	apps := ssoApps{t: t, pool: pool, opts: []func(*config.Config){withSSOPublicURL}}
	app := apps.app()
	admin := rbacUser(t, app, "owner@xila.io")
	bob := rbacUser(t, app, "bob@xila.io")
	bobID := userIDOf(t, app, admin, "bob@xila.io")
	byAction := func(action string) []auditRow { return auditWhere(t, pool, "action = $1", action) }

	// Two-factor: the password step, a wrong code, a right one — all name bob.
	_, setup := req(t, app, http.MethodPost, "/api/v1/me/mfa/setup", bob, "")
	secret, _ := setup["secret"].(string)
	req(t, app, http.MethodPost, "/api/v1/me/mfa/enable", bob, `{"code":"`+totp(t, secret, 0)+`"}`)
	_, first := req(t, app, http.MethodPost, "/api/v1/auth/login", "", `{"email":"bob@xila.io","password":"supersecret"}`)
	challenge, _ := first["mfa_token"].(string)
	req(t, app, http.MethodPost, "/api/v1/auth/mfa", "", `{"mfa_token":"`+challenge+`","code":"999999"}`)
	req(t, app, http.MethodPost, "/api/v1/auth/mfa", "", `{"mfa_token":"`+challenge+`","code":"`+totp(t, secret, 1)+`"}`)
	logins := byAction("auth.login")
	last := logins[len(logins)-1]
	if deref(last.ActorUserID) != bobID || !strings.Contains(last.Changes, `"mfa_required": true`) || strings.Contains(last.Changes, challenge) {
		t.Errorf("password step with MFA = %+v", last)
	}
	mfa := byAction("auth.mfa")
	if len(mfa) != 2 || mfa[0].Outcome != "failure" || mfa[0].ActorKind != "anonymous" || deref(mfa[0].ActorUserID) != bobID ||
		mfa[1].Outcome != "success" || mfa[1].ActorKind != "user" || deref(mfa[1].ActorUserID) != bobID {
		t.Fatalf("mfa entries = %+v", mfa)
	}
	for _, e := range mfa {
		if strings.Contains(e.Changes, "999999") || strings.Contains(e.Changes, challenge) {
			t.Errorf("mfa entry kept a credential: %s", e.Changes)
		}
	}

	// Password reset: request names the address; confirm names the user, never
	// the reset token or the new password.
	req(t, app, http.MethodPost, "/api/v1/auth/password-reset/request", "", `{"email":"bob@xila.io"}`)
	_, link := req(t, app, http.MethodPost, "/api/v1/users/"+bobID+"/password-reset-link", admin, "")
	_, resetToken, _ := strings.Cut(link["url"].(string), "#token=")
	req(t, app, http.MethodPost, "/api/v1/auth/password-reset/confirm", "", `{"token":"`+resetToken+`","password":"brandnewpass"}`)
	if r := byAction("auth.password_reset.request"); len(r) != 1 || r[0].ActorEmail != "bob@xila.io" {
		t.Errorf("reset request entries = %+v", r)
	}
	if r := byAction("auth.password_reset.confirm"); len(r) != 1 || r[0].Outcome != "success" || deref(r[0].ActorUserID) != bobID ||
		strings.Contains(r[0].Changes, resetToken) || strings.Contains(r[0].Changes, "brandnewpass") {
		t.Errorf("reset confirm entries = %+v", r)
	}

	// SSO: a provider's client secret never lands in the log; a login through
	// it names the user, a refused one records why.
	resp, p := req(t, app, http.MethodPost, "/api/v1/sso/providers", admin, providerBody("corp", "Corp", idp, ""))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create provider = %d %v", resp.StatusCode, p)
	}
	if r := auditRows(t, pool, http.MethodPost, "/api/v1/sso/providers"); len(r) != 1 || strings.Contains(r[0].Changes, "corp-secret") {
		t.Errorf("provider create entry = %+v", r)
	}
	if loc := apps.oidcLogin(idp, "/api/v1/auth/oidc/corp", "corp-sub", "carl@xila.io"); !strings.HasPrefix(loc, "/#sso_token=") {
		t.Fatalf("sso login → %q", loc)
	}
	carlID := userIDOf(t, app, admin, "carl@xila.io")
	flow := apps.app()
	loc, cookies := startLogin(t, flow, "/api/v1/auth/oidc/corp/login")
	callback(t, flow, "/api/v1/auth/oidc/corp/callback", loc.Query().Get("state")+"x", cookies)
	sso := byAction("auth.sso_login")
	if len(sso) != 2 || sso[0].Outcome != "success" || deref(sso[0].ActorUserID) != carlID || sso[0].ResourceID != "corp" ||
		sso[1].Outcome != "failure" || sso[1].ActorUserID != nil || !strings.Contains(sso[1].Changes, `"error"`) {
		t.Errorf("sso entries = %+v", sso)
	}
}
