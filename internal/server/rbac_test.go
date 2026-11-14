package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/pgtest"
)

// rbacUser registers + logs in, returning the JWT.
func rbacUser(t *testing.T, app *fiber.App, email string) string {
	t.Helper()
	creds := `{"email":"` + email + `","password":"supersecret"}`
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/auth/register", "", creds); resp.StatusCode != http.StatusCreated {
		t.Fatalf("register %s = %d", email, resp.StatusCode)
	}
	resp, body := req(t, app, http.MethodPost, "/api/v1/auth/login", "", creds)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login %s = %d", email, resp.StatusCode)
	}
	token, _ := body["token"].(string)
	if token == "" {
		t.Fatalf("no token for %s", email)
	}
	return token
}

// TestRBACEnforcement exercises the authz middleware end-to-end: bootstrap admin,
// team-scoped access, read-only viewers, list scoping, and admin-only actions.
func TestRBACEnforcement(t *testing.T) {
	app := newTestApp(t)

	// First registered user bootstraps as admin; the next two are regular users.
	admin := rbacUser(t, app, "admin@xila.io")
	bob := rbacUser(t, app, "bob@xila.io")
	carol := rbacUser(t, app, "carol@xila.io")

	if _, me := req(t, app, http.MethodGet, "/api/v1/me", admin, ""); me["is_admin"] != true {
		t.Fatalf("first user should be admin, got %v", me["is_admin"])
	}
	if _, me := req(t, app, http.MethodGet, "/api/v1/me", bob, ""); me["is_admin"] != false {
		t.Fatalf("second user should not be admin, got %v", me["is_admin"])
	}

	// Bob creates an org (becomes org admin), then a team (owner) + a project.
	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", bob, `{"slug":"pay-org","name":"PayOrg"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", bob, `{"slug":"payments","name":"Payments"}`)
	teamID, _ := teamBody["id"].(string)
	_, projBody := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", bob, `{"slug":"api","name":"API"}`)
	projID, _ := projBody["id"].(string)
	if orgID == "" || teamID == "" || projID == "" {
		t.Fatal("bob could not create org/team/project")
	}

	// Carol is not a member: no read access to the project, and list-scoping hides it.
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+projID, carol, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("carol GET project = %d, want 403", resp.StatusCode)
	}
	if _, body := req(t, app, http.MethodGet, "/api/v1/projects", carol, ""); len(body["projects"].([]any)) != 0 {
		t.Errorf("carol should see no projects, got %v", body["projects"])
	}
	// Bob (owner) and the admin can see it.
	if _, body := req(t, app, http.MethodGet, "/api/v1/projects", bob, ""); len(body["projects"].([]any)) != 1 {
		t.Errorf("bob should see his 1 project, got %v", body["projects"])
	}
	if _, body := req(t, app, http.MethodGet, "/api/v1/projects", admin, ""); len(body["projects"].([]any)) != 1 {
		t.Errorf("admin should see all (1) projects, got %v", body["projects"])
	}

	// Admin-only surface.
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/users", carol, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("carol GET /users = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/users", admin, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("admin GET /users = %d, want 200", resp.StatusCode)
	}
	// A package-metadata sweep hits every registry for the whole portfolio:
	// admin-only. The cached metadata itself is public package data.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/pkgmeta/refresh", carol, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("carol POST /pkgmeta/refresh = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/pkgmeta?purl=pkg:npm/express", carol, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("carol GET /pkgmeta (nothing cached) = %d, want 404", resp.StatusCode)
	}

	// Bob invites Carol as a viewer (owner-only action).
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/members", bob,
		`{"email":"carol@xila.io","role":"viewer"}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("bob add member = %d, want 201", resp.StatusCode)
	}

	// Carol can now READ the project...
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+projID, carol, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("viewer carol GET project = %d, want 200", resp.StatusCode)
	}
	// ...but a viewer must not mutate (upload a scan).
	scanPath := "/api/v1/projects/" + projID + "/scans?scanner=trivy"
	if resp, _ := req(t, app, http.MethodPost, scanPath, carol, smokeTrivyReport); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer carol upload scan = %d, want 403", resp.StatusCode)
	}
	// Bob (owner ⇒ editor) can upload.
	if resp, _ := req(t, app, http.MethodPost, scanPath, bob, smokeTrivyReport); resp.StatusCode != http.StatusCreated {
		t.Errorf("owner bob upload scan = %d, want 201", resp.StatusCode)
	}
	// Carol (viewer, not owner) cannot manage members.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/members", carol,
		`{"email":"admin@xila.io","role":"editor"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer carol add member = %d, want 403", resp.StatusCode)
	}

	// Notification-channel management is admin-only in this pass.
	chBody := `{"name":"x","type":"webhook","url":"http://example.com","events":["*"]}`
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/notifications/channels", bob, chBody); resp.StatusCode != http.StatusForbidden {
		t.Errorf("bob create channel = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/notifications/channels", admin, chBody); resp.StatusCode != http.StatusCreated {
		t.Errorf("admin create channel = %d, want 201", resp.StatusCode)
	}
}

// TestOrgScoping verifies org creation makes you admin, org list scoping, and
// that non-members can't create teams in someone else's org.
func TestOrgScoping(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "iadmin@xila.io") // first user = instance admin
	bob := rbacUser(t, app, "bob2@xila.io")
	carol := rbacUser(t, app, "carol2@xila.io")

	_, boBody := req(t, app, http.MethodPost, "/api/v1/orgs", bob, `{"slug":"bo","name":"BO"}`)
	orgB, _ := boBody["id"].(string)
	_, coBody := req(t, app, http.MethodPost, "/api/v1/orgs", carol, `{"slug":"co","name":"CO"}`)
	orgC, _ := coBody["id"].(string)
	if orgB == "" || orgC == "" {
		t.Fatal("org creation failed")
	}

	// Each user sees only their own org; the instance admin sees both.
	if _, b := req(t, app, http.MethodGet, "/api/v1/orgs", bob, ""); len(b["organizations"].([]any)) != 1 {
		t.Errorf("bob orgs = %v, want 1", b["organizations"])
	}
	if _, b := req(t, app, http.MethodGet, "/api/v1/orgs", admin, ""); len(b["organizations"].([]any)) != 2 {
		t.Errorf("admin orgs = %v, want 2", b["organizations"])
	}

	// Carol (not a member of BO) cannot create a team there; Bob (admin) can.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgB+"/teams", carol, `{"slug":"x","name":"X"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("carol create team in BO = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgB+"/teams", bob, `{"slug":"x","name":"X"}`); resp.StatusCode != http.StatusCreated {
		t.Errorf("bob create team in BO = %d, want 201", resp.StatusCode)
	}
}

// TestProjectScopedAccess is the end-to-end version of the feature: grant a user
// a role on ONE project, without putting them in the team, and check that the
// grant does exactly that and nothing more.
func TestProjectScopedAccess(t *testing.T) {
	app := newTestApp(t)

	owner := rbacUser(t, app, "founder@xila.io") // first user: admin + instance owner
	lead := rbacUser(t, app, "lead@xila.io")
	dana := rbacUser(t, app, "dana@xila.io")

	// Lead builds an org/team with two projects. Dana is in none of it.
	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", lead, `{"slug":"acme","name":"Acme"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", lead, `{"slug":"core","name":"Core"}`)
	teamID, _ := teamBody["id"].(string)
	_, aBody := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", lead, `{"slug":"alpha","name":"Alpha"}`)
	projectA, _ := aBody["id"].(string)
	_, bBody := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", lead, `{"slug":"beta","name":"Beta"}`)
	projectB, _ := bBody["id"].(string)
	if projectA == "" || projectB == "" {
		t.Fatal("project setup failed")
	}

	// Before any grant, Dana can't see project A.
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+projectA, dana, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("ungranted user reading a project = %d, want 403", resp.StatusCode)
	}

	// The team owner grants her viewer on project A only.
	resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+projectA+"/members", lead,
		`{"email":"dana@xila.io","role":"viewer"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("granting a project role = %d, want 201", resp.StatusCode)
	}

	// She can now read project A…
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+projectA, dana, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("granted viewer reading their project = %d, want 200", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+projectA+"/findings", dana, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("granted viewer reading findings = %d, want 200", resp.StatusCode)
	}

	// …and nothing else. The sibling project in the same team stays closed.
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+projectB, dana, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("a grant on one project leaked to a sibling project: %d, want 403", resp.StatusCode)
	}
	// She is not in the team, so the team itself is still closed to her.
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/teams/"+teamID, dana, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("project grant leaked team access: %d, want 403", resp.StatusCode)
	}

	// A viewer is strictly read-only: she cannot upload a scan or triage.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+projectA+"/scans?scanner=trivy", dana,
		`{"Results":[]}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer uploading a scan = %d, want 403", resp.StatusCode)
	}
	// …nor grant access to anyone else — that takes owner.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+projectA+"/members", dana,
		`{"email":"dana@xila.io","role":"owner"}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("viewer granting themselves owner = %d, want 403 — this is privilege escalation", resp.StatusCode)
	}

	// And the project shows up in her portfolio list: a project you can open but
	// cannot find in any list is a bug.
	_, list := req(t, app, http.MethodGet, "/api/v1/projects", dana, "")
	projects, _ := list["projects"].([]any)
	if len(projects) != 1 {
		t.Fatalf("Dana sees %d projects, want exactly 1 (the one granted)", len(projects))
	}
	if got, _ := projects[0].(map[string]any)["id"].(string); got != projectA {
		t.Errorf("Dana sees project %s, want %s", got, projectA)
	}

	// Raising her to editor lets her upload; the grant is a real role, not a flag.
	req(t, app, http.MethodPost, "/api/v1/projects/"+projectA+"/members", lead,
		`{"email":"dana@xila.io","role":"editor"}`)
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+projectA+"/scans?scanner=trivy", dana,
		`{"Results":[]}`); resp.StatusCode != http.StatusCreated {
		t.Errorf("editor uploading a scan = %d, want 201", resp.StatusCode)
	}
	// An editor works the backlog but can't relax the deadlines it's held to:
	// reading the SLA is fine, changing it takes owner (lead), and the
	// instance-wide default is admin-only.
	slaPath := "/api/v1/projects/" + projectA + "/sla/policy"
	if resp, _ := req(t, app, http.MethodGet, slaPath, dana, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("editor reading the SLA = %d, want 200", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPut, slaPath, dana, `{"critical_days":365}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor relaxing their own SLA = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPut, slaPath, lead, `{"critical_days":3}`); resp.StatusCode != http.StatusOK {
		t.Errorf("owner setting the SLA = %d, want 200", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPut, "/api/v1/orgs/"+orgID+"/sla/policy", lead, `{"critical_days":5}`); resp.StatusCode != http.StatusOK {
		t.Errorf("org admin setting the org SLA = %d, want 200", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPut, "/api/v1/sla/policy", lead, `{"critical_days":30}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin setting the global SLA = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPut, "/api/v1/sla/settings", lead,
		`{"scale_by_criticality":true,"factors":{"critical":0.5,"high":0.75,"medium":1,"low":1.5}}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin enabling SLA criticality scaling = %d, want 403", resp.StatusCode)
	}
	// Which branch is the default decides what metrics and gates report, so an
	// editor can read versions but not move the default.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/projects/"+projectA+"/scans?scanner=trivy&branch=feature-z", dana,
		`{"Results":[]}`); resp.StatusCode != http.StatusCreated {
		t.Fatalf("editor scanning a branch = %d, want 201", resp.StatusCode)
	}
	_, vlist := req(t, app, http.MethodGet, "/api/v1/projects/"+projectA+"/versions", dana, "")
	var featureZ string
	for _, raw := range vlist["versions"].([]any) {
		if v, _ := raw.(map[string]any); v["name"] == "feature-z" {
			featureZ, _ = v["id"].(string)
		}
	}
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/projects/"+projectA+"/versions/"+featureZ, dana,
		`{"is_default":true}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor changing the default branch = %d, want 403", resp.StatusCode)
	}
	// The issue tracker holds a credential: an editor can read the config but
	// only the owner can set or test it, and the portfolio-wide sync is admin-only.
	trackerPath := "/api/v1/projects/" + projectA + "/issue-tracker"
	trackerBody := `{"kind":"github","target":"acme/web","token":"ghp_x"}`
	if resp, _ := req(t, app, http.MethodPut, trackerPath, dana, trackerBody); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor configuring the issue tracker = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, trackerPath+"/test", dana, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor testing the issue tracker = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPut, trackerPath, lead, trackerBody); resp.StatusCode != http.StatusOK {
		t.Errorf("owner configuring the issue tracker = %d, want 200", resp.StatusCode)
	}
	if resp, tr := req(t, app, http.MethodGet, trackerPath, dana, ""); resp.StatusCode != http.StatusOK || tr["has_token"] != true {
		t.Errorf("editor reading the issue tracker = %d %v, want 200", resp.StatusCode, tr)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/issue-trackers/sync", lead, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin running the issue sync = %d, want 403", resp.StatusCode)
	}
	// A connector holds a credential too: only the owner configures or tests
	// it; pulling it is just a scan, so an editor may run it.
	dt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Total-Count", "0")
		fmt.Fprint(w, `[]`)
	}))
	defer dt.Close()
	connPath := "/api/v1/projects/" + projectA + "/connectors"
	connBody := `{"kind":"dependency-track","base_url":"` + dt.URL + `","remote_project":"ca4f2da9-0fad-4a13-92d7-f627f3168a56","token":"odt_x"}`
	if resp, _ := req(t, app, http.MethodPost, connPath, dana, connBody); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor creating a connector = %d, want 403", resp.StatusCode)
	}
	resp, conn := req(t, app, http.MethodPost, connPath, lead, connBody)
	connID, _ := conn["id"].(string)
	if resp.StatusCode != http.StatusCreated || connID == "" {
		t.Fatalf("owner creating a connector = %d %v, want 201", resp.StatusCode, conn)
	}
	if resp, _ := req(t, app, http.MethodPut, connPath+"/"+connID, dana, connBody); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor editing a connector = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, connPath+"/"+connID+"/test", dana, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor testing a connector = %d, want 403", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodDelete, connPath+"/"+connID, dana, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("editor deleting a connector = %d, want 403", resp.StatusCode)
	}
	if resp, body := req(t, app, http.MethodPost, connPath+"/"+connID+"/pull", dana, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("editor pulling a connector = %d %v, want 200", resp.StatusCode, body)
	}
	if resp, list := req(t, app, http.MethodGet, connPath, dana, ""); resp.StatusCode != http.StatusOK || len(list["connectors"].([]any)) != 1 {
		t.Errorf("editor listing connectors = %d %v, want 200 with 1", resp.StatusCode, list)
	}

	// A diff's base must come from the same project: access to project A's
	// snapshot must not open a window onto project B's inventory.
	upload := func(projectID string) string {
		t.Helper()
		_, body := req(t, app, http.MethodPost, "/api/v1/projects/"+projectID+"/sboms", lead, smokeCycloneDX)
		id, _ := body["id"].(string)
		if id == "" {
			t.Fatalf("sbom upload to %s failed: %v", projectID, body)
		}
		return id
	}
	sbomA, sbomB := upload(projectA), upload(projectB)
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/sboms/"+sbomA+"/diff?base="+sbomB, dana, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("diff against another project's sbom = %d, want 404", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/sboms/"+sbomB+"/graph", dana, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("graph of a project she can't see = %d, want 403", resp.StatusCode)
	}
	for _, path := range []string{"/api/v1/sboms/" + sbomB + "/services", "/api/v1/projects/" + projectB + "/services"} {
		if resp, _ := req(t, app, http.MethodGet, path, dana, ""); resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s for a project she can't see = %d, want 403", path, resp.StatusCode)
		}
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/sboms/"+sbomA+"/services", dana, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("services of a granted project = %d, want 200", resp.StatusCode)
	}

	// Revoking the grant closes the door again.
	if resp, _ := req(t, app, http.MethodDelete,
		"/api/v1/projects/"+projectA+"/members/"+userIDOf(t, app, owner, "dana@xila.io"), lead, ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("revoking a grant = %d, want 204", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+projectA, dana, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("access survived revocation: %d, want 403", resp.StatusCode)
	}
}

// TestInstanceOwnerIsProtected: an admin may manage other admins, but nobody may
// touch the owner.
func TestInstanceOwnerIsProtected(t *testing.T) {
	app := newTestApp(t)

	owner := rbacUser(t, app, "founder@xila.io") // first user
	other := rbacUser(t, app, "other@xila.io")

	_, me := req(t, app, http.MethodGet, "/api/v1/me", owner, "")
	if me["is_admin"] != true || me["is_owner"] != true {
		t.Fatalf("the first user must be admin+owner, got %v", me)
	}

	ownerID := userIDOf(t, app, owner, "founder@xila.io")
	otherID := userIDOf(t, app, owner, "other@xila.io")

	// Promote the second user to admin. Admins can manage admins…
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/users/"+otherID, owner, `{"is_admin":true}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("promoting a user = %d, want 200", resp.StatusCode)
	}

	// …but that admin cannot demote the owner. This is the entire point: before,
	// any admin could lock out the person who set the instance up.
	resp, body := req(t, app, http.MethodPatch, "/api/v1/users/"+ownerID, other, `{"is_admin":false}`)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("an admin demoting the owner = %d, want 403 (%v)", resp.StatusCode, body)
	}
	// Not even the owner can demote themselves — the invariant is "there is always
	// an owner", not "the owner is careful".
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/users/"+ownerID, owner, `{"is_admin":false}`); resp.StatusCode != http.StatusForbidden {
		t.Errorf("the owner demoting themselves = %d, want 403", resp.StatusCode)
	}

	// A mere admin cannot seize ownership either.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/users/"+otherID+"/transfer-ownership", other, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("an admin transferring ownership to themselves = %d, want 403", resp.StatusCode)
	}

	// Only the owner can hand it over.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/users/"+otherID+"/transfer-ownership", owner, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("owner transferring ownership = %d, want 200", resp.StatusCode)
	}
	if _, me := req(t, app, http.MethodGet, "/api/v1/me", other, ""); me["is_owner"] != true {
		t.Error("the successor is not the owner")
	}
	if _, me := req(t, app, http.MethodGet, "/api/v1/me", owner, ""); me["is_owner"] != false {
		t.Error("the previous owner is still the owner — there are two")
	}
	// The former owner keeps admin, and is now demotable like anyone else.
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/users/"+ownerID, other, `{"is_admin":false}`); resp.StatusCode != http.StatusOK {
		t.Errorf("demoting the former owner = %d, want 200", resp.StatusCode)
	}
}

// userIDOf looks a user's id up by email via the admin user list.
func userIDOf(t *testing.T, app *fiber.App, adminToken, email string) string {
	t.Helper()
	_, body := req(t, app, http.MethodGet, "/api/v1/users", adminToken, "")
	users, _ := body["users"].([]any)
	for _, u := range users {
		m, _ := u.(map[string]any)
		if m["email"] == email {
			id, _ := m["id"].(string)
			return id
		}
	}
	t.Fatalf("no user %q in the user list", email)
	return ""
}

// TestAdminRevocationTakesEffectImmediately guards a hole that a JWT-based
// `is_admin` claim opens: the token still says "admin" after you demote someone,
// so if authorization trusts the claim, the revocation you just performed does
// nothing for up to a full token lifetime. Admin status is read from the database
// on every request for exactly this reason.
func TestAdminRevocationTakesEffectImmediately(t *testing.T) {
	app := newTestApp(t)

	owner := rbacUser(t, app, "founder@xila.io")
	rogue := rbacUser(t, app, "rogue@xila.io") // token minted while NOT an admin
	rogueID := userIDOf(t, app, owner, "rogue@xila.io")

	// Promote. The old token's claim still says is_admin=false…
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/users/"+rogueID, owner, `{"is_admin":true}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("promote = %d", resp.StatusCode)
	}
	// …yet the promotion is in effect at once, with no re-login.
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/users", rogue, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("a freshly promoted admin = %d on an admin route, want 200 without re-login", resp.StatusCode)
	}

	// Demote. Same token, which still carries whatever claim it was minted with.
	if resp, _ := req(t, app, http.MethodPatch, "/api/v1/users/"+rogueID, owner, `{"is_admin":false}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("demote = %d", resp.StatusCode)
	}
	// The revocation must bite immediately — not when the token happens to expire.
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/users", rogue, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("a demoted admin still reached an admin route: %d, want 403", resp.StatusCode)
	}
}

// TestPolicyRBAC: component policies are instance-wide, so only an instance
// admin may change or force-evaluate them; everyone may read them and dry-run
// a draft, scoped to the projects they can see.
func TestPolicyRBAC(t *testing.T) {
	app := newTestApp(t)
	admin := rbacUser(t, app, "padmin@xila.io")
	bob := rbacUser(t, app, "pbob@xila.io")
	carol := rbacUser(t, app, "pcarol@xila.io")

	_, orgBody := req(t, app, http.MethodPost, "/api/v1/orgs", bob, `{"slug":"pol-org","name":"PolOrg"}`)
	orgID, _ := orgBody["id"].(string)
	_, teamBody := req(t, app, http.MethodPost, "/api/v1/orgs/"+orgID+"/teams", bob, `{"slug":"pol-team","name":"PolTeam"}`)
	teamID, _ := teamBody["id"].(string)
	_, projBody := req(t, app, http.MethodPost, "/api/v1/teams/"+teamID+"/projects", bob, `{"slug":"pol-api","name":"API"}`)
	projID, _ := projBody["id"].(string)
	if projID == "" {
		t.Fatal("bob could not create a project")
	}

	body := `{"name":"no event-stream","scope":"projects","project_ids":["` + projID + `"],
		"conditions":[{"subject":"purl","operator":"matches","value":"pkg:npm/event-stream@*"}]}`
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/policies", bob, body); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin create policy = %d, want 403", resp.StatusCode)
	}
	for _, m := range []string{http.MethodPut, http.MethodDelete} {
		if resp, _ := req(t, app, m, "/api/v1/policies/"+pgtest.SeededPolicyID, bob, body); resp.StatusCode != http.StatusForbidden {
			t.Errorf("non-admin %s policy = %d, want 403", m, resp.StatusCode)
		}
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/policies/evaluate", bob, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("non-admin evaluate = %d, want 403", resp.StatusCode)
	}
	bad := `{"name":"x","conditions":[{"subject":"stars","operator":"gte","value":5}]}`
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/policies", admin, bad); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unknown subject = %d, want 400", resp.StatusCode)
	}
	resp, created := req(t, app, http.MethodPost, "/api/v1/policies", admin, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("admin create policy = %d (%v), want 201", resp.StatusCode, created)
	}
	scopedID, _ := created["id"].(string)
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/policies", admin, body); resp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate name = %d, want 409", resp.StatusCode)
	}

	names := func(token, path string) []string {
		t.Helper()
		resp, b := req(t, app, http.MethodGet, path, token, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s = %d", path, resp.StatusCode)
		}
		var out []string
		for _, p := range b["policies"].([]any) {
			out = append(out, p.(map[string]any)["name"].(string))
		}
		return out
	}
	if got := names(bob, "/api/v1/policies"); len(got) != 2 {
		t.Errorf("bob sees policies %v, want the seeded + his project's", got)
	}
	if got := names(carol, "/api/v1/policies"); len(got) != 1 || got[0] != "Strong copyleft licenses" {
		t.Errorf("carol sees policies %v, want only the global one", got)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/policies/"+scopedID, carol, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("carol GET another project's policy = %d, want 404", resp.StatusCode)
	}
	if got := names(bob, "/api/v1/projects/"+projID+"/policies"); len(got) != 2 {
		t.Errorf("policies in force on bob's project = %v, want 2", got)
	}
	if resp, _ := req(t, app, http.MethodGet, "/api/v1/projects/"+projID+"/policies", carol, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("carol GET project policies = %d, want 403", resp.StatusCode)
	}

	// Preview: anyone, but only over projects they can see.
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/policies/preview?project_id="+projID, bob, body); resp.StatusCode != http.StatusOK {
		t.Errorf("bob preview on his project = %d, want 200", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/policies/preview?project_id="+projID, carol, body); resp.StatusCode != http.StatusNotFound {
		t.Errorf("carol preview on bob's project = %d, want 404", resp.StatusCode)
	}
	if resp, _ := req(t, app, http.MethodPost, "/api/v1/policies/evaluate?project_id="+projID, admin, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("admin evaluate = %d, want 200", resp.StatusCode)
	}
}
