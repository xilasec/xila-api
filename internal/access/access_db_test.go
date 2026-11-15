package access_test

import (
	"context"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/xilasec/xila-api/internal/access"
	"github.com/xilasec/xila-api/internal/membership"
	"github.com/xilasec/xila-api/internal/pgtest"
)

type world struct {
	t        *testing.T
	ctx      context.Context
	exec     func(q string, args ...any)
	id       func(q string, args ...any) string
	users    []string
	orgs     []string
	teams    []string // team i belongs to orgs[i%2]
	projects []string // project i belongs to teams[i%len(teams)]
}

func seed(t *testing.T) (*world, *access.Repository, *membership.Repository) {
	pool := pgtest.Pool(t)
	ctx := context.Background()
	w := &world{t: t, ctx: ctx}
	w.exec = func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	w.id = func(q string, args ...any) string {
		t.Helper()
		var id string
		if err := pool.QueryRow(ctx, q, args...).Scan(&id); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return id
	}
	for i := range 6 {
		w.users = append(w.users, w.id(`INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id`,
			fmt.Sprintf("u%d@xila.io", i)))
	}
	for i := range 2 {
		w.orgs = append(w.orgs, w.id(`INSERT INTO organizations (slug, name) VALUES ($1, $1) RETURNING id`, fmt.Sprintf("org%d", i)))
	}
	for i := range 3 {
		w.teams = append(w.teams, w.id(`INSERT INTO teams (org_id, slug, name) VALUES ($1, $2, $2) RETURNING id`,
			w.orgs[i%2], fmt.Sprintf("team%d", i)))
	}
	for i := range 5 {
		w.projects = append(w.projects, w.id(`INSERT INTO projects (team_id, slug, name) VALUES ($1, $2, $2) RETURNING id`,
			w.teams[i%3], fmt.Sprintf("proj%d", i)))
	}
	return w, access.NewRepository(pool), membership.NewRepository(pool)
}

// The audit's effective role is RoleOnProject's, for every (user, project)
// of a randomized grant matrix — including "no access".
func TestAuditAgreesWithAuthorization(t *testing.T) {
	w, audit, members := seed(t)
	// A hierarchy across teams of one org: proj0 > proj2 > proj3 (org0) and
	// proj1 > proj4 (org1), so inherited grants are in the matrix too.
	w.exec(`UPDATE projects SET parent_id = $1 WHERE id = $2`, w.projects[0], w.projects[2])
	w.exec(`UPDATE projects SET parent_id = $1 WHERE id = $2`, w.projects[2], w.projects[3])
	w.exec(`UPDATE projects SET parent_id = $1 WHERE id = $2`, w.projects[1], w.projects[4])
	roles := []string{"owner", "editor", "viewer", "uploader"}
	r := rand.New(rand.NewPCG(8, 18))
	for _, u := range w.users {
		for _, p := range w.projects {
			if r.IntN(4) == 0 {
				w.exec(`INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, $3)`, p, u, roles[r.IntN(4)])
			}
		}
		for _, tm := range w.teams {
			if r.IntN(3) == 0 {
				w.exec(`INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3)`, tm, u, roles[r.IntN(4)])
			}
		}
		for _, o := range w.orgs {
			if n := r.IntN(4); n < 2 {
				w.exec(`INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3)`, o, u, []string{"admin", "member"}[n])
			}
		}
	}
	// Who sees each project, by UsersWithProjectAccess.
	listed := map[string]map[string]string{}
	for _, p := range w.projects {
		ms, err := members.UsersWithProjectAccess(w.ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		listed[p] = map[string]string{}
		for _, m := range ms {
			listed[p][m.UserID] = string(m.Role)
		}
	}
	checked, inherited := 0, 0
	for _, u := range w.users {
		entries, err := audit.List(w.ctx, access.Filter{UserID: u, Limit: 1000})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, e := range entries {
			got[*e.ProjectID] = e.EffectiveRole
			for _, g := range e.Grants {
				if g.Kind == access.KindParentProject {
					inherited++
				}
			}
		}
		visible, err := members.ProjectIDsForUser(w.ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range w.projects {
			want, ok, err := members.RoleOnProject(w.ctx, u, p)
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				want = ""
			}
			if got[p] != string(want) {
				t.Errorf("user %s project %s: audit %q, RoleOnProject %q", u, p, got[p], want)
			}
			if listed[p][u] != string(want) {
				t.Errorf("user %s project %s: UsersWithProjectAccess %q, RoleOnProject %q", u, p, listed[p][u], want)
			}
			if slices.Contains(visible, p) != ok {
				t.Errorf("user %s project %s: in ProjectIDsForUser = %v, has a role = %v", u, p, slices.Contains(visible, p), ok)
			}
			checked++
		}
	}
	if checked != 30 {
		t.Fatalf("checked %d pairs", checked)
	}
	if inherited == 0 {
		t.Fatal("the matrix exercised no inherited grant")
	}
}

// A grant on a parent opens every descendant, and the audit names the
// ancestor it came from; moving the child away takes the access with it.
func TestAuditNamesParentProject(t *testing.T) {
	w, audit, members := seed(t)
	dana := w.users[0]
	parent, child, grandchild := w.projects[0], w.projects[2], w.projects[3] // team0, team2, team0: all org0
	w.exec(`UPDATE projects SET parent_id = $1 WHERE id = $2`, parent, child)
	w.exec(`UPDATE projects SET parent_id = $1 WHERE id = $2`, child, grandchild)
	w.exec(`INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, 'editor')`, parent, dana)

	role, ok, err := members.RoleOnProject(w.ctx, dana, child)
	if err != nil || !ok || role != "editor" {
		t.Fatalf("role on child = %q %v %v, want editor", role, ok, err)
	}
	entries, err := audit.List(w.ctx, access.Filter{UserID: dana, ProjectID: grandchild, Limit: 10})
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %+v, %v", entries, err)
	}
	g := entries[0].Grants
	if entries[0].EffectiveRole != "editor" || len(g) != 1 || g[0].Kind != access.KindParentProject ||
		g[0].ViaID == nil || *g[0].ViaID != parent || g[0].ViaName == nil || *g[0].ViaName != "proj0" {
		t.Errorf("grandchild grants = %+v", entries[0])
	}

	// Detach the middle project: neither it nor its child is reachable now.
	w.exec(`UPDATE projects SET parent_id = NULL WHERE id = $1`, child)
	for _, p := range []string{child, grandchild} {
		if _, ok, _ := members.RoleOnProject(w.ctx, dana, p); ok {
			t.Errorf("project %s still reachable after the move", p)
		}
	}
}

// Each grant kind is explained; an SSO-synced grant names the mapping that
// makes it; a deactivated user is flagged; an instance admin reaches every
// project with one row (or the filtered project's row).
func TestAuditExplainsGrants(t *testing.T) {
	w, audit, _ := seed(t)
	dana, sam, admin, bot := w.users[0], w.users[1], w.users[2], w.users[3]
	p0 := w.projects[0] // team0, org0
	w.exec(`INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, 'viewer')`, p0, dana)
	w.exec(`INSERT INTO team_members (team_id, user_id, role, source) VALUES ($1, $2, 'editor', 'sso')`, w.teams[0], dana)
	w.exec(`INSERT INTO sso_group_mappings (provider, group_name, target_kind, team_id, role) VALUES
		('oidc', 'eng', 'team', $1, 'editor'), ('saml', 'eng-viewers', 'team', $1, 'viewer')`, w.teams[0])
	w.exec(`INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, 'admin')`, w.orgs[0], sam)
	w.exec(`UPDATE users SET disabled_at = now() WHERE id = $1`, sam)
	w.exec(`UPDATE users SET is_admin = true WHERE id = $1`, admin)
	w.exec(`UPDATE users SET kind = 'service', password_hash = NULL WHERE id = $1`, bot)
	w.exec(`INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, 'editor')`, p0, bot)

	entries, err := audit.List(w.ctx, access.Filter{ProjectID: p0, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]access.Entry{}
	for _, e := range entries {
		by[e.UserID] = e
	}
	d := by[dana]
	if d.EffectiveRole != "editor" || len(d.Grants) != 2 || d.Grants[0].Kind != access.KindTeam ||
		*d.Grants[0].ViaName != "team0" || d.Grants[0].Source != "sso" ||
		!slices.Equal(d.Grants[0].SSOMappings, []string{"oidc:eng"}) || d.Grants[1].Kind != access.KindProject {
		t.Errorf("dana = %+v", d)
	}
	s := by[sam]
	if s.EffectiveRole != "owner" || !s.Disabled || s.Grants[0].Kind != access.KindOrgAdmin || *s.Grants[0].ViaName != "org0" {
		t.Errorf("sam (deactivated org admin) = %+v", s)
	}
	a := by[admin]
	if a.EffectiveRole != "admin" || a.ProjectID == nil || *a.ProjectID != p0 || a.Grants[0].Kind != access.KindInstanceAdmin {
		t.Errorf("admin on the project = %+v", a)
	}
	if b := by[bot]; b.PrincipalKind != "service" || b.EffectiveRole != "editor" {
		t.Errorf("service account = %+v", b)
	}
	if len(entries) != 4 {
		t.Errorf("project 0 has %d principals, want 4", len(entries))
	}

	// Unfiltered, the admin is one "every project" row.
	all, err := audit.List(w.ctx, access.Filter{UserID: admin, Limit: 100})
	if err != nil || len(all) != 1 || all[0].ProjectID != nil || all[0].EffectiveRole != "admin" {
		t.Fatalf("admin entries = %+v, %v", all, err)
	}
	// Filters: SSO-sourced grants only; services only.
	// Dana's SSO team role reaches both of team0's projects (proj0, proj3).
	if sso, _ := audit.List(w.ctx, access.Filter{Source: "sso", Limit: 100}); len(sso) != 2 ||
		sso[0].UserID != dana || sso[1].UserID != dana || *sso[1].ProjectName != "proj3" {
		t.Errorf("source=sso = %d entries", len(sso))
	}
	if svc, _ := audit.List(w.ctx, access.Filter{PrincipalKind: "service", Limit: 100}); len(svc) != 1 || svc[0].UserID != bot {
		t.Errorf("principal_kind=service = %+v", svc)
	}
}
