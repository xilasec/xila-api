package membership_test

import (
	"context"
	"testing"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/membership"
	"github.com/xilasec/xila-api/internal/pgtest"
)

// TestProjectRoleGrantsOneProjectOnly is the feature: "give Dana read access to
// this one project" — which team membership alone could not express, because
// joining a team hands you every project in it.
func TestProjectRoleGrantsOneProjectOnly(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := membership.NewRepository(pool)
	ctx := context.Background()

	dana := seedUser(t, pool, "dana@x.io")
	var teamID, projectA, projectB string
	if err := pool.QueryRow(ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-pr','o') RETURNING id)
		INSERT INTO teams (org_id, slug, name) SELECT id, 't', 'Team' FROM o RETURNING id`).Scan(&teamID); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (team_id, slug, name) VALUES ($1,'a','A') RETURNING id`, teamID).Scan(&projectA); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (team_id, slug, name) VALUES ($1,'b','B') RETURNING id`, teamID).Scan(&projectB); err != nil {
		t.Fatal(err)
	}

	// Dana is in no team. She gets viewer on project A only.
	if err := repo.AddToProject(ctx, projectA, dana, domain.TeamViewer); err != nil {
		t.Fatalf("grant: %v", err)
	}

	role, ok, err := repo.RoleOnProject(ctx, dana, projectA)
	if err != nil || !ok || role != domain.TeamViewer {
		t.Fatalf("role on the granted project = %q,%v (err %v), want viewer", role, ok, err)
	}
	// The sibling project in the same team must stay invisible. A grant that leaks
	// sideways is worse than no grant at all.
	if _, ok, _ := repo.RoleOnProject(ctx, dana, projectB); ok {
		t.Error("a grant on one project must not give access to another project in the same team")
	}

	// And she must be able to *find* it: a project you can open but cannot see in
	// any list is a bug, not a security feature.
	pids, err := repo.ProjectIDsForUser(ctx, dana)
	if err != nil {
		t.Fatalf("scope: %v", err)
	}
	if len(pids) != 1 || pids[0] != projectA {
		t.Errorf("visible projects = %v, want exactly [%s]", pids, projectA)
	}

	// A viewer is strictly read-only.
	if role.AtLeast(domain.TeamEditor) {
		t.Error("viewer must not satisfy an editor requirement")
	}

	// Revoking the grant takes the access away entirely.
	if err := repo.RemoveFromProject(ctx, projectA, dana); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, ok, _ := repo.RoleOnProject(ctx, dana, projectA); ok {
		t.Error("access survived revocation")
	}
}

// TestEffectiveRoleIsTheHighestGrant: roles add access, they never subtract it. A
// model where a grant in one place is cancelled by one somewhere else is a model
// nobody can reason about, and its mistakes are silent.
func TestEffectiveRoleIsTheHighestGrant(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := membership.NewRepository(pool)
	ctx := context.Background()

	u := seedUser(t, pool, "eve@x.io")
	var orgID, teamID, projectID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO organizations (slug,name) VALUES ('o-eff','o') RETURNING id`).Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO teams (org_id,slug,name) VALUES ($1,'t','T') RETURNING id`, orgID).Scan(&teamID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (team_id,slug,name) VALUES ($1,'p','P') RETURNING id`, teamID).Scan(&projectID); err != nil {
		t.Fatal(err)
	}

	// Editor on the team, viewer on this project. The team grant is higher, so it
	// wins — the project grant cannot demote her.
	if err := repo.Add(ctx, teamID, u, domain.TeamEditor); err != nil {
		t.Fatal(err)
	}
	if err := repo.AddToProject(ctx, projectID, u, domain.TeamViewer); err != nil {
		t.Fatal(err)
	}
	role, ok, err := repo.RoleOnProject(ctx, u, projectID)
	if err != nil || !ok {
		t.Fatalf("role: %v", err)
	}
	if role != domain.TeamEditor {
		t.Errorf("effective role = %q, want editor — a lower project grant must not demote a team editor", role)
	}

	// Now owner on the project: the higher grant wins the other way round.
	if err := repo.AddToProject(ctx, projectID, u, domain.TeamOwner); err != nil {
		t.Fatal(err)
	}
	if role, _, _ := repo.RoleOnProject(ctx, u, projectID); role != domain.TeamOwner {
		t.Errorf("effective role = %q, want owner — a project grant must be able to raise a team role", role)
	}

	// An org admin is owner everywhere in the org, with no project row at all.
	admin := seedUser(t, pool, "orgadmin2@x.io")
	if _, err := pool.Exec(ctx,
		`INSERT INTO org_members (org_id, user_id, role) VALUES ($1,$2,'admin')`, orgID, admin); err != nil {
		t.Fatal(err)
	}
	if role, ok, _ := repo.RoleOnProject(ctx, admin, projectID); !ok || role != domain.TeamOwner {
		t.Errorf("org admin's project role = %q,%v, want owner", role, ok)
	}

	// A stranger has nothing.
	stranger := seedUser(t, pool, "stranger@x.io")
	if _, ok, _ := repo.RoleOnProject(ctx, stranger, projectID); ok {
		t.Error("a user with no grant anywhere must have no access")
	}
}
