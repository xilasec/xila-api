package membership_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/membership"
	"github.com/xilasec/xila-api/internal/pgtest"
)

func seedUser(t *testing.T, pool *pgxpool.Pool, email string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id`, email).Scan(&id); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return id
}

func seedTeamProject(t *testing.T, pool *pgxpool.Pool) (teamID, projectID string) {
	t.Helper()
	ctx := context.Background()
	if err := pool.QueryRow(ctx, `WITH o AS (INSERT INTO organizations (slug,name) VALUES ('o-mb','o') RETURNING id) INSERT INTO teams (org_id,slug,name) SELECT id,'t','T' FROM o RETURNING id`).Scan(&teamID); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (team_id, slug, name) VALUES ($1,'p','P') RETURNING id`, teamID).Scan(&projectID); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return teamID, projectID
}

func TestMembershipRolesAndResolution(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := membership.NewRepository(pool)
	ctx := context.Background()

	owner := seedUser(t, pool, "owner@x.io")
	other := seedUser(t, pool, "other@x.io")
	teamID, projectID := seedTeamProject(t, pool)

	if err := repo.Add(ctx, teamID, owner, domain.TeamOwner, ""); err != nil {
		t.Fatalf("add owner: %v", err)
	}
	role, member, err := repo.RoleOnTeam(ctx, owner, teamID)
	if err != nil || !member || role != domain.TeamOwner {
		t.Fatalf("RoleOnTeam(owner) = %v,%v,%v", role, member, err)
	}
	if _, member, _ := repo.RoleOnTeam(ctx, other, teamID); member {
		t.Error("other should not be a member yet")
	}

	// Adding as a non-member of the projects table etc. — add other as viewer.
	if err := repo.Add(ctx, teamID, other, domain.TeamViewer, ""); err != nil {
		t.Fatalf("add viewer: %v", err)
	}
	if members, _ := repo.List(ctx, teamID); len(members) != 2 {
		t.Errorf("List members = %d, want 2", len(members))
	}

	// The last owner cannot be removed.
	if err := repo.Remove(ctx, teamID, owner); !errors.Is(err, membership.ErrLastOwner) {
		t.Errorf("remove last owner err = %v, want ErrLastOwner", err)
	}
	// A viewer can be removed.
	if err := repo.Remove(ctx, teamID, other); err != nil {
		t.Errorf("remove viewer: %v", err)
	}

	// Resolution: project -> team, and the owner's visible projects.
	if tid, ok, _ := repo.TeamOfProject(ctx, projectID); !ok || tid != teamID {
		t.Errorf("TeamOfProject = %s,%v, want %s", tid, ok, teamID)
	}
	if pids, _ := repo.ProjectIDsForUser(ctx, owner); len(pids) != 1 || pids[0] != projectID {
		t.Errorf("ProjectIDsForUser(owner) = %v, want [%s]", pids, projectID)
	}

	// Resolution via a project-owned resource (finding -> project).
	f, err := finding.NewRepository(pool).Upsert(ctx, finding.Finding{
		ProjectID: projectID, Fingerprint: "fp", Scanner: "trivy",
		Category: domain.CategorySCA, RuleID: "CVE-1", Title: "v", Severity: domain.SeverityHigh,
	})
	if err != nil {
		t.Fatalf("seed finding: %v", err)
	}
	if pid, ok, _ := repo.ProjectOfResource(ctx, "findings", f.ID); !ok || pid != projectID {
		t.Errorf("ProjectOfResource(findings) = %s,%v, want %s", pid, ok, projectID)
	}
	if _, ok, _ := repo.ProjectOfResource(ctx, "bogus", f.ID); ok {
		t.Error("ProjectOfResource(bogus) should not resolve")
	}
}

func TestOrgAdminIsTeamOwner(t *testing.T) {
	pool := pgtest.Pool(t)
	repo := membership.NewRepository(pool)
	ctx := context.Background()

	user := seedUser(t, pool, "orgadmin@x.io")
	teamID, projectID := seedTeamProject(t, pool)
	var orgID string
	if err := pool.QueryRow(ctx, `SELECT org_id FROM teams WHERE id = $1`, teamID).Scan(&orgID); err != nil {
		t.Fatalf("get org: %v", err)
	}

	// The user is an org admin but NOT a direct team member.
	if _, err := pool.Exec(ctx,
		`INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, 'admin')`, orgID, user); err != nil {
		t.Fatalf("add org admin: %v", err)
	}

	role, ok, err := repo.RoleOnTeam(ctx, user, teamID)
	if err != nil || !ok || role != domain.TeamOwner {
		t.Fatalf("RoleOnTeam(org admin) = %v,%v,%v, want owner,true", role, ok, err)
	}
	if r, ok, _ := repo.RoleOnOrg(ctx, user, orgID); !ok || r != domain.OrgAdmin {
		t.Errorf("RoleOnOrg = %v,%v, want admin,true", r, ok)
	}
	if tids, _ := repo.TeamIDsForUser(ctx, user); len(tids) != 1 || tids[0] != teamID {
		t.Errorf("TeamIDsForUser = %v, want [%s] via org admin", tids, teamID)
	}
	if pids, _ := repo.ProjectIDsForUser(ctx, user); len(pids) != 1 || pids[0] != projectID {
		t.Errorf("ProjectIDsForUser = %v, want [%s] via org admin", pids, projectID)
	}
}
