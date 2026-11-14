// Package membership manages team membership and answers the authorization
// questions: what role does a user have on a team, which teams/projects can they
// see, and which team owns a given resource.
package membership

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
)

// Domain errors.
var (
	ErrNotFound  = errors.New("membership not found")
	ErrNoUser    = errors.New("user does not exist")
	ErrLastOwner = errors.New("cannot remove the last owner of a team")
)

// Member is a user's membership in a team.
type Member struct {
	UserID string          `json:"user_id"`
	Email  string          `json:"email"`
	Role   domain.TeamRole `json:"role"`
	// Source is "manual" (granted here) or "sso" (an IdP group mapping, synced
	// on that user's every SSO login). Empty on computed effective-access lists.
	Source string `json:"source,omitempty"`
}

// Repository provides access to team_members.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// ProjectGrantsSQL lists every grant that reaches a project, one row per
// (user_id, project_id, kind, role, source, via_id): a direct project grant
// (kind project), the user's team role on the project's team (team; via_id =
// the team), org admin of the owning org (org_admin, role owner; via_id = the
// org), and a project or team grant on any ancestor project, which reaches
// every descendant (parent_project, same role and source; via_id = the
// ancestor). Org admin isn't inherited: a tree never leaves its org, so it
// already reaches every descendant itself. A user's effective role is the
// highest of their rows (domain.MaxTeamRole). RoleOnProject and the permission
// audit both read it, so "what can this user do here" has one definition.
// Instance admins bypass project authorization entirely and aren't rows here.
//
// The inherited branch walks up from each child project (project_ancestors,
// a recursive CTE), so a filter on project_id stays a narrow lookup.
const ProjectGrantsSQL = `
	SELECT pm.user_id, pm.project_id, 'project' AS kind, pm.role, pm.source, NULL::uuid AS via_id
	  FROM project_members pm
	UNION ALL
	SELECT tm.user_id, p.id, 'team', tm.role, tm.source, tm.team_id
	  FROM team_members tm JOIN projects p ON p.team_id = tm.team_id
	UNION ALL
	SELECT om.user_id, p.id, 'org_admin', 'owner', om.source, t.org_id
	  FROM org_members om JOIN teams t ON t.org_id = om.org_id JOIN projects p ON p.team_id = t.id
	 WHERE om.role = 'admin'
	UNION ALL
	SELECT ag.user_id, d.id, 'parent_project', ag.role, ag.source, a.ancestor_id
	  FROM projects d
	  CROSS JOIN LATERAL project_ancestors(d.id) a
	  JOIN (SELECT pm.user_id, pm.project_id, pm.role, pm.source FROM project_members pm
	        UNION ALL
	        SELECT tm.user_id, p.id, tm.role, tm.source
	          FROM team_members tm JOIN projects p ON p.team_id = tm.team_id) ag ON ag.project_id = a.ancestor_id
	 WHERE d.parent_id IS NOT NULL`

// UsersWithProjectAccess lists everyone who can see a project with their
// effective (highest) role: direct grants, the owning team, admins of the
// owning organization (owner), grants on an ancestor project, and instance
// admins (owner). Same rule as RoleOnProject, for every user at once.
func (r *Repository) UsersWithProjectAccess(ctx context.Context, projectID string) ([]Member, error) {
	const q = `
		WITH grants AS (
			SELECT user_id, role FROM (` + ProjectGrantsSQL + `) g WHERE g.project_id = $1
			UNION ALL
			SELECT id, 'owner' FROM users WHERE is_admin
		)
		SELECT g.user_id, u.email,
		       CASE max(CASE g.role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END)
		            WHEN 3 THEN 'owner' WHEN 2 THEN 'editor' ELSE 'viewer' END
		FROM grants g JOIN users u ON u.id = g.user_id
		GROUP BY g.user_id, u.email
		ORDER BY u.email`
	rows, err := r.db.Query(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("users with project access: %w", err)
	}
	defer rows.Close()
	out := []Member{}
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Email, &m.Role); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Add inserts or updates a user's role on a team. A manual grant takes over an
// SSO-synced row for the same team, which the group sync then leaves alone.
func (r *Repository) Add(ctx context.Context, teamID, userID string, role domain.TeamRole) error {
	const q = `INSERT INTO team_members (team_id, user_id, role) VALUES ($1, $2, $3)
		ON CONFLICT (team_id, user_id) DO UPDATE SET role = EXCLUDED.role, source = 'manual'`
	_, err := r.db.Exec(ctx, q, teamID, userID, role)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" { // FK: user or team missing
		return ErrNoUser
	}
	if err != nil {
		return fmt.Errorf("add member: %w", err)
	}
	return nil
}

// Remove drops a user from a team, refusing to remove the last owner.
func (r *Repository) Remove(ctx context.Context, teamID, userID string) error {
	var owners int
	if err := r.db.QueryRow(ctx,
		`SELECT count(*) FROM team_members WHERE team_id = $1 AND role = 'owner'`, teamID).Scan(&owners); err != nil {
		return fmt.Errorf("count owners: %w", err)
	}
	var role domain.TeamRole
	err := r.db.QueryRow(ctx, `SELECT role FROM team_members WHERE team_id = $1 AND user_id = $2`, teamID, userID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("get member: %w", err)
	}
	if role == domain.TeamOwner && owners <= 1 {
		return ErrLastOwner
	}
	if _, err := r.db.Exec(ctx, `DELETE FROM team_members WHERE team_id = $1 AND user_id = $2`, teamID, userID); err != nil {
		return fmt.Errorf("remove member: %w", err)
	}
	return nil
}

// List returns a team's members with their email + role.
func (r *Repository) List(ctx context.Context, teamID string) ([]Member, error) {
	const q = `SELECT m.user_id, u.email, m.role, m.source
		FROM team_members m JOIN users u ON u.id = m.user_id
		WHERE m.team_id = $1 ORDER BY m.role DESC, u.email`
	rows, err := r.db.Query(ctx, q, teamID)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	defer rows.Close()
	members := []Member{}
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Email, &m.Role, &m.Source); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

// RoleOnTeam returns a user's effective role on a team and whether they have
// any access. Admins of the team's organization are treated as team owners.
func (r *Repository) RoleOnTeam(ctx context.Context, userID, teamID string) (domain.TeamRole, bool, error) {
	const q = `SELECT COALESCE(
		(SELECT role FROM team_members WHERE user_id = $1 AND team_id = $2),
		(SELECT 'owner' FROM teams t JOIN org_members om ON om.org_id = t.org_id
		  WHERE t.id = $2 AND om.user_id = $1 AND om.role = 'admin')
	)`
	var role *domain.TeamRole
	if err := r.db.QueryRow(ctx, q, userID, teamID).Scan(&role); err != nil {
		return "", false, fmt.Errorf("role on team: %w", err)
	}
	if role == nil {
		return "", false, nil
	}
	return *role, true, nil
}

// --- project membership ---
//
// A project role grants access to *one* project without joining its team — the
// "give Dana read access to this one project" case, which team membership alone
// cannot express.

// AddToProject inserts or updates a user's role on a project. Like Add, a
// manual grant takes over an SSO-synced row.
func (r *Repository) AddToProject(ctx context.Context, projectID, userID string, role domain.TeamRole) error {
	const q = `INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, $3)
		ON CONFLICT (project_id, user_id) DO UPDATE SET role = EXCLUDED.role, source = 'manual'`
	_, err := r.db.Exec(ctx, q, projectID, userID, role)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" { // FK: user or project missing
		return ErrNoUser
	}
	if err != nil {
		return fmt.Errorf("add project member: %w", err)
	}
	return nil
}

// RemoveFromProject drops a user's direct role on a project.
//
// There is no last-owner guard here, unlike teams: a project always remains
// reachable through its team, so removing its last direct member cannot orphan it.
func (r *Repository) RemoveFromProject(ctx context.Context, projectID, userID string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM project_members WHERE project_id = $1 AND user_id = $2`, projectID, userID)
	if err != nil {
		return fmt.Errorf("remove project member: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListProjectMembers returns a project's *direct* members. It deliberately does
// not include people who reach the project through its team — that would conflate
// "granted access here" with "has access", and you couldn't tell what you'd
// actually be revoking.
func (r *Repository) ListProjectMembers(ctx context.Context, projectID string) ([]Member, error) {
	const q = `SELECT m.user_id, u.email, m.role, m.source
		FROM project_members m JOIN users u ON u.id = m.user_id
		WHERE m.project_id = $1 ORDER BY m.role DESC, u.email`
	rows, err := r.db.Query(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("list project members: %w", err)
	}
	defer rows.Close()
	members := []Member{}
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Email, &m.Role, &m.Source); err != nil {
			return nil, fmt.Errorf("scan project member: %w", err)
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

// RoleOnProject returns a user's effective role on a project: the **highest** of
// every path they hold access through — a direct project role, their role on the
// owning team, or owner if they administer the owning organization.
//
// Highest, not "most specific": roles add access, they never take it away. A team
// editor cannot be pinned down to viewer on one project, because a model where a
// grant in one place is cancelled by a grant in another is one nobody can reason
// about — and the mistakes it produces are silent.
func (r *Repository) RoleOnProject(ctx context.Context, userID, projectID string) (domain.TeamRole, bool, error) {
	const q = `SELECT role FROM (` + ProjectGrantsSQL + `) g WHERE g.user_id = $1 AND g.project_id = $2`
	rows, err := r.db.Query(ctx, q, userID, projectID)
	if err != nil {
		return "", false, fmt.Errorf("role on project: %w", err)
	}
	defer rows.Close()

	var roles []domain.TeamRole
	for rows.Next() {
		var role domain.TeamRole
		if err := rows.Scan(&role); err != nil {
			return "", false, fmt.Errorf("scan project role: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	role, ok := domain.MaxTeamRole(roles...)
	return role, ok, nil
}

// ProjectExists reports whether a project exists, so the middleware can tell
// "you may not" (403) apart from "there is no such thing" (404).
func (r *Repository) ProjectExists(ctx context.Context, projectID string) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx, `SELECT true FROM projects WHERE id = $1`, projectID).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("project exists: %w", err)
	}
	return true, nil
}

// AdminStatus reports whether a user is currently an instance admin, and whether
// they are the owner.
//
// It reads the database, not the JWT. The token carries an `is_admin` claim for
// the UI's convenience, but authorization must not trust it: a demoted admin's
// token still says admin until it expires, so trusting the claim means a
// revocation you performed does not actually take effect for up to a token
// lifetime. One primary-key lookup per request is a cheap price for a revocation
// that is real.
func (r *Repository) AdminStatus(ctx context.Context, userID string) (isAdmin, isOwner bool, err error) {
	err = r.db.QueryRow(ctx, `SELECT is_admin, is_owner FROM users WHERE id = $1`, userID).
		Scan(&isAdmin, &isOwner)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, false, nil // the user was deleted; they are nobody now
	}
	if err != nil {
		return false, false, fmt.Errorf("admin status: %w", err)
	}
	return isAdmin, isOwner, nil
}

// RoleOnOrg returns a user's org role and whether they're a member.
func (r *Repository) RoleOnOrg(ctx context.Context, userID, orgID string) (domain.OrgRole, bool, error) {
	var role domain.OrgRole
	err := r.db.QueryRow(ctx, `SELECT role FROM org_members WHERE user_id = $1 AND org_id = $2`, userID, orgID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("role on org: %w", err)
	}
	return role, true, nil
}

// teamScopeSQL selects the ids of teams a user can access: direct team members
// plus every team in orgs where they're an admin. $1 is the user id.
const teamScopeSQL = `
	SELECT team_id FROM team_members WHERE user_id = $1
	UNION
	SELECT t.id FROM teams t JOIN org_members om ON om.org_id = t.org_id
	  WHERE om.user_id = $1 AND om.role = 'admin'`

// TeamIDsForUser returns the ids of teams the user can access.
func (r *Repository) TeamIDsForUser(ctx context.Context, userID string) ([]string, error) {
	return r.scanIDs(ctx, teamScopeSQL, userID)
}

// OrgIDsForUser returns the ids of orgs the user belongs to.
func (r *Repository) OrgIDsForUser(ctx context.Context, userID string) ([]string, error) {
	return r.scanIDs(ctx, `SELECT org_id FROM org_members WHERE user_id = $1`, userID)
}

// ProjectIDsForUser returns the ids of projects the user can see: every
// project ProjectGrantsSQL gives them a row on — their teams' projects, direct
// grants, their org-admin orgs' projects, and every descendant of those.
// Portfolio-wide list endpoints filter on this — so a grant that isn't in here
// is a project the user can open but cannot find, which is its own kind of bug.
func (r *Repository) ProjectIDsForUser(ctx context.Context, userID string) ([]string, error) {
	const q = `SELECT DISTINCT g.project_id FROM (` + ProjectGrantsSQL + `) g WHERE g.user_id = $1`
	return r.scanIDs(ctx, q, userID)
}

// OwnedProjectIDs returns the ids of projects on which the user's effective
// role is owner (ProjectGrantsSQL) — whose archived records they may list.
func (r *Repository) OwnedProjectIDs(ctx context.Context, userID string) ([]string, error) {
	return r.scanIDs(ctx, `SELECT DISTINCT project_id FROM (`+ProjectGrantsSQL+`) g WHERE g.user_id = $1 AND g.role = 'owner'`, userID)
}

func (r *Repository) scanIDs(ctx context.Context, q, arg string) ([]string, error) {
	rows, err := r.db.Query(ctx, q, arg)
	if err != nil {
		return nil, fmt.Errorf("scan ids: %w", err)
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// TeamOfProject returns the team that owns a project.
func (r *Repository) TeamOfProject(ctx context.Context, projectID string) (string, bool, error) {
	var teamID string
	err := r.db.QueryRow(ctx, `SELECT team_id FROM projects WHERE id = $1`, projectID).Scan(&teamID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("team of project: %w", err)
	}
	return teamID, true, nil
}

// resourceTables maps a route resource to its table (all have a project_id).
var resourceTables = map[string]string{
	"findings":    "findings",
	"scans":       "scans",
	"sboms":       "sboms",
	"assets":      "assets",
	"vex":         "vex_statements",
	"assessments": "finding_assessments",
	"engagements": "engagements",
	"cra-cases":   "cra_cases",
	"remediation": "remediation_actions",
}

// ProjectOfResource resolves a project-owned resource (finding/scan/sbom/asset/
// vex) to its project, which is what authorization is checked against.
func (r *Repository) ProjectOfResource(ctx context.Context, resource, id string) (string, bool, error) {
	table, ok := resourceTables[resource]
	if !ok {
		return "", false, nil
	}
	// The table name comes from resourceTables, never from the request — the id is
	// the only user input, and it's a bound parameter.
	q := fmt.Sprintf(`SELECT project_id FROM %s WHERE id = $1`, table)
	var projectID string
	err := r.db.QueryRow(ctx, q, id).Scan(&projectID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("project of %s: %w", resource, err)
	}
	return projectID, true, nil
}
