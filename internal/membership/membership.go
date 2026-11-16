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

// Member is a user's or group's membership in a team/org/project. Exactly one
// of UserID or GroupID is set.
type Member struct {
	UserID string          `json:"user_id,omitempty"`
	Email  string          `json:"email,omitempty"`
	Role   domain.TeamRole `json:"role"`
	// Source is "manual" (granted here) or "sso" (an IdP group mapping, synced
	// on that user's every SSO login). Empty on computed effective-access lists.
	Source string `json:"source,omitempty"`
	// GroupID/GroupName are set instead of UserID/Email when this grant is on
	// a user group rather than an individual user.
	GroupID   string `json:"group_id,omitempty"`
	GroupName string `json:"group_name,omitempty"`
	// CustomRoleID/CustomRoleName are set when the grant uses a custom role
	// (team/project grants only). Role is still the custom role's base role.
	CustomRoleID   string `json:"custom_role_id,omitempty"`
	CustomRoleName string `json:"custom_role_name,omitempty"`
}

// Repository provides access to team_members, org_members, project_members,
// user_groups and custom_roles.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// ProjectGrantsSQL lists every grant that reaches a project, one row per
// (user_id, project_id, kind, role, source, via_id, custom_role_id, group_id):
// a direct project grant (kind project), the user's team role on the
// project's team (team; via_id = the team), org admin of the owning org
// (org_admin, role owner; via_id = the org), and a project or team grant on
// any ancestor project, which reaches every descendant (parent_project, same
// role and source; via_id = the ancestor). Org admin isn't inherited: a tree
// never leaves its org, so it already reaches every descendant itself.
//
// A team/project grant made on a user group is expanded here to one row per
// member (group_id names the group it came through; custom_role_id, when
// set, narrows that specific grant's capabilities — see internal/authz). A
// user's effective role is the highest of their rows (domain.MaxTeamRole).
// RoleOnProject and the permission audit both read it, so "what can this user
// do here" has one definition. Instance admins bypass project authorization
// entirely and aren't rows here.
//
// The inherited branch walks up from each child project (project_ancestors,
// a recursive CTE), so a filter on project_id stays a narrow lookup.
const ProjectGrantsSQL = `
	SELECT COALESCE(pm.user_id, pgm.user_id) AS user_id, pm.project_id, 'project' AS kind, pm.role, pm.source,
	       NULL::uuid AS via_id, pm.custom_role_id, pm.group_id
	  FROM project_members pm
	  LEFT JOIN user_group_members pgm ON pgm.group_id = pm.group_id
	 WHERE pm.user_id IS NOT NULL OR pgm.user_id IS NOT NULL
	UNION ALL
	SELECT COALESCE(tm.user_id, tgm.user_id), p.id, 'team', tm.role, tm.source, tm.team_id, tm.custom_role_id, tm.group_id
	  FROM team_members tm JOIN projects p ON p.team_id = tm.team_id
	  LEFT JOIN user_group_members tgm ON tgm.group_id = tm.group_id
	 WHERE tm.user_id IS NOT NULL OR tgm.user_id IS NOT NULL
	UNION ALL
	SELECT COALESCE(om.user_id, ogm.user_id), p.id, 'org_admin', 'owner', om.source, t.org_id, NULL::uuid, om.group_id
	  FROM org_members om JOIN teams t ON t.org_id = om.org_id JOIN projects p ON p.team_id = t.id
	  LEFT JOIN user_group_members ogm ON ogm.group_id = om.group_id
	 WHERE om.role = 'admin' AND (om.user_id IS NOT NULL OR ogm.user_id IS NOT NULL)
	UNION ALL
	SELECT ag.user_id, d.id, 'parent_project', ag.role, ag.source, a.ancestor_id, ag.custom_role_id, ag.group_id
	  FROM projects d
	  CROSS JOIN LATERAL project_ancestors(d.id) a
	  JOIN (SELECT COALESCE(pm.user_id, pgm.user_id) AS user_id, pm.project_id, pm.role, pm.source, pm.custom_role_id, pm.group_id
	          FROM project_members pm
	          LEFT JOIN user_group_members pgm ON pgm.group_id = pm.group_id
	         WHERE pm.user_id IS NOT NULL OR pgm.user_id IS NOT NULL
	        UNION ALL
	        SELECT COALESCE(tm.user_id, tgm.user_id), p.id, tm.role, tm.source, tm.custom_role_id, tm.group_id
	          FROM team_members tm JOIN projects p ON p.team_id = tm.team_id
	          LEFT JOIN user_group_members tgm ON tgm.group_id = tm.group_id
	         WHERE tm.user_id IS NOT NULL OR tgm.user_id IS NOT NULL) ag ON ag.project_id = a.ancestor_id
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
		       CASE max(CASE g.role WHEN 'owner' THEN 4 WHEN 'editor' THEN 3 WHEN 'uploader' THEN 2 ELSE 1 END)
		            WHEN 4 THEN 'owner' WHEN 3 THEN 'editor' WHEN 2 THEN 'uploader' ELSE 'viewer' END
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
// customRoleID narrows the base role's capabilities (see internal/authz); ""
// means no custom role.
func (r *Repository) Add(ctx context.Context, teamID, userID string, role domain.TeamRole, customRoleID string) error {
	const q = `INSERT INTO team_members (team_id, user_id, role, custom_role_id) VALUES ($1, $2, $3, NULLIF($4, '')::uuid)
		ON CONFLICT (team_id, user_id) WHERE user_id IS NOT NULL
		DO UPDATE SET role = EXCLUDED.role, custom_role_id = EXCLUDED.custom_role_id, source = 'manual'`
	_, err := r.db.Exec(ctx, q, teamID, userID, role, customRoleID)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "23514") { // FK: user or team missing
		return ErrNoUser
	}
	if err != nil {
		return fmt.Errorf("add member: %w", err)
	}
	return nil
}

// AddGroup grants a user group a role on a team: every member of the group
// gets that role on the team. Like Add, a manual grant takes over an
// SSO-synced row for the same (team, group).
func (r *Repository) AddGroup(ctx context.Context, teamID, groupID string, role domain.TeamRole, customRoleID string) error {
	const q = `INSERT INTO team_members (team_id, group_id, role, custom_role_id) VALUES ($1, $2, $3, NULLIF($4, '')::uuid)
		ON CONFLICT (team_id, group_id) WHERE group_id IS NOT NULL
		DO UPDATE SET role = EXCLUDED.role, custom_role_id = EXCLUDED.custom_role_id, source = 'manual'`
	_, err := r.db.Exec(ctx, q, teamID, groupID, role, customRoleID)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "23514") { // FK: group or team missing
		return ErrNoUser
	}
	if err != nil {
		return fmt.Errorf("add group to team: %w", err)
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

// RemoveGroup revokes a group's role on a team, refusing to remove the last
// owner row (a group holding the only 'owner' grant counts as one row, like a
// user's).
func (r *Repository) RemoveGroup(ctx context.Context, teamID, groupID string) error {
	var owners int
	if err := r.db.QueryRow(ctx,
		`SELECT count(*) FROM team_members WHERE team_id = $1 AND role = 'owner'`, teamID).Scan(&owners); err != nil {
		return fmt.Errorf("count owners: %w", err)
	}
	var role domain.TeamRole
	err := r.db.QueryRow(ctx, `SELECT role FROM team_members WHERE team_id = $1 AND group_id = $2`, teamID, groupID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("get group member: %w", err)
	}
	if role == domain.TeamOwner && owners <= 1 {
		return ErrLastOwner
	}
	if _, err := r.db.Exec(ctx, `DELETE FROM team_members WHERE team_id = $1 AND group_id = $2`, teamID, groupID); err != nil {
		return fmt.Errorf("remove group from team: %w", err)
	}
	return nil
}

const teamMembersListSQL = `
	SELECT m.user_id::text, u.email, ''::text, ''::text, m.role, m.source, COALESCE(m.custom_role_id::text, ''), COALESCE(cr.name, '')
	  FROM team_members m
	  JOIN users u ON u.id = m.user_id
	  LEFT JOIN custom_roles cr ON cr.id = m.custom_role_id
	 WHERE m.team_id = $1 AND m.user_id IS NOT NULL
	UNION ALL
	SELECT ''::text, ''::text, m.group_id::text, g.name, m.role, m.source, COALESCE(m.custom_role_id::text, ''), COALESCE(cr.name, '')
	  FROM team_members m
	  JOIN user_groups g ON g.id = m.group_id
	  LEFT JOIN custom_roles cr ON cr.id = m.custom_role_id
	 WHERE m.team_id = $1 AND m.group_id IS NOT NULL
	 ORDER BY 5 DESC, 2, 4`

// List returns a team's members (users and groups) with their email/name + role.
func (r *Repository) List(ctx context.Context, teamID string) ([]Member, error) {
	return r.scanMembers(ctx, teamMembersListSQL, teamID)
}

func (r *Repository) scanMembers(ctx context.Context, q, arg string) ([]Member, error) {
	rows, err := r.db.Query(ctx, q, arg)
	if err != nil {
		return nil, fmt.Errorf("list members: %w", err)
	}
	defer rows.Close()
	members := []Member{}
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Email, &m.GroupID, &m.GroupName, &m.Role, &m.Source, &m.CustomRoleID, &m.CustomRoleName); err != nil {
			return nil, fmt.Errorf("scan member: %w", err)
		}
		members = append(members, m)
	}
	return members, rows.Err()
}

// RoleOnTeam returns a user's effective role on a team and whether they have
// any access: a direct grant, a grant on a group they belong to, or owner if
// they administer the team's organization (directly or through a group).
func (r *Repository) RoleOnTeam(ctx context.Context, userID, teamID string) (domain.TeamRole, bool, error) {
	const q = `
		SELECT role FROM team_members WHERE user_id = $1 AND team_id = $2
		UNION ALL
		SELECT tm.role FROM team_members tm JOIN user_group_members gm ON gm.group_id = tm.group_id
		 WHERE gm.user_id = $1 AND tm.team_id = $2
		UNION ALL
		SELECT 'owner' FROM teams t JOIN org_members om ON om.org_id = t.org_id
		 WHERE t.id = $2 AND om.user_id = $1 AND om.role = 'admin'
		UNION ALL
		SELECT 'owner' FROM teams t JOIN org_members om ON om.org_id = t.org_id
		  JOIN user_group_members gm ON gm.group_id = om.group_id
		 WHERE t.id = $2 AND gm.user_id = $1 AND om.role = 'admin'`
	rows, err := r.db.Query(ctx, q, userID, teamID)
	if err != nil {
		return "", false, fmt.Errorf("role on team: %w", err)
	}
	defer rows.Close()
	var roles []domain.TeamRole
	for rows.Next() {
		var role domain.TeamRole
		if err := rows.Scan(&role); err != nil {
			return "", false, fmt.Errorf("scan team role: %w", err)
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	role, ok := domain.MaxTeamRole(roles...)
	return role, ok, nil
}

// TeamCapabilityAllowed reports whether userID holds at least min on teamID
// through some grant that does not deny cap: a base-role grant never denies
// anything, and among several grants the union wins — a capability denied by
// one is still allowed if another (meeting min) doesn't deny it. Org admins
// (direct or via group) always pass: they are never assigned a custom role.
func (r *Repository) TeamCapabilityAllowed(ctx context.Context, userID, teamID string, min domain.TeamRole, cap domain.Capability) (bool, error) {
	const q = `
		SELECT tm.role, COALESCE(cr.denied_capabilities, '{}')
		  FROM team_members tm
		  LEFT JOIN user_group_members gm ON gm.group_id = tm.group_id
		  LEFT JOIN custom_roles cr ON cr.id = tm.custom_role_id
		 WHERE tm.team_id = $2 AND (tm.user_id = $1 OR gm.user_id = $1)
		UNION ALL
		SELECT 'owner', '{}'::text[]
		  FROM teams t JOIN org_members om ON om.org_id = t.org_id
		  LEFT JOIN user_group_members gm ON gm.group_id = om.group_id
		 WHERE t.id = $2 AND om.role = 'admin' AND (om.user_id = $1 OR gm.user_id = $1)`
	return r.anyGrantAllows(ctx, q, userID, teamID, min, cap)
}

// ProjectCapabilityAllowed is TeamCapabilityAllowed's project-scoped twin,
// over every grant ProjectGrantsSQL resolves for the project (direct, team,
// org admin, inherited).
func (r *Repository) ProjectCapabilityAllowed(ctx context.Context, userID, projectID string, min domain.TeamRole, cap domain.Capability) (bool, error) {
	const q = `
		SELECT g.role, COALESCE(cr.denied_capabilities, '{}')
		  FROM (` + ProjectGrantsSQL + `) g
		  LEFT JOIN custom_roles cr ON cr.id = g.custom_role_id
		 WHERE g.user_id = $1 AND g.project_id = $2`
	return r.anyGrantAllows(ctx, q, userID, projectID, min, cap)
}

// ProjectIDsAllowing narrows ids to the projects on which some grant of
// userID doesn't deny cap (the union rule of ProjectCapabilityAllowed, for a
// cross-project list).
func (r *Repository) ProjectIDsAllowing(ctx context.Context, userID string, ids []string, cap domain.Capability) ([]string, error) {
	const q = `
		SELECT DISTINCT g.project_id
		  FROM (` + ProjectGrantsSQL + `) g
		  LEFT JOIN custom_roles cr ON cr.id = g.custom_role_id
		 WHERE g.user_id = $1 AND g.project_id = ANY($2)
		   AND NOT (COALESCE(cr.denied_capabilities, '{}') @> ARRAY[$3::text])`
	rows, err := r.db.Query(ctx, q, userID, ids, string(cap))
	if err != nil {
		return nil, fmt.Errorf("projects allowing %s: %w", cap, err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func (r *Repository) anyGrantAllows(ctx context.Context, q, userID, scopeID string, min domain.TeamRole, cap domain.Capability) (bool, error) {
	rows, err := r.db.Query(ctx, q, userID, scopeID)
	if err != nil {
		return false, fmt.Errorf("capability check: %w", err)
	}
	defer rows.Close()
	allowed := false
	for rows.Next() {
		var role domain.TeamRole
		var denied []string
		if err := rows.Scan(&role, &denied); err != nil {
			return false, fmt.Errorf("scan capability row: %w", err)
		}
		if role.AtLeast(min) && !containsCapability(denied, cap) {
			allowed = true
		}
	}
	return allowed, rows.Err()
}

func containsCapability(denied []string, cap domain.Capability) bool {
	for _, d := range denied {
		if d == string(cap) {
			return true
		}
	}
	return false
}

// --- project membership ---
//
// A project role grants access to *one* project without joining its team — the
// "give Dana read access to this one project" case, which team membership alone
// cannot express.

// AddToProject inserts or updates a user's role on a project. Like Add, a
// manual grant takes over an SSO-synced row.
func (r *Repository) AddToProject(ctx context.Context, projectID, userID string, role domain.TeamRole, customRoleID string) error {
	const q = `INSERT INTO project_members (project_id, user_id, role, custom_role_id) VALUES ($1, $2, $3, NULLIF($4, '')::uuid)
		ON CONFLICT (project_id, user_id) WHERE user_id IS NOT NULL
		DO UPDATE SET role = EXCLUDED.role, custom_role_id = EXCLUDED.custom_role_id, source = 'manual'`
	_, err := r.db.Exec(ctx, q, projectID, userID, role, customRoleID)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "23514") { // FK: user or project missing
		return ErrNoUser
	}
	if err != nil {
		return fmt.Errorf("add project member: %w", err)
	}
	return nil
}

// AddProjectGroup grants a user group a role on one project.
func (r *Repository) AddProjectGroup(ctx context.Context, projectID, groupID string, role domain.TeamRole, customRoleID string) error {
	const q = `INSERT INTO project_members (project_id, group_id, role, custom_role_id) VALUES ($1, $2, $3, NULLIF($4, '')::uuid)
		ON CONFLICT (project_id, group_id) WHERE group_id IS NOT NULL
		DO UPDATE SET role = EXCLUDED.role, custom_role_id = EXCLUDED.custom_role_id, source = 'manual'`
	_, err := r.db.Exec(ctx, q, projectID, groupID, role, customRoleID)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "23514") { // FK: group or project missing
		return ErrNoUser
	}
	if err != nil {
		return fmt.Errorf("add group to project: %w", err)
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

// RemoveProjectGroup drops a group's direct role on a project.
func (r *Repository) RemoveProjectGroup(ctx context.Context, projectID, groupID string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM project_members WHERE project_id = $1 AND group_id = $2`, projectID, groupID)
	if err != nil {
		return fmt.Errorf("remove group from project: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const projectMembersListSQL = `
	SELECT m.user_id::text, u.email, ''::text, ''::text, m.role, m.source, COALESCE(m.custom_role_id::text, ''), COALESCE(cr.name, '')
	  FROM project_members m
	  JOIN users u ON u.id = m.user_id
	  LEFT JOIN custom_roles cr ON cr.id = m.custom_role_id
	 WHERE m.project_id = $1 AND m.user_id IS NOT NULL
	UNION ALL
	SELECT ''::text, ''::text, m.group_id::text, g.name, m.role, m.source, COALESCE(m.custom_role_id::text, ''), COALESCE(cr.name, '')
	  FROM project_members m
	  JOIN user_groups g ON g.id = m.group_id
	  LEFT JOIN custom_roles cr ON cr.id = m.custom_role_id
	 WHERE m.project_id = $1 AND m.group_id IS NOT NULL
	 ORDER BY 5 DESC, 2, 4`

// ListProjectMembers returns a project's *direct* members (users and groups).
// It deliberately does not include people who reach the project through its
// team — that would conflate "granted access here" with "has access", and you
// couldn't tell what you'd actually be revoking.
func (r *Repository) ListProjectMembers(ctx context.Context, projectID string) ([]Member, error) {
	return r.scanMembers(ctx, projectMembersListSQL, projectID)
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

// RoleOnOrg returns a user's org role and whether they're a member, either
// directly or through a group granted a role on the org.
func (r *Repository) RoleOnOrg(ctx context.Context, userID, orgID string) (domain.OrgRole, bool, error) {
	const q = `
		SELECT role FROM org_members WHERE user_id = $1 AND org_id = $2
		UNION ALL
		SELECT om.role FROM org_members om JOIN user_group_members gm ON gm.group_id = om.group_id
		 WHERE gm.user_id = $1 AND om.org_id = $2`
	rows, err := r.db.Query(ctx, q, userID, orgID)
	if err != nil {
		return "", false, fmt.Errorf("role on org: %w", err)
	}
	defer rows.Close()
	role, found := domain.OrgRole(""), false
	for rows.Next() {
		var r2 domain.OrgRole
		if err := rows.Scan(&r2); err != nil {
			return "", false, fmt.Errorf("scan org role: %w", err)
		}
		if !found || r2 == domain.OrgAdmin {
			role, found = r2, true
			if r2 == domain.OrgAdmin {
				break // admin is the highest org role; nothing beats it
			}
		}
	}
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	return role, found, nil
}

// teamScopeSQL selects the ids of teams a user can access: direct team
// members, teams a group they belong to is granted, plus every team in orgs
// where they're an admin (directly or via group). $1 is the user id.
const teamScopeSQL = `
	SELECT team_id FROM team_members WHERE user_id = $1
	UNION
	SELECT tm.team_id FROM team_members tm JOIN user_group_members gm ON gm.group_id = tm.group_id WHERE gm.user_id = $1
	UNION
	SELECT t.id FROM teams t JOIN org_members om ON om.org_id = t.org_id
	  WHERE om.user_id = $1 AND om.role = 'admin'
	UNION
	SELECT t.id FROM teams t JOIN org_members om ON om.org_id = t.org_id
	  JOIN user_group_members gm ON gm.group_id = om.group_id
	  WHERE gm.user_id = $1 AND om.role = 'admin'`

// TeamIDsForUser returns the ids of teams the user can access.
func (r *Repository) TeamIDsForUser(ctx context.Context, userID string) ([]string, error) {
	return r.scanIDs(ctx, teamScopeSQL, userID)
}

// OrgIDsForUser returns the ids of orgs the user belongs to, directly or
// through a group.
func (r *Repository) OrgIDsForUser(ctx context.Context, userID string) ([]string, error) {
	const q = `
		SELECT org_id FROM org_members WHERE user_id = $1
		UNION
		SELECT om.org_id FROM org_members om JOIN user_group_members gm ON gm.group_id = om.group_id WHERE gm.user_id = $1`
	return r.scanIDs(ctx, q, userID)
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
