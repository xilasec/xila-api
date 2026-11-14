// Package access is the permission audit: for every principal (people and
// service accounts), every project they can reach, the effective role, and
// each grant that contributes to it — a direct project grant, a team role,
// org admin, a grant on an ancestor project, instance admin — naming the SSO
// group mapping behind an SSO-synced grant. The effective role comes from
// membership.ProjectGrantsSQL, the same rows RoleOnProject authorizes with.
package access

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/membership"
)

// Grant kinds.
const (
	KindProject       = "project"        // a direct project grant
	KindTeam          = "team"           // a role on the project's team
	KindOrgAdmin      = "org_admin"      // admin of the owning organization (acts as owner)
	KindParentProject = "parent_project" // a project or team grant on an ancestor project
	KindInstanceAdmin = "instance_admin" // instance admin: every project, every action
)

// Grant is one reason a principal reaches a project.
type Grant struct {
	Kind   string `json:"kind"`
	Role   string `json:"role"`   // owner | editor | viewer ("admin" for instance_admin)
	Source string `json:"source"` // manual | sso
	// Via names what the grant is on: the team (team), the org (org_admin),
	// the ancestor project (parent_project).
	ViaID   *string `json:"via_id"`
	ViaName *string `json:"via_name"`
	// SSOMappings are the IdP group mappings that produce exactly this grant
	// ("provider:group"): an sso-sourced grant was made by at least one of them.
	SSOMappings []string `json:"sso_mappings"`
}

// Entry is a principal's access to one project — or, for an instance admin
// with no project in the filter, to every project (Project* nil).
type Entry struct {
	UserID        string  `json:"user_id"`
	Email         string  `json:"email"`
	PrincipalKind string  `json:"principal_kind"` // user | service
	Disabled      bool    `json:"disabled"`       // deactivated: the grants exist but can't be used
	ProjectID     *string `json:"project_id"`
	ProjectName   *string `json:"project_name"`
	TeamID        *string `json:"team_id"`
	TeamName      *string `json:"team_name"`
	OrgID         *string `json:"org_id"`
	OrgName       *string `json:"org_name"`
	// EffectiveRole is the highest grant: owner | editor | viewer, or admin.
	EffectiveRole string  `json:"effective_role"`
	Grants        []Grant `json:"grants"`
}

// Filter narrows the audit. Zero values don't filter.
type Filter struct {
	User          string // email substring
	UserID        string
	ProjectID     string
	TeamID        string
	OrgID         string
	Role          string // effective role: owner | editor | viewer | admin
	Source        string // any contributing grant has this source: manual | sso
	PrincipalKind string // user | service
	Limit, Offset int
}

// Repository reads the access graph.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// ssoMappingsSQL lists the "provider:group" of the mappings that grant g.
const ssoMappingsSQL = `CASE WHEN g.source = 'sso' THEN (
	SELECT COALESCE(jsonb_agg(m.provider || ':' || m.group_name ORDER BY m.provider, m.group_name), '[]'::jsonb)
	FROM sso_group_mappings m
	WHERE (g.kind = 'project' AND m.target_kind = 'project' AND m.project_id = g.project_id AND m.role = g.role)
	   OR (g.kind = 'team' AND m.target_kind = 'team' AND m.team_id = g.via_id AND m.role = g.role)
	   OR (g.kind = 'org_admin' AND m.target_kind = 'org' AND m.org_id = g.via_id AND m.role = 'admin')
) ELSE '[]'::jsonb END`

// accessSQL is one row per (principal, project) with the effective role and
// its grants, plus one row per instance admin (project NULL, role admin). $1–$8
// are the filters, $9/$10 limit/offset.
const accessSQL = `
WITH g AS (` + membership.ProjectGrantsSQL + `),
pairs AS (
	SELECT g.user_id, g.project_id,
	       (ARRAY['viewer', 'editor', 'owner'])[max(CASE g.role WHEN 'owner' THEN 3 WHEN 'editor' THEN 2 ELSE 1 END)] AS role,
	       jsonb_agg(jsonb_build_object(
	           'kind', g.kind, 'role', g.role, 'source', g.source, 'via_id', g.via_id,
	           'via_name', CASE g.kind WHEN 'team' THEN (SELECT name FROM teams WHERE id = g.via_id)
	                                   WHEN 'org_admin' THEN (SELECT name FROM organizations WHERE id = g.via_id)
	                                   WHEN 'parent_project' THEN (SELECT name FROM projects WHERE id = g.via_id) END,
	           'sso_mappings', ` + ssoMappingsSQL + `)
	         ORDER BY CASE g.kind WHEN 'org_admin' THEN 1 WHEN 'team' THEN 2 WHEN 'project' THEN 3 ELSE 4 END) AS grants
	FROM g GROUP BY g.user_id, g.project_id
),
rows AS (
	SELECT u.id AS user_id, u.email, u.kind AS principal_kind, u.disabled_at IS NOT NULL AS disabled,
	       p.id AS project_id, p.name AS project_name, t.id AS team_id, t.name AS team_name,
	       o.id AS org_id, o.name AS org_name, pairs.role, pairs.grants
	FROM pairs
	JOIN users u ON u.id = pairs.user_id AND NOT u.is_admin
	JOIN projects p ON p.id = pairs.project_id
	JOIN teams t ON t.id = p.team_id
	JOIN organizations o ON o.id = t.org_id
	UNION ALL
	-- An instance admin reaches every project, whatever else they hold: one
	-- row with no project — or, when the audit is about one project, that
	-- project's row, listing their grants on it after instance_admin.
	SELECT u.id, u.email, u.kind, u.disabled_at IS NOT NULL,
	       p.id, p.name, t.id, t.name, o.id, o.name, 'admin',
	       jsonb_build_array(jsonb_build_object('kind', 'instance_admin', 'role', 'admin', 'source', u.admin_source,
	           'via_id', NULL, 'via_name', NULL,
	           'sso_mappings', CASE WHEN u.admin_source = 'sso' THEN (
	               SELECT COALESCE(jsonb_agg(m.provider || ':' || m.group_name ORDER BY m.provider, m.group_name), '[]'::jsonb)
	               FROM sso_group_mappings m WHERE m.target_kind = 'instance_admin') ELSE '[]'::jsonb END))
	         || COALESCE(pa.grants, '[]'::jsonb)
	FROM users u
	LEFT JOIN projects p ON p.id = NULLIF($3, '')::uuid
	LEFT JOIN teams t ON t.id = p.team_id
	LEFT JOIN organizations o ON o.id = t.org_id
	LEFT JOIN pairs pa ON pa.user_id = u.id AND pa.project_id = p.id
	WHERE u.is_admin AND ($3 = '' OR p.id IS NOT NULL)
)
SELECT user_id, email, principal_kind, disabled, project_id, project_name, team_id, team_name,
       org_id, org_name, role, grants
FROM rows
WHERE ($1 = '' OR email ILIKE '%' || $1 || '%')
  AND ($2 = '' OR user_id = $2::uuid)
  AND ($3 = '' OR project_id = $3::uuid)
  AND ($4 = '' OR team_id = $4::uuid OR (project_id IS NULL AND role = 'admin'))
  AND ($5 = '' OR org_id = $5::uuid OR (project_id IS NULL AND role = 'admin'))
  AND ($6 = '' OR role = $6)
  AND ($7 = '' OR EXISTS (SELECT 1 FROM jsonb_array_elements(grants) x WHERE x->>'source' = $7))
  AND ($8 = '' OR principal_kind = $8)
ORDER BY email, (project_id IS NOT NULL), org_name, team_name, project_name
LIMIT $9 OFFSET $10`

// List returns the access entries matching f, ordered by principal then
// org/team/project.
func (r *Repository) List(ctx context.Context, f Filter) ([]Entry, error) {
	out := []Entry{}
	err := r.Each(ctx, f, f.Limit, func(e Entry) error {
		out = append(out, e)
		return nil
	})
	return out, err
}

// Each streams the entries matching f (from f.Offset, at most limit), for
// exports.
func (r *Repository) Each(ctx context.Context, f Filter, limit int, fn func(Entry) error) error {
	rows, err := r.db.Query(ctx, accessSQL, strings.TrimSpace(f.User), f.UserID, f.ProjectID, f.TeamID, f.OrgID,
		f.Role, f.Source, f.PrincipalKind, limit, f.Offset)
	if err != nil {
		return fmt.Errorf("permission audit: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var e Entry
		var grants []byte
		if err := rows.Scan(&e.UserID, &e.Email, &e.PrincipalKind, &e.Disabled, &e.ProjectID, &e.ProjectName,
			&e.TeamID, &e.TeamName, &e.OrgID, &e.OrgName, &e.EffectiveRole, &grants); err != nil {
			return fmt.Errorf("scan access entry: %w", err)
		}
		if err := json.Unmarshal(grants, &e.Grants); err != nil {
			return fmt.Errorf("decode grants: %w", err)
		}
		for i := range e.Grants {
			if e.Grants[i].SSOMappings == nil {
				e.Grants[i].SSOMappings = []string{}
			}
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}
