// Package sso is the protocol-neutral half of Single Sign-On: it turns a
// verified login from any identity provider (OIDC, SAML) into a Xila user —
// linking or provisioning the account — re-syncs the roles that user gets from
// IdP groups, and mints the session. The protocol packages (internal/oidc,
// internal/saml) only verify what the IdP asserted and hand an Assertion here.
package sso

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
)

// Domain errors.
var (
	ErrNotFound       = errors.New("group mapping not found")
	ErrDuplicate      = errors.New("this group is already mapped to that target")
	ErrTargetNotFound = errors.New("the mapping target does not exist")
	ErrInvalid        = errors.New("invalid group mapping")
)

// Provider kinds, as stored on identities, providers and mappings.
const (
	ProviderOIDC = "oidc"
	ProviderSAML = "saml"
	// ProviderLDAP is the LDAP / Active Directory directory (LDAP_*): one per
	// instance, signed in through the password form. Its mappings use the kind
	// scope (provider "ldap", no provider_id).
	ProviderLDAP = "ldap"
	ProviderAny  = "any" // a mapping that applies to logins through every provider
)

// TargetKind is what a group mapping grants.
type TargetKind string

const (
	TargetInstanceAdmin TargetKind = "instance_admin"
	TargetOrg           TargetKind = "org"
	TargetTeam          TargetKind = "team"
	TargetProject       TargetKind = "project"
)

// GroupMapping grants members of an IdP group a role. Group names match the
// IdP's values exactly (case-sensitive): a Keycloak group path ("/xila-admins"),
// an Okta group name, an Entra ID group object id.
//
// Scope: Provider is the kind scope — "any", or every provider of one kind
// (environment and database alike). ProviderID narrows it to one provider: a
// database provider's uuid (the mapping is deleted with it), or "oidc"/"saml"
// for the one configured by environment. Group names only mean something
// within one IdP, so with several providers of a kind, scope mappings to one.
type GroupMapping struct {
	ID           string     `json:"id"`
	Provider     string     `json:"provider"`                // oidc | saml | any
	ProviderID   string     `json:"provider_id,omitempty"`   // one provider; empty = the whole kind scope
	ProviderName string     `json:"provider_name,omitempty"` // read-only
	Group        string     `json:"group"`
	TargetKind   TargetKind `json:"target_kind"`
	TargetID     string     `json:"target_id,omitempty"` // org/team/project id; empty for instance_admin
	TargetName   string     `json:"target_name,omitempty"`
	// Role: org → admin|member; team/project → owner|editor|viewer; empty for
	// instance_admin.
	Role      string    `json:"role,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// isEnvID reports whether a provider id names an environment provider.
func isEnvID(id string) bool { return id == ProviderOIDC || id == ProviderSAML }

// Validate normalizes and checks a mapping before it is stored. A ProviderID
// must already have been resolved, with Provider set to its kind.
func (m *GroupMapping) Validate() error {
	m.Group = strings.TrimSpace(m.Group)
	if m.Provider == "" {
		m.Provider = ProviderAny
	}
	switch m.Provider {
	case ProviderOIDC, ProviderSAML, ProviderLDAP:
	case ProviderAny:
		if m.ProviderID != "" {
			return fmt.Errorf("%w: a mapping for one provider takes that provider's kind", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: provider must be oidc, saml, ldap or any", ErrInvalid)
	}
	if m.ProviderID != "" && !isEnvID(m.ProviderID) {
		if _, err := uuid.Parse(m.ProviderID); err != nil {
			return fmt.Errorf("%w: provider_id must be a provider id", ErrInvalid)
		}
	}
	if m.ProviderID != "" && isEnvID(m.ProviderID) && m.ProviderID != m.Provider {
		return fmt.Errorf("%w: provider_id and provider disagree on the kind", ErrInvalid)
	}
	if m.Group == "" {
		return fmt.Errorf("%w: group is required", ErrInvalid)
	}
	switch m.TargetKind {
	case TargetInstanceAdmin:
		if m.TargetID != "" || m.Role != "" {
			return fmt.Errorf("%w: instance_admin takes no target_id or role", ErrInvalid)
		}
		return nil
	case TargetOrg:
		if !domain.OrgRole(m.Role).Valid() {
			return fmt.Errorf("%w: org role must be admin or member", ErrInvalid)
		}
	case TargetTeam, TargetProject:
		if !domain.TeamRole(m.Role).Valid() {
			return fmt.Errorf("%w: role must be owner, editor, viewer or uploader", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: target_kind must be instance_admin, org, team or project", ErrInvalid)
	}
	if _, err := uuid.Parse(m.TargetID); err != nil {
		return fmt.Errorf("%w: target_id must be a uuid", ErrInvalid)
	}
	return nil
}

// Repository stores group mappings and applies them to a user's grants.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

const mappingSelect = `
	SELECT m.id, m.provider, m.provider_id::text, m.env_provider, COALESCE(sp.name, ''), m.group_name, m.target_kind,
	       COALESCE(m.org_id, m.team_id, m.project_id)::text,
	       COALESCE(o.name, t.name, p.name, ''), m.role, m.created_at
	FROM sso_group_mappings m
	LEFT JOIN sso_providers sp ON sp.id = m.provider_id
	LEFT JOIN organizations o ON o.id = m.org_id
	LEFT JOIN teams t ON t.id = m.team_id
	LEFT JOIN projects p ON p.id = m.project_id`

func scanMapping(row pgx.Row) (GroupMapping, error) {
	var m GroupMapping
	var target, providerID *string
	var env bool
	err := row.Scan(&m.ID, &m.Provider, &providerID, &env, &m.ProviderName, &m.Group, &m.TargetKind, &target,
		&m.TargetName, &m.Role, &m.CreatedAt)
	if target != nil {
		m.TargetID = *target
	}
	switch {
	case providerID != nil:
		m.ProviderID = *providerID
	case env:
		m.ProviderID = m.Provider // the environment provider's id is its kind
	}
	return m, err
}

// List returns every mapping, grouped by IdP group.
func (r *Repository) List(ctx context.Context) ([]GroupMapping, error) {
	rows, err := r.db.Query(ctx, mappingSelect+` ORDER BY m.group_name, m.provider, m.target_kind, m.created_at`)
	if err != nil {
		return nil, fmt.Errorf("list group mappings: %w", err)
	}
	defer rows.Close()
	out := []GroupMapping{}
	for rows.Next() {
		m, err := scanMapping(rows)
		if err != nil {
			return nil, fmt.Errorf("scan group mapping: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// Create stores a validated mapping.
func (r *Repository) Create(ctx context.Context, m GroupMapping) (GroupMapping, error) {
	var orgID, teamID, projectID *string
	switch m.TargetKind {
	case TargetOrg:
		orgID = &m.TargetID
	case TargetTeam:
		teamID = &m.TargetID
	case TargetProject:
		projectID = &m.TargetID
	}
	var providerID *string
	env := m.ProviderID != "" && isEnvID(m.ProviderID)
	if m.ProviderID != "" && !env {
		providerID = &m.ProviderID
	}
	var id string
	err := r.db.QueryRow(ctx, `INSERT INTO sso_group_mappings
		(provider, provider_id, env_provider, group_name, target_kind, org_id, team_id, project_id, role)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
		m.Provider, providerID, env, m.Group, m.TargetKind, orgID, teamID, projectID, m.Role).Scan(&id)
	if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok {
		switch {
		case pgErr.Code == "23505":
			return GroupMapping{}, ErrDuplicate
		case pgErr.Code == "23503" && pgErr.ConstraintName == "sso_group_mappings_provider_fk":
			return GroupMapping{}, ErrProviderNotFound
		case pgErr.Code == "23503":
			return GroupMapping{}, ErrTargetNotFound
		}
	}
	if err != nil {
		return GroupMapping{}, fmt.Errorf("create group mapping: %w", err)
	}
	return scanMapping(r.db.QueryRow(ctx, mappingSelect+` WHERE m.id = $1`, id))
}

// Delete removes a mapping. The grants it made are revoked at each affected
// user's next SSO login.
func (r *Repository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM sso_group_mappings WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete group mapping: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// desiredGrants is what a user's groups entitle them to: the highest role per
// target when several groups map to the same one.
type desiredGrants struct {
	admin    bool
	orgs     map[string]domain.OrgRole
	teams    map[string]domain.TeamRole
	projects map[string]domain.TeamRole
}

// desired matches the user's groups against the mappings in scope for a login
// through p: any-provider ones, the ones for p's whole kind, and the ones for
// exactly p.
func (r *Repository) desired(ctx context.Context, p Provider, groups []string) (desiredGrants, error) {
	d := desiredGrants{
		orgs: map[string]domain.OrgRole{}, teams: map[string]domain.TeamRole{}, projects: map[string]domain.TeamRole{},
	}
	if len(groups) == 0 {
		return d, nil
	}
	rows, err := r.db.Query(ctx, `
		SELECT target_kind, COALESCE(org_id, team_id, project_id)::text, role
		FROM sso_group_mappings
		WHERE provider IN ($1, 'any') AND group_name = ANY($2)
		  AND ((provider_id IS NULL AND NOT env_provider) OR provider_id = $3 OR (env_provider AND $4))`,
		p.Kind, groups, p.databaseID(), p.Env())
	if err != nil {
		return d, fmt.Errorf("match group mappings: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var kind TargetKind
		var target *string
		var role string
		if err := rows.Scan(&kind, &target, &role); err != nil {
			return d, fmt.Errorf("scan group mapping: %w", err)
		}
		switch kind {
		case TargetInstanceAdmin:
			d.admin = true
		case TargetOrg:
			if cur, ok := d.orgs[*target]; !ok || cur != domain.OrgAdmin {
				d.orgs[*target] = domain.OrgRole(role)
			}
		case TargetTeam:
			d.teams[*target], _ = domain.MaxTeamRole(d.teams[*target], domain.TeamRole(role))
		case TargetProject:
			d.projects[*target], _ = domain.MaxTeamRole(d.projects[*target], domain.TeamRole(role))
		}
	}
	return d, rows.Err()
}

// grantTables are the membership tables the sync manages, keyed by target
// column. Names are constants, never request input.
var grantTables = []struct{ table, target string }{
	{"org_members", "org_id"},
	{"team_members", "team_id"},
	{"project_members", "project_id"},
}

// SyncGrants makes the user's SSO-managed grants match what their IdP groups
// map to right now, in one transaction:
//
//   - rows with source 'sso' are inserted, re-roled or deleted to match;
//   - a 'manual' row for the same target is never touched (the effective role is
//     already the highest grant, so the manual one keeps counting);
//   - instance admin is granted with admin_source 'sso' and revoked only if it
//     came from SSO — and the owner is never demoted.
//
// No groups (or a missing groups claim) means no SSO grants: the sync fails
// closed.
func (r *Repository) SyncGrants(ctx context.Context, userID string, p Provider, groups []string) error {
	d, err := r.desired(ctx, p, groups)
	if err != nil {
		return err
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin grant sync: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	if d.admin {
		_, err = tx.Exec(ctx, `UPDATE users SET is_admin = true, admin_source = 'sso', updated_at = now()
			WHERE id = $1 AND NOT is_admin`, userID)
	} else {
		_, err = tx.Exec(ctx, `UPDATE users SET is_admin = false, admin_source = 'manual', updated_at = now()
			WHERE id = $1 AND is_admin AND admin_source = 'sso' AND NOT is_owner`, userID)
	}
	if err != nil {
		return fmt.Errorf("sync admin: %w", err)
	}

	for _, g := range grantTables {
		var ids, roles []string
		switch g.table {
		case "org_members":
			for id, role := range d.orgs {
				ids, roles = append(ids, id), append(roles, string(role))
			}
		case "team_members":
			for id, role := range d.teams {
				ids, roles = append(ids, id), append(roles, string(role))
			}
		case "project_members":
			for id, role := range d.projects {
				ids, roles = append(ids, id), append(roles, string(role))
			}
		}
		if ids == nil {
			ids, roles = []string{}, []string{}
		}
		// Only rows this sync owns change, and only when they differ.
		upsert := fmt.Sprintf(`
			INSERT INTO %[1]s (%[2]s, user_id, role, source)
			SELECT t.id, $1, t.role, 'sso' FROM unnest($2::uuid[], $3::text[]) AS t(id, role)
			ON CONFLICT (%[2]s, user_id) WHERE user_id IS NOT NULL DO UPDATE SET role = EXCLUDED.role
			WHERE %[1]s.source = 'sso' AND %[1]s.role IS DISTINCT FROM EXCLUDED.role`, g.table, g.target)
		if _, err := tx.Exec(ctx, upsert, userID, ids, roles); err != nil {
			return fmt.Errorf("sync %s: %w", g.table, err)
		}
		revoke := fmt.Sprintf(`DELETE FROM %s WHERE user_id = $1 AND source = 'sso' AND NOT (%s = ANY($2::uuid[]))`,
			g.table, g.target)
		if _, err := tx.Exec(ctx, revoke, userID, ids); err != nil {
			return fmt.Errorf("revoke %s: %w", g.table, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit grant sync: %w", err)
	}
	return nil
}
