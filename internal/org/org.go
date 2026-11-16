// Package org manages organizations — the top-level tenant above teams — and
// org membership. Org admins manage the org and (via membership) all its teams.
package org

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
)

// Domain errors.
var (
	ErrNotFound  = errors.New("organization not found")
	ErrDuplicate = errors.New("organization slug already exists")
	ErrNoUser    = errors.New("user does not exist")
	ErrLastAdmin = errors.New("cannot remove the last admin of an organization")
)

// Organization is a top-level tenant.
type Organization struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Member is a user's membership in an org.
type Member struct {
	UserID string         `json:"user_id,omitempty"`
	Email  string         `json:"email,omitempty"`
	Role   domain.OrgRole `json:"role"`
	// Source is "manual" (granted here) or "sso" (an IdP group mapping, synced
	// on that user's every SSO login).
	Source string `json:"source"`
	// GroupID/GroupName are set instead of UserID/Email when this grant is on
	// a user group rather than an individual user.
	GroupID   string `json:"group_id,omitempty"`
	GroupName string `json:"group_name,omitempty"`
}

// Repository provides access to organizations + org_members.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

const orgColumns = `id, slug, name, created_at, updated_at`

func scanOrg(row pgx.Row) (Organization, error) {
	var o Organization
	err := row.Scan(&o.ID, &o.Slug, &o.Name, &o.CreatedAt, &o.UpdatedAt)
	return o, err
}

// Create inserts an organization.
func (r *Repository) Create(ctx context.Context, slug, name string) (Organization, error) {
	const q = `INSERT INTO organizations (slug, name) VALUES ($1, $2) RETURNING ` + orgColumns
	o, err := scanOrg(r.db.QueryRow(ctx, q, slug, name))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return Organization{}, ErrDuplicate
	}
	if err != nil {
		return Organization{}, fmt.Errorf("insert org: %w", err)
	}
	return o, nil
}

// GetBySlug fetches an organization by slug, returning ErrNotFound when
// absent. Used by idempotent seeders (e.g. internal/demo) that look an org up
// before creating it.
func (r *Repository) GetBySlug(ctx context.Context, slug string) (Organization, error) {
	o, err := scanOrg(r.db.QueryRow(ctx, `SELECT `+orgColumns+` FROM organizations WHERE slug = $1`, slug))
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	if err != nil {
		return Organization{}, fmt.Errorf("get org by slug: %w", err)
	}
	return o, nil
}

// Get fetches an org by id.
func (r *Repository) Get(ctx context.Context, id string) (Organization, error) {
	o, err := scanOrg(r.db.QueryRow(ctx, `SELECT `+orgColumns+` FROM organizations WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	if err != nil {
		return Organization{}, fmt.Errorf("get org: %w", err)
	}
	return o, nil
}

// ListByIDs returns the orgs with the given ids (empty -> none).
func (r *Repository) ListByIDs(ctx context.Context, ids []string) ([]Organization, error) {
	orgs := []Organization{}
	if len(ids) == 0 {
		return orgs, nil
	}
	return r.query(ctx, `SELECT `+orgColumns+` FROM organizations WHERE id = ANY($1) ORDER BY name`, ids)
}

// List returns every org (admin view).
func (r *Repository) List(ctx context.Context) ([]Organization, error) {
	return r.query(ctx, `SELECT `+orgColumns+` FROM organizations ORDER BY name`)
}

func (r *Repository) query(ctx context.Context, q string, args ...any) ([]Organization, error) {
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list orgs: %w", err)
	}
	defer rows.Close()
	orgs := []Organization{}
	for rows.Next() {
		o, err := scanOrg(rows)
		if err != nil {
			return nil, fmt.Errorf("scan org: %w", err)
		}
		orgs = append(orgs, o)
	}
	return orgs, rows.Err()
}

// AddMember inserts or updates a user's org role. A manual grant takes over an
// SSO-synced row for the same org, which the group sync then leaves alone.
func (r *Repository) AddMember(ctx context.Context, orgID, userID string, role domain.OrgRole) error {
	const q = `INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, $3)
		ON CONFLICT (org_id, user_id) WHERE user_id IS NOT NULL
		DO UPDATE SET role = EXCLUDED.role, source = 'manual'`
	_, err := r.db.Exec(ctx, q, orgID, userID, role)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "23514") {
		return ErrNoUser
	}
	if err != nil {
		return fmt.Errorf("add org member: %w", err)
	}
	return nil
}

// AddGroupMember grants a user group a role on an org: every member of the
// group gets that org role.
func (r *Repository) AddGroupMember(ctx context.Context, orgID, groupID string, role domain.OrgRole) error {
	const q = `INSERT INTO org_members (org_id, group_id, role) VALUES ($1, $2, $3)
		ON CONFLICT (org_id, group_id) WHERE group_id IS NOT NULL
		DO UPDATE SET role = EXCLUDED.role, source = 'manual'`
	_, err := r.db.Exec(ctx, q, orgID, groupID, role)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && (pgErr.Code == "23503" || pgErr.Code == "23514") {
		return ErrNoUser
	}
	if err != nil {
		return fmt.Errorf("add org group member: %w", err)
	}
	return nil
}

// RemoveGroupMember drops a group's role on an org, refusing to drop the
// last admin row.
func (r *Repository) RemoveGroupMember(ctx context.Context, orgID, groupID string) error {
	var admins int
	if err := r.db.QueryRow(ctx,
		`SELECT count(*) FROM org_members WHERE org_id = $1 AND role = 'admin'`, orgID).Scan(&admins); err != nil {
		return fmt.Errorf("count org admins: %w", err)
	}
	var role domain.OrgRole
	err := r.db.QueryRow(ctx, `SELECT role FROM org_members WHERE org_id = $1 AND group_id = $2`, orgID, groupID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("get org group member: %w", err)
	}
	if role == domain.OrgAdmin && admins <= 1 {
		return ErrLastAdmin
	}
	if _, err := r.db.Exec(ctx, `DELETE FROM org_members WHERE org_id = $1 AND group_id = $2`, orgID, groupID); err != nil {
		return fmt.Errorf("remove org group member: %w", err)
	}
	return nil
}

// RemoveMember drops a user from an org, refusing to remove the last admin.
func (r *Repository) RemoveMember(ctx context.Context, orgID, userID string) error {
	var admins int
	if err := r.db.QueryRow(ctx,
		`SELECT count(*) FROM org_members WHERE org_id = $1 AND role = 'admin'`, orgID).Scan(&admins); err != nil {
		return fmt.Errorf("count org admins: %w", err)
	}
	var role domain.OrgRole
	err := r.db.QueryRow(ctx, `SELECT role FROM org_members WHERE org_id = $1 AND user_id = $2`, orgID, userID).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("get org member: %w", err)
	}
	if role == domain.OrgAdmin && admins <= 1 {
		return ErrLastAdmin
	}
	if _, err := r.db.Exec(ctx, `DELETE FROM org_members WHERE org_id = $1 AND user_id = $2`, orgID, userID); err != nil {
		return fmt.Errorf("remove org member: %w", err)
	}
	return nil
}

// ListMembers returns an org's members (users and groups) with email/name + role.
func (r *Repository) ListMembers(ctx context.Context, orgID string) ([]Member, error) {
	const q = `
		SELECT m.user_id::text, u.email, ''::text, ''::text, m.role, m.source
		  FROM org_members m JOIN users u ON u.id = m.user_id
		 WHERE m.org_id = $1 AND m.user_id IS NOT NULL
		UNION ALL
		SELECT ''::text, ''::text, m.group_id::text, g.name, m.role, m.source
		  FROM org_members m JOIN user_groups g ON g.id = m.group_id
		 WHERE m.org_id = $1 AND m.group_id IS NOT NULL
		 ORDER BY 5 DESC, 2, 4`
	rows, err := r.db.Query(ctx, q, orgID)
	if err != nil {
		return nil, fmt.Errorf("list org members: %w", err)
	}
	defer rows.Close()
	members := []Member{}
	for rows.Next() {
		var m Member
		if err := rows.Scan(&m.UserID, &m.Email, &m.GroupID, &m.GroupName, &m.Role, &m.Source); err != nil {
			return nil, fmt.Errorf("scan org member: %w", err)
		}
		members = append(members, m)
	}
	return members, rows.Err()
}
