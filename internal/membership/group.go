package membership

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrGroupNotFound is returned when a group does not exist.
var ErrGroupNotFound = errors.New("group not found")

// ErrGroupDuplicate is returned when a group name is already taken in the org.
var ErrGroupDuplicate = errors.New("a group with that name already exists in this organization")

// Group is an admin-managed named group of users, scoped to an organization.
// Granting a role to a group (on the org, a team, or a project) gives every
// current and future member of the group that role — see ProjectGrantsSQL.
type Group struct {
	ID         string    `json:"id"`
	OrgID      string    `json:"org_id"`
	Name       string    `json:"name"`
	ExternalID *string   `json:"external_id,omitempty"` // set when provisioned by SCIM
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	// MemberCount is filled by ListGroups; zero elsewhere.
	MemberCount int `json:"member_count,omitempty"`
}

const groupColumns = `id, org_id, name, scim_external_id, created_at, updated_at`

func scanGroup(row pgx.Row) (Group, error) {
	var g Group
	err := row.Scan(&g.ID, &g.OrgID, &g.Name, &g.ExternalID, &g.CreatedAt, &g.UpdatedAt)
	return g, err
}

// CreateGroup inserts a group. externalID is the SCIM externalId, or "" when
// created through the regular admin API.
func (r *Repository) CreateGroup(ctx context.Context, orgID, name, externalID string) (Group, error) {
	const q = `INSERT INTO user_groups (org_id, name, scim_external_id) VALUES ($1, $2, NULLIF($3, ''))
		RETURNING ` + groupColumns
	g, err := scanGroup(r.db.QueryRow(ctx, q, orgID, name, externalID))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
		return Group{}, ErrGroupDuplicate
	}
	if errors.As(err, &pgErr) && pgErr.Code == "23503" { // FK: org missing
		return Group{}, ErrNoUser
	}
	if err != nil {
		return Group{}, fmt.Errorf("create group: %w", err)
	}
	return g, nil
}

// GetGroup fetches a group by id.
func (r *Repository) GetGroup(ctx context.Context, id string) (Group, error) {
	const q = `SELECT ` + groupColumns + ` FROM user_groups WHERE id = $1`
	g, err := scanGroup(r.db.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Group{}, ErrGroupNotFound
	}
	if err != nil {
		return Group{}, fmt.Errorf("get group: %w", err)
	}
	return g, nil
}

// GetGroupByExternalID fetches a group by its SCIM externalId.
func (r *Repository) GetGroupByExternalID(ctx context.Context, externalID string) (Group, error) {
	const q = `SELECT ` + groupColumns + ` FROM user_groups WHERE scim_external_id = $1`
	g, err := scanGroup(r.db.QueryRow(ctx, q, externalID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Group{}, ErrGroupNotFound
	}
	if err != nil {
		return Group{}, fmt.Errorf("get group by external id: %w", err)
	}
	return g, nil
}

// GetGroupByName fetches a group by its (org-scoped) name, for SCIM's
// `displayName eq "..."` filter.
func (r *Repository) GetGroupByName(ctx context.Context, orgID, name string) (Group, error) {
	const q = `SELECT ` + groupColumns + ` FROM user_groups WHERE org_id = $1 AND name = $2`
	g, err := scanGroup(r.db.QueryRow(ctx, q, orgID, name))
	if errors.Is(err, pgx.ErrNoRows) {
		return Group{}, ErrGroupNotFound
	}
	if err != nil {
		return Group{}, fmt.Errorf("get group by name: %w", err)
	}
	return g, nil
}

// ListGroups returns an org's groups with their member counts, by name.
func (r *Repository) ListGroups(ctx context.Context, orgID string) ([]Group, error) {
	const q = `
		SELECT g.id, g.org_id, g.name, g.scim_external_id, g.created_at, g.updated_at, count(m.user_id)
		  FROM user_groups g LEFT JOIN user_group_members m ON m.group_id = g.id
		 WHERE g.org_id = $1
		 GROUP BY g.id ORDER BY g.name`
	rows, err := r.db.Query(ctx, q, orgID)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		var g Group
		if err := rows.Scan(&g.ID, &g.OrgID, &g.Name, &g.ExternalID, &g.CreatedAt, &g.UpdatedAt, &g.MemberCount); err != nil {
			return nil, fmt.Errorf("scan group: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// RenameGroup updates a group's name (and, when non-empty, its externalId).
func (r *Repository) RenameGroup(ctx context.Context, id, name string) (Group, error) {
	const q = `UPDATE user_groups SET name = $2, updated_at = now() WHERE id = $1 RETURNING ` + groupColumns
	g, err := scanGroup(r.db.QueryRow(ctx, q, id, name))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return Group{}, ErrGroupDuplicate
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return Group{}, ErrGroupNotFound
	}
	if err != nil {
		return Group{}, fmt.Errorf("rename group: %w", err)
	}
	return g, nil
}

// DeleteGroup removes a group. Its grants and memberships cascade.
func (r *Repository) DeleteGroup(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM user_groups WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrGroupNotFound
	}
	return nil
}

// GroupMember is a user's membership in a group.
type GroupMember struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

// AddGroupMember adds a user to a group (idempotent).
func (r *Repository) AddGroupMember(ctx context.Context, groupID, userID string) error {
	const q = `INSERT INTO user_group_members (group_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`
	_, err := r.db.Exec(ctx, q, groupID, userID)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" { // FK: group or user missing
		return ErrNoUser
	}
	if err != nil {
		return fmt.Errorf("add group member: %w", err)
	}
	return nil
}

// RemoveGroupMember drops a user from a group.
func (r *Repository) RemoveGroupMember(ctx context.Context, groupID, userID string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM user_group_members WHERE group_id = $1 AND user_id = $2`, groupID, userID)
	if err != nil {
		return fmt.Errorf("remove group member: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetGroupMembers replaces a group's membership with exactly userIDs (SCIM
// PUT / PATCH replace members).
func (r *Repository) SetGroupMembers(ctx context.Context, groupID string, userIDs []string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin set group members: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if _, err := tx.Exec(ctx, `DELETE FROM user_group_members WHERE group_id = $1`, groupID); err != nil {
		return fmt.Errorf("clear group members: %w", err)
	}
	if len(userIDs) > 0 {
		const ins = `INSERT INTO user_group_members (group_id, user_id) SELECT $1, u FROM unnest($2::uuid[]) AS u`
		if _, err := tx.Exec(ctx, ins, groupID, userIDs); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23503" {
				return ErrNoUser
			}
			return fmt.Errorf("set group members: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit set group members: %w", err)
	}
	return nil
}

// ListGroupMembers returns a group's members.
func (r *Repository) ListGroupMembers(ctx context.Context, groupID string) ([]GroupMember, error) {
	const q = `SELECT m.user_id, u.email FROM user_group_members m JOIN users u ON u.id = m.user_id
		WHERE m.group_id = $1 ORDER BY u.email`
	rows, err := r.db.Query(ctx, q, groupID)
	if err != nil {
		return nil, fmt.Errorf("list group members: %w", err)
	}
	defer rows.Close()
	out := []GroupMember{}
	for rows.Next() {
		var m GroupMember
		if err := rows.Scan(&m.UserID, &m.Email); err != nil {
			return nil, fmt.Errorf("scan group member: %w", err)
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
