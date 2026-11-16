package membership

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/xilasec/xila-api/internal/domain"
)

// ErrRoleNotFound is returned when a custom role does not exist.
var ErrRoleNotFound = errors.New("custom role not found")

// ErrRoleDuplicate is returned when a custom role name is already taken in the org.
var ErrRoleDuplicate = errors.New("a role with that name already exists in this organization")

// ErrRoleInUse is returned when deleting a custom role that is still assigned.
var ErrRoleInUse = errors.New("this role is still assigned to a team or project member")

// CustomRole is an admin-defined role = a base role (viewer/uploader/editor/
// owner) minus a set of denied capabilities. Assignable wherever a base role
// is granted on a team or project (its rank for authorization purposes is
// always BaseRole — see internal/authz).
type CustomRole struct {
	ID                 string              `json:"id"`
	OrgID              string              `json:"org_id"`
	Name               string              `json:"name"`
	BaseRole           domain.TeamRole     `json:"base_role"`
	DeniedCapabilities []domain.Capability `json:"denied_capabilities"`
	CreatedAt          time.Time           `json:"created_at"`
	UpdatedAt          time.Time           `json:"updated_at"`
}

const customRoleColumns = `id, org_id, name, base_role, denied_capabilities, created_at, updated_at`

func scanCustomRole(row pgx.Row) (CustomRole, error) {
	var role CustomRole
	var denied []string
	err := row.Scan(&role.ID, &role.OrgID, &role.Name, &role.BaseRole, &denied, &role.CreatedAt, &role.UpdatedAt)
	for _, d := range denied {
		role.DeniedCapabilities = append(role.DeniedCapabilities, domain.Capability(d))
	}
	return role, err
}

// CreateCustomRole inserts a custom role. baseRole and every entry of denied
// must already be validated (Valid()) by the caller.
func (r *Repository) CreateCustomRole(ctx context.Context, orgID, name string, baseRole domain.TeamRole, denied []domain.Capability) (CustomRole, error) {
	const q = `INSERT INTO custom_roles (org_id, name, base_role, denied_capabilities) VALUES ($1, $2, $3, $4)
		RETURNING ` + customRoleColumns
	role, err := scanCustomRole(r.db.QueryRow(ctx, q, orgID, name, baseRole, capStrings(denied)))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return CustomRole{}, ErrRoleDuplicate
	}
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return CustomRole{}, ErrNoUser
	}
	if err != nil {
		return CustomRole{}, fmt.Errorf("create custom role: %w", err)
	}
	return role, nil
}

// GetCustomRole fetches a custom role by id.
func (r *Repository) GetCustomRole(ctx context.Context, id string) (CustomRole, error) {
	const q = `SELECT ` + customRoleColumns + ` FROM custom_roles WHERE id = $1`
	role, err := scanCustomRole(r.db.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return CustomRole{}, ErrRoleNotFound
	}
	if err != nil {
		return CustomRole{}, fmt.Errorf("get custom role: %w", err)
	}
	return role, nil
}

// ListCustomRoles returns an org's custom roles, by name.
func (r *Repository) ListCustomRoles(ctx context.Context, orgID string) ([]CustomRole, error) {
	const q = `SELECT ` + customRoleColumns + ` FROM custom_roles WHERE org_id = $1 ORDER BY name`
	rows, err := r.db.Query(ctx, q, orgID)
	if err != nil {
		return nil, fmt.Errorf("list custom roles: %w", err)
	}
	defer rows.Close()
	out := []CustomRole{}
	for rows.Next() {
		role, err := scanCustomRole(rows)
		if err != nil {
			return nil, fmt.Errorf("scan custom role: %w", err)
		}
		out = append(out, role)
	}
	return out, rows.Err()
}

// UpdateCustomRole replaces a custom role's name, base role and denied
// capabilities. Existing grants using it keep the custom_role_id but adopt
// the new base_role/denied set immediately (the role, not a copy, is what's
// referenced) — except the base role column stored on each grant row, which
// callers must re-sync: see Handler.Update.
func (r *Repository) UpdateCustomRole(ctx context.Context, id, name string, baseRole domain.TeamRole, denied []domain.Capability) (CustomRole, error) {
	const q = `UPDATE custom_roles SET name = $2, base_role = $3, denied_capabilities = $4, updated_at = now()
		WHERE id = $1 RETURNING ` + customRoleColumns
	role, err := scanCustomRole(r.db.QueryRow(ctx, q, id, name, baseRole, capStrings(denied)))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return CustomRole{}, ErrRoleDuplicate
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return CustomRole{}, ErrRoleNotFound
	}
	if err != nil {
		return CustomRole{}, fmt.Errorf("update custom role: %w", err)
	}
	// Grants keep role = base_role in step with the custom role they
	// reference, so the ladder rank (which reads that column directly, never
	// joining custom_roles) doesn't drift from a role's own base.
	if _, err := r.db.Exec(ctx, `UPDATE team_members SET role = $2 WHERE custom_role_id = $1`, id, baseRole); err != nil {
		return CustomRole{}, fmt.Errorf("resync team grants: %w", err)
	}
	if _, err := r.db.Exec(ctx, `UPDATE project_members SET role = $2 WHERE custom_role_id = $1`, id, baseRole); err != nil {
		return CustomRole{}, fmt.Errorf("resync project grants: %w", err)
	}
	return role, nil
}

// DeleteCustomRole removes a custom role, refusing while it is still
// assigned (the grant would silently fall back to an unrestricted base role).
func (r *Repository) DeleteCustomRole(ctx context.Context, id string) error {
	var inUse bool
	const check = `SELECT EXISTS (SELECT 1 FROM team_members WHERE custom_role_id = $1
		UNION ALL SELECT 1 FROM project_members WHERE custom_role_id = $1)`
	if err := r.db.QueryRow(ctx, check, id).Scan(&inUse); err != nil {
		return fmt.Errorf("check custom role in use: %w", err)
	}
	if inUse {
		return ErrRoleInUse
	}
	tag, err := r.db.Exec(ctx, `DELETE FROM custom_roles WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete custom role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrRoleNotFound
	}
	return nil
}

func capStrings(caps []domain.Capability) []string {
	out := make([]string, len(caps))
	for i, c := range caps {
		out[i] = string(c)
	}
	return out
}
