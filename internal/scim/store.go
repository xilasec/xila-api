// Package scim is SCIM 2.0 provisioning (RFC 7643/7644): an identity
// provider creates, updates and deactivates Xila users and the user groups
// of one organization. Each SCIM token belongs to one organization; the
// directory sees and changes only that organization's members and groups.
// Roles stay admin-managed in Xila: SCIM never grants access by itself, a
// group gets its grants from an admin.
package scim

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TokenPrefix marks a SCIM bearer token. It is checked only against
// scim_tokens, never against API tokens (and the reverse), so neither kind
// of credential reaches the other's routes.
const TokenPrefix = "xila_scim_"

// Errors.
var (
	ErrNotFound     = errors.New("not found")
	ErrUniqueness   = errors.New("already exists")
	ErrUnauthorized = errors.New("invalid or revoked SCIM token")
	ErrProtected    = errors.New("the instance owner and service accounts can't be changed through SCIM")
)

// Token is a SCIM client's credential (the secret itself is never stored).
type Token struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	OrgID      string     `json:"org_id"`
	OrgName    string     `json:"org_name"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at"`
	RevokedAt  *time.Time `json:"revoked_at"`
}

// Store is SCIM's persistence: tokens, and org-scoped users and groups.
type Store struct{ db *pgxpool.Pool }

// NewStore constructs a Store.
func NewStore(db *pgxpool.Pool) *Store { return &Store{db: db} }

func hashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

const tokenColumns = `t.id, t.name, t.org_id, o.name, t.created_at, t.last_used_at, t.revoked_at`

func scanToken(row pgx.Row) (Token, error) {
	var t Token
	err := row.Scan(&t.ID, &t.Name, &t.OrgID, &t.OrgName, &t.CreatedAt, &t.LastUsedAt, &t.RevokedAt)
	return t, err
}

// CreateToken mints a token for orgID and returns it with its secret, shown
// once.
func (s *Store) CreateToken(ctx context.Context, name, orgID, createdBy string) (Token, string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return Token{}, "", err
	}
	secret := TokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	t, err := scanToken(s.db.QueryRow(ctx, `
		WITH t AS (INSERT INTO scim_tokens (name, org_id, token_hash, created_by) VALUES ($1, $2, $3, $4) RETURNING *)
		SELECT `+tokenColumns+` FROM t JOIN organizations o ON o.id = t.org_id`, name, orgID, hashSecret(secret), createdBy))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return Token{}, "", ErrNotFound
	}
	if err != nil {
		return Token{}, "", fmt.Errorf("create scim token: %w", err)
	}
	return t, secret, nil
}

// ListTokens lists every token, newest first.
func (s *Store) ListTokens(ctx context.Context) ([]Token, error) {
	rows, err := s.db.Query(ctx, `SELECT `+tokenColumns+` FROM scim_tokens t JOIN organizations o ON o.id = t.org_id
		ORDER BY t.created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list scim tokens: %w", err)
	}
	defer rows.Close()
	out := []Token{}
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeToken revokes a token at once.
func (s *Store) RevokeToken(ctx context.Context, id string) error {
	tag, err := s.db.Exec(ctx, `UPDATE scim_tokens SET revoked_at = COALESCE(revoked_at, now()) WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("revoke scim token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Authenticate resolves a bearer secret to its live token.
func (s *Store) Authenticate(ctx context.Context, secret string) (Token, error) {
	if !strings.HasPrefix(secret, TokenPrefix) {
		return Token{}, ErrUnauthorized
	}
	t, err := scanToken(s.db.QueryRow(ctx, `
		WITH t AS (UPDATE scim_tokens SET last_used_at = now() WHERE token_hash = $1 AND revoked_at IS NULL RETURNING *)
		SELECT `+tokenColumns+` FROM t JOIN organizations o ON o.id = t.org_id`, hashSecret(secret)))
	if errors.Is(err, pgx.ErrNoRows) {
		return Token{}, ErrUnauthorized
	}
	if err != nil {
		return Token{}, fmt.Errorf("authenticate scim token: %w", err)
	}
	return t, nil
}

// User is a Xila user as one organization's directory sees it.
type User struct {
	ID         string
	Email      string
	ExternalID *string
	Active     bool
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Groups     []GroupRef
}

// GroupRef is a group a user is in (or a member of a group).
type GroupRef struct {
	ID      string
	Display string
}

// orgUserFrom selects the org's human members (a direct org_members row).
const orgUserFrom = ` FROM users u
	JOIN org_members om ON om.user_id = u.id AND om.org_id = $1
	WHERE u.kind = 'user'`

const userColumns = `u.id, u.email, u.scim_external_id, u.disabled_at IS NULL, u.created_at, u.updated_at`

func scanUser(row pgx.Row) (User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Email, &u.ExternalID, &u.Active, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

// GetUser returns an org member by id, with its groups.
func (s *Store) GetUser(ctx context.Context, orgID, id string) (User, error) {
	u, err := scanUser(s.db.QueryRow(ctx, `SELECT `+userColumns+orgUserFrom+` AND u.id::text = $2`, orgID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("get scim user: %w", err)
	}
	return u, s.fillGroups(ctx, orgID, []*User{&u})
}

// UserFilter is a parsed `attr eq "value"` on users ("" = none).
type UserFilter struct {
	Attr  string // userName | externalId
	Value string
}

// ListUsers returns a page of the org's members (by email) and the total.
func (s *Store) ListUsers(ctx context.Context, orgID string, f UserFilter, offset, limit int) ([]User, int, error) {
	where, args := "", []any{orgID}
	switch f.Attr {
	case "userName":
		args = append(args, strings.ToLower(f.Value))
		where = ` AND lower(u.email) = $2`
	case "externalId":
		args = append(args, f.Value)
		where = ` AND u.scim_external_id = $2`
	}
	var total int
	if err := s.db.QueryRow(ctx, `SELECT count(*)`+orgUserFrom+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count scim users: %w", err)
	}
	args = append(args, limit, offset)
	rows, err := s.db.Query(ctx, `SELECT `+userColumns+orgUserFrom+where+
		fmt.Sprintf(` ORDER BY u.email LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list scim users: %w", err)
	}
	defer rows.Close()
	out := []User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	ptrs := make([]*User, len(out))
	for i := range out {
		ptrs[i] = &out[i]
	}
	return out, total, s.fillGroups(ctx, orgID, ptrs)
}

func (s *Store) fillGroups(ctx context.Context, orgID string, users []*User) error {
	if len(users) == 0 {
		return nil
	}
	ids := make([]string, len(users))
	byID := map[string]*User{}
	for i, u := range users {
		ids[i] = u.ID
		u.Groups = []GroupRef{}
		byID[u.ID] = u
	}
	rows, err := s.db.Query(ctx, `SELECT m.user_id, g.id, g.name FROM user_group_members m
		JOIN user_groups g ON g.id = m.group_id AND g.org_id = $1
		WHERE m.user_id = ANY($2::uuid[]) ORDER BY g.name`, orgID, ids)
	if err != nil {
		return fmt.Errorf("user groups: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var uid string
		var g GroupRef
		if err := rows.Scan(&uid, &g.ID, &g.Display); err != nil {
			return err
		}
		if u := byID[uid]; u != nil {
			u.Groups = append(u.Groups, g)
		}
	}
	return rows.Err()
}

// CreateUser provisions userName into the org: a new passwordless account
// (it signs in through SSO), or an existing account that isn't yet a member
// of this org. ErrUniqueness when it already is.
func (s *Store) CreateUser(ctx context.Context, orgID, email, externalID string, active bool) (User, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return User{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	var id, kind string
	var owner bool
	err = tx.QueryRow(ctx, `SELECT id, kind, is_owner FROM users WHERE lower(email) = $1 FOR UPDATE`, email).Scan(&id, &kind, &owner)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// A brand-new account. Never the bootstrap owner: provisioning needs
		// a token an admin created, so the instance has users already.
		if err := tx.QueryRow(ctx, `INSERT INTO users (email, scim_external_id) VALUES ($1, NULLIF($2, '')) RETURNING id`,
			email, externalID).Scan(&id); err != nil {
			return User{}, uniqueOr(err, "create scim user")
		}
	case err != nil:
		return User{}, fmt.Errorf("find user: %w", err)
	case kind != "user" || owner:
		return User{}, ErrProtected
	default:
		var member bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM org_members WHERE org_id = $1 AND user_id = $2)`,
			orgID, id).Scan(&member); err != nil {
			return User{}, err
		}
		if member {
			return User{}, ErrUniqueness
		}
		if externalID != "" {
			if _, err := tx.Exec(ctx, `UPDATE users SET scim_external_id = $2, updated_at = now() WHERE id = $1`, id, externalID); err != nil {
				return User{}, uniqueOr(err, "set external id")
			}
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO org_members (org_id, user_id, role) VALUES ($1, $2, 'member')
		ON CONFLICT DO NOTHING`, orgID, id); err != nil {
		return User{}, fmt.Errorf("add org member: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return User{}, err
	}
	if !active {
		if err := s.SetActive(ctx, orgID, id, false); err != nil {
			return User{}, err
		}
	}
	return s.GetUser(ctx, orgID, id)
}

// UpdateUser changes a member's userName (email) and externalId (nil =
// unchanged).
func (s *Store) UpdateUser(ctx context.Context, orgID, id string, email, externalID *string) error {
	if _, err := s.member(ctx, orgID, id); err != nil {
		return err
	}
	if email != nil {
		e := strings.ToLower(strings.TrimSpace(*email))
		if e == "" {
			return fmt.Errorf("%w: userName is required", errInvalid)
		}
		if _, err := s.db.Exec(ctx, `UPDATE users SET email = $2, updated_at = now() WHERE id = $1 AND email <> $2`, id, e); err != nil {
			return uniqueOr(err, "set email")
		}
	}
	if externalID != nil {
		if _, err := s.db.Exec(ctx, `UPDATE users SET scim_external_id = NULLIF($2, ''), updated_at = now() WHERE id = $1`, id, *externalID); err != nil {
			return uniqueOr(err, "set external id")
		}
	}
	return nil
}

// member checks id is a provisionable member of the org.
func (s *Store) member(ctx context.Context, orgID, id string) (User, error) {
	var owner bool
	var kind string
	err := s.db.QueryRow(ctx, `SELECT u.is_owner, u.kind FROM users u JOIN org_members om ON om.user_id = u.id AND om.org_id = $1
		WHERE u.id::text = $2`, orgID, id).Scan(&owner, &kind)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	if owner || kind != "user" {
		return User{}, ErrProtected
	}
	return User{ID: id}, nil
}

// SetActive deactivates or reactivates a member. Deactivating disables the
// account and ends its sessions (token_version), unless the user also
// belongs to another organization: then it only takes them out of this one
// (org membership, its groups, and grants on its teams and projects), so one
// tenant's directory can't lock someone out of another tenant.
func (s *Store) SetActive(ctx context.Context, orgID, id string, active bool) error {
	if _, err := s.member(ctx, orgID, id); err != nil {
		return err
	}
	if active {
		_, err := s.db.Exec(ctx, `UPDATE users SET disabled_at = NULL, updated_at = now() WHERE id = $1 AND NOT is_owner`, id)
		return err
	}
	var otherOrgs bool
	if err := s.db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM org_members WHERE user_id = $1 AND org_id <> $2)`,
		id, orgID).Scan(&otherOrgs); err != nil {
		return err
	}
	if otherOrgs {
		return s.leaveOrg(ctx, orgID, id)
	}
	_, err := s.db.Exec(ctx, `
		UPDATE users SET disabled_at = COALESCE(disabled_at, now()),
		       token_version = token_version + CASE WHEN disabled_at IS NULL THEN 1 ELSE 0 END,
		       updated_at = now()
		WHERE id = $1 AND NOT is_owner`, id)
	if err != nil {
		return fmt.Errorf("deactivate: %w", err)
	}
	_, err = s.db.Exec(ctx, `DELETE FROM password_reset_tokens WHERE user_id = $1`, id)
	return err
}

// Remove handles DELETE: a single-org user is deactivated (their history and
// authored records stay); a multi-org user leaves this org.
func (s *Store) Remove(ctx context.Context, orgID, id string) error {
	return s.SetActive(ctx, orgID, id, false)
}

func (s *Store) leaveOrg(ctx context.Context, orgID, id string) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	for _, q := range []string{
		`DELETE FROM user_group_members m USING user_groups g WHERE m.group_id = g.id AND g.org_id = $1 AND m.user_id = $2`,
		`DELETE FROM project_members pm USING projects p, teams t
			WHERE pm.project_id = p.id AND p.team_id = t.id AND t.org_id = $1 AND pm.user_id = $2`,
		`DELETE FROM team_members tm USING teams t WHERE tm.team_id = t.id AND t.org_id = $1 AND tm.user_id = $2`,
		`DELETE FROM org_members WHERE org_id = $1 AND user_id = $2`,
	} {
		if _, err := tx.Exec(ctx, q, orgID, id); err != nil {
			return fmt.Errorf("leave org: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// Group is one of the org's user groups as SCIM sees it.
type Group struct {
	ID         string
	Name       string
	ExternalID *string
	CreatedAt  time.Time
	UpdatedAt  time.Time
	Members    []GroupRef
}

const groupColumns = `id, name, scim_external_id, created_at, updated_at`

func scanGroup(row pgx.Row) (Group, error) {
	var g Group
	err := row.Scan(&g.ID, &g.Name, &g.ExternalID, &g.CreatedAt, &g.UpdatedAt)
	return g, err
}

// GetGroup returns one of the org's groups with its members.
func (s *Store) GetGroup(ctx context.Context, orgID, id string) (Group, error) {
	g, err := scanGroup(s.db.QueryRow(ctx, `SELECT `+groupColumns+` FROM user_groups WHERE org_id = $1 AND id::text = $2`, orgID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Group{}, ErrNotFound
	}
	if err != nil {
		return Group{}, fmt.Errorf("get scim group: %w", err)
	}
	return g, s.fillMembers(ctx, []*Group{&g})
}

// GroupFilter is a parsed `attr eq "value"` on groups.
type GroupFilter struct {
	Attr  string // displayName | externalId
	Value string
}

// ListGroups returns a page of the org's groups and the total.
func (s *Store) ListGroups(ctx context.Context, orgID string, f GroupFilter, offset, limit int, withMembers bool) ([]Group, int, error) {
	where, args := ` WHERE org_id = $1`, []any{orgID}
	switch f.Attr {
	case "displayName":
		args = append(args, f.Value)
		where += ` AND name = $2`
	case "externalId":
		args = append(args, f.Value)
		where += ` AND scim_external_id = $2`
	}
	var total int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM user_groups`+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count scim groups: %w", err)
	}
	args = append(args, limit, offset)
	rows, err := s.db.Query(ctx, `SELECT `+groupColumns+` FROM user_groups`+where+
		fmt.Sprintf(` ORDER BY name LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list scim groups: %w", err)
	}
	defer rows.Close()
	out := []Group{}
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if !withMembers {
		return out, total, nil
	}
	ptrs := make([]*Group, len(out))
	for i := range out {
		ptrs[i] = &out[i]
	}
	return out, total, s.fillMembers(ctx, ptrs)
}

func (s *Store) fillMembers(ctx context.Context, groups []*Group) error {
	if len(groups) == 0 {
		return nil
	}
	ids := make([]string, len(groups))
	byID := map[string]*Group{}
	for i, g := range groups {
		ids[i] = g.ID
		g.Members = []GroupRef{}
		byID[g.ID] = g
	}
	rows, err := s.db.Query(ctx, `SELECT m.group_id, u.id, u.email FROM user_group_members m JOIN users u ON u.id = m.user_id
		WHERE m.group_id = ANY($1::uuid[]) ORDER BY u.email`, ids)
	if err != nil {
		return fmt.Errorf("group members: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var gid string
		var m GroupRef
		if err := rows.Scan(&gid, &m.ID, &m.Display); err != nil {
			return err
		}
		if g := byID[gid]; g != nil {
			g.Members = append(g.Members, m)
		}
	}
	return rows.Err()
}

// CreateGroup creates one of the org's groups with members (org member ids).
func (s *Store) CreateGroup(ctx context.Context, orgID, name, externalID string, members []string) (Group, error) {
	var id string
	err := s.db.QueryRow(ctx, `INSERT INTO user_groups (org_id, name, scim_external_id) VALUES ($1, $2, NULLIF($3, '')) RETURNING id`,
		orgID, name, externalID).Scan(&id)
	if err != nil {
		return Group{}, uniqueOr(err, "create scim group")
	}
	if err := s.SetMembers(ctx, orgID, id, members); err != nil {
		return Group{}, err
	}
	return s.GetGroup(ctx, orgID, id)
}

// UpdateGroup renames a group and sets its externalId (nil = unchanged).
func (s *Store) UpdateGroup(ctx context.Context, orgID, id string, name, externalID *string) error {
	if _, err := s.GetGroup(ctx, orgID, id); err != nil {
		return err
	}
	if name != nil {
		if strings.TrimSpace(*name) == "" {
			return fmt.Errorf("%w: displayName is required", errInvalid)
		}
		if _, err := s.db.Exec(ctx, `UPDATE user_groups SET name = $2, updated_at = now() WHERE id = $1`, id, *name); err != nil {
			return uniqueOr(err, "rename group")
		}
	}
	if externalID != nil {
		if _, err := s.db.Exec(ctx, `UPDATE user_groups SET scim_external_id = NULLIF($2, ''), updated_at = now() WHERE id = $1`, id, *externalID); err != nil {
			return uniqueOr(err, "set group external id")
		}
	}
	return nil
}

// SetMembers replaces a group's members; AddMembers / RemoveMembers change
// some. Every member must be a member of the org.
func (s *Store) SetMembers(ctx context.Context, orgID, id string, users []string) error {
	return s.changeMembers(ctx, orgID, id, users, true, false)
}

// AddMembers adds org members to a group.
func (s *Store) AddMembers(ctx context.Context, orgID, id string, users []string) error {
	return s.changeMembers(ctx, orgID, id, users, false, false)
}

// RemoveMembers removes users from a group.
func (s *Store) RemoveMembers(ctx context.Context, orgID, id string, users []string) error {
	return s.changeMembers(ctx, orgID, id, users, false, true)
}

func (s *Store) changeMembers(ctx context.Context, orgID, id string, users []string, replace, remove bool) error {
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_groups WHERE id::text = $1 AND org_id = $2)`, id, orgID).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return ErrNotFound
	}
	if users == nil {
		users = []string{}
	}
	if !remove {
		var known int
		if err := tx.QueryRow(ctx, `SELECT count(DISTINCT u.id) FROM users u JOIN org_members om ON om.user_id = u.id AND om.org_id = $1
			WHERE u.id::text = ANY($2)`, orgID, users).Scan(&known); err != nil {
			return err
		}
		if known != len(dedupe(users)) {
			return fmt.Errorf("%w: every member must be a user of this organization", errInvalid)
		}
	}
	switch {
	case replace:
		if _, err := tx.Exec(ctx, `DELETE FROM user_group_members WHERE group_id = $1`, id); err != nil {
			return err
		}
		fallthrough
	case !remove:
		if _, err := tx.Exec(ctx, `INSERT INTO user_group_members (group_id, user_id)
			SELECT $1, u::uuid FROM unnest($2::text[]) u ON CONFLICT DO NOTHING`, id, users); err != nil {
			return fmt.Errorf("add group members: %w", err)
		}
	default:
		if _, err := tx.Exec(ctx, `DELETE FROM user_group_members WHERE group_id = $1 AND user_id::text = ANY($2)`, id, users); err != nil {
			return fmt.Errorf("remove group members: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE user_groups SET updated_at = now() WHERE id = $1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DeleteGroup deletes one of the org's groups (its grants go with it).
func (s *Store) DeleteGroup(ctx context.Context, orgID, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM user_groups WHERE org_id = $1 AND id::text = $2`, orgID, id)
	if err != nil {
		return fmt.Errorf("delete scim group: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

var errInvalid = errors.New("invalid value")

func uniqueOr(err error, what string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrUniqueness
	}
	return fmt.Errorf("%s: %w", what, err)
}

func dedupe(ids []string) []string {
	seen := map[string]bool{}
	out := ids[:0:0]
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
