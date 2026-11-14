// Package audit is the instance audit log: an append-only record of every
// mutating API request and every sign-in event — who (a user, service account
// or API token), what (action, resource, before → after or the redacted request
// body), where from (client IP) and with what result.
//
// Entries are written synchronously after the handler, so one can't be lost to
// a crash between the change and its record, but a failed write never fails the
// user's request: it is logged and counted (xila.audit.write_failures). The
// table rejects UPDATE and DELETE in a trigger; only the retention purge
// (audit_log_purge) may delete, and only rows older than its cutoff.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Actor kinds.
const (
	ActorUser           = "user"
	ActorServiceAccount = "service_account"
	ActorAPIToken       = "api_token"
	ActorSystem         = "system"
	ActorAnonymous      = "anonymous" // a failed sign-in: nobody proved who they are
)

// Outcomes.
const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
)

// Entry is one audit record.
type Entry struct {
	ID           int64           `json:"id"`
	CreatedAt    time.Time       `json:"created_at"`
	ActorKind    string          `json:"actor_kind"`
	ActorUserID  *string         `json:"actor_user_id"`
	ActorTokenID *string         `json:"actor_token_id"`
	ActorEmail   string          `json:"actor_email"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	ProjectID    *string         `json:"project_id"`
	TeamID       *string         `json:"team_id"`
	OrgID        *string         `json:"org_id"`
	Method       string          `json:"method"`
	Path         string          `json:"path"`
	ClientIP     string          `json:"client_ip"`
	Status       int             `json:"status"`
	Outcome      string          `json:"outcome"`
	RequestID    string          `json:"request_id"`
	Changes      json.RawMessage `json:"changes"`
}

// Filter narrows a listing. Empty fields don't filter.
type Filter struct {
	ActorID      string    // exact actor_user_id
	Actor        string    // substring of the actor's email
	ActorKind    string    // exact
	Action       string    // exact action, or a dotted prefix ("users" matches "users.create")
	ResourceType string    // exact
	ResourceID   string    // exact
	ProjectID    string    // exact
	Outcome      string    // success | failure
	From         time.Time // created_at >= From
	To           time.Time // created_at < To
}

// Repository is the audit_log store.
type Repository struct{ db *pgxpool.Pool }

// NewRepository constructs the store.
func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

const entryColumns = `id, created_at, actor_kind, actor_user_id::text, actor_token_id::text, actor_email,
	action, resource_type, resource_id, project_id::text, team_id::text, org_id::text,
	method, path, client_ip, status, outcome, request_id, changes`

func scanEntry(row pgx.Row) (Entry, error) {
	var e Entry
	err := row.Scan(&e.ID, &e.CreatedAt, &e.ActorKind, &e.ActorUserID, &e.ActorTokenID, &e.ActorEmail,
		&e.Action, &e.ResourceType, &e.ResourceID, &e.ProjectID, &e.TeamID, &e.OrgID,
		&e.Method, &e.Path, &e.ClientIP, &e.Status, &e.Outcome, &e.RequestID, &e.Changes)
	return e, err
}

// Insert appends one entry. An empty ActorEmail is filled from the actor's
// user row, so the log stays readable after the user is deleted.
func (r *Repository) Insert(ctx context.Context, e Entry) error {
	changes := e.Changes
	if len(changes) == 0 {
		changes = json.RawMessage(`{}`)
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO audit_log (actor_kind, actor_user_id, actor_token_id, actor_email, action,
			resource_type, resource_id, project_id, team_id, org_id, method, path, client_ip,
			status, outcome, request_id, changes)
		VALUES ($1, $2, $3,
			COALESCE(NULLIF($4, ''), (SELECT email FROM users WHERE id = $2), ''),
			$5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)`,
		e.ActorKind, e.ActorUserID, e.ActorTokenID, e.ActorEmail, e.Action,
		e.ResourceType, e.ResourceID, e.ProjectID, e.TeamID, e.OrgID, e.Method, e.Path, e.ClientIP,
		e.Status, e.Outcome, e.RequestID, changes)
	if err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}
	return nil
}

// ScopeOf resolves the team and org a project (or the org a team) belongs to,
// before the handler runs — a DELETE leaves nothing to resolve afterwards.
// Unknown ids resolve to nothing.
func (r *Repository) ScopeOf(ctx context.Context, projectID, teamID string) (team, org string, err error) {
	switch {
	case projectID != "":
		err = r.db.QueryRow(ctx, `
			SELECT p.team_id::text, t.org_id::text FROM projects p JOIN teams t ON t.id = p.team_id
			WHERE p.id = $1`, projectID).Scan(&team, &org)
	case teamID != "":
		err = r.db.QueryRow(ctx, `SELECT org_id::text FROM teams WHERE id = $1`, teamID).Scan(&org)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil
	}
	return team, org, err
}

// where renders a filter as SQL conditions over positional args.
func (f Filter) where() (string, []any) {
	var conds []string
	var args []any
	add := func(cond string, v any) {
		args = append(args, v)
		conds = append(conds, strings.ReplaceAll(cond, "$?", fmt.Sprintf("$%d", len(args))))
	}
	if f.ActorID != "" {
		add("actor_user_id::text = $?", f.ActorID)
	}
	if f.Actor != "" {
		add("actor_email ILIKE '%' || $? || '%'", escapeLike(f.Actor))
	}
	if f.ActorKind != "" {
		add("actor_kind = $?", f.ActorKind)
	}
	if f.Action != "" {
		args = append(args, f.Action, escapeLike(f.Action)+".%")
		conds = append(conds, fmt.Sprintf("(action = $%d OR action LIKE $%d)", len(args)-1, len(args)))
	}
	if f.ResourceType != "" {
		add("resource_type = $?", f.ResourceType)
	}
	if f.ResourceID != "" {
		add("resource_id = $?", f.ResourceID)
	}
	if f.ProjectID != "" {
		add("project_id::text = $?", f.ProjectID)
	}
	if f.Outcome != "" {
		add("outcome = $?", f.Outcome)
	}
	if !f.From.IsZero() {
		add("created_at >= $?", f.From)
	}
	if !f.To.IsZero() {
		add("created_at < $?", f.To)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conds, " AND "), args
}

// escapeLike makes s match literally inside a LIKE pattern.
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// List returns entries newest first.
func (r *Repository) List(ctx context.Context, f Filter, limit, offset int) ([]Entry, error) {
	where, args := f.where()
	args = append(args, limit, offset)
	rows, err := r.db.Query(ctx, `SELECT `+entryColumns+` FROM audit_log`+where+
		fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT $%d OFFSET $%d`, len(args)-1, len(args)), args...)
	if err != nil {
		return nil, fmt.Errorf("list audit log: %w", err)
	}
	defer rows.Close()
	out := []Entry{}
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Each streams up to limit entries matching f (newest first) into fn — the
// export's cursor, sharing List's filter so an export never shows a row the
// listing hides.
func (r *Repository) Each(ctx context.Context, f Filter, limit int, fn func(Entry) error) error {
	where, args := f.where()
	args = append(args, limit)
	rows, err := r.db.Query(ctx, `SELECT `+entryColumns+` FROM audit_log`+where+
		fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT $%d`, len(args)), args...)
	if err != nil {
		return fmt.Errorf("export audit log: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		e, err := scanEntry(rows)
		if err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
	return rows.Err()
}
