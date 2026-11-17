// Package issuetracker links findings to issues in Jira, GitHub Issues or GitLab
// Issues, one tracker per project.
//
// An issue is created on demand (POST /findings/{id}/issue) or automatically for
// findings at or above the tracker's severity threshold. Sync then keeps the two
// sides' open/closed state in step: a finding leaving the backlog closes its
// issue, an issue closed in the tracker marks the finding remediated (the next
// scan reopens it if it is still there, and that reopens the issue). Which side
// moved is decided against the last state both agreed on, so they never fight.
package issuetracker

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/domain"
)

// Sentinel errors.
var (
	ErrNotFound  = errors.New("issue tracker not found")
	ErrNoLink    = errors.New("finding has no linked issue")
	ErrNoProject = errors.New("project not found")
)

// Kind is the tracker product.
type Kind string

// Supported trackers.
const (
	KindJira        Kind = "jira"
	KindGitHub      Kind = "github"
	KindGitLab      Kind = "gitlab"
	KindAzureDevOps Kind = "azure-devops"
	KindLinear      Kind = "linear"
	KindServiceNow  Kind = "servicenow"
)

// Valid reports whether k is a supported tracker.
func (k Kind) Valid() bool {
	return k == KindJira || k == KindGitHub || k == KindGitLab ||
		k == KindAzureDevOps || k == KindLinear || k == KindServiceNow
}

// DefaultBaseURL is the hosted service's URL for a kind. Jira, Azure DevOps
// and ServiceNow have none: every organization/instance is its own site.
func (k Kind) DefaultBaseURL() string {
	switch k {
	case KindGitHub:
		return "https://api.github.com"
	case KindGitLab:
		return "https://gitlab.com"
	case KindLinear:
		return "https://api.linear.app"
	}
	return ""
}

// DefaultTransitions is the close/reopen state value for a kind that doesn't
// ask the user to pick one, keyed to what a fresh project of that kind looks
// like: Jira's and GitHub/GitLab's (unused by them) default workflow; Azure
// Boards' Basic process template; Linear's workflow state *types* (not
// names — see linear.go); ServiceNow's out-of-the-box incident states.
func (k Kind) DefaultTransitions() (done, reopen string) {
	switch k {
	case KindAzureDevOps:
		return "Closed", "Active"
	case KindLinear:
		return "completed", "unstarted"
	case KindServiceNow:
		return "Resolved", "New"
	}
	return "Done", "To Do"
}

// State is an issue's (or, as last synced, a link's) open/closed state.
type State string

// Issue states.
const (
	StateOpen   State = "open"
	StateClosed State = "closed"
)

// Tracker is a project's issue-tracker configuration. The token is never
// serialized; HasToken says one is stored.
type Tracker struct {
	ID               string          `json:"id"`
	ProjectID        string          `json:"project_id"`
	Kind             Kind            `json:"kind"`
	BaseURL          string          `json:"base_url"`
	Target           string          `json:"target"`
	HasToken         bool            `json:"has_token"`
	JiraEmail        string          `json:"jira_email"`
	AuthUser         string          `json:"auth_user"`
	IssueType        string          `json:"issue_type"`
	DoneTransition   string          `json:"done_transition"`
	ReopenTransition string          `json:"reopen_transition"`
	MinSeverity      domain.Severity `json:"min_severity"`
	AutoCreate       bool            `json:"auto_create"`
	Labels           []string        `json:"labels"`
	Enabled          bool            `json:"enabled"`
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`

	tokenEnc []byte
}

// Link ties a finding to its external issue.
type Link struct {
	ID           string    `json:"id"`
	FindingID    string    `json:"finding_id"`
	TrackerID    string    `json:"tracker_id"`
	Kind         Kind      `json:"kind"`
	ExternalID   string    `json:"external_id"`
	URL          string    `json:"url"`
	State        State     `json:"state"`
	LastSyncedAt time.Time `json:"last_synced_at"`
	CreatedAt    time.Time `json:"created_at"`
}

// SyncItem is a link plus its finding's current status, the input to one sync
// decision.
type SyncItem struct {
	Link
	Status domain.FindingStatus
}

// Repository stores tracker configs and finding↔issue links.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

const trackerColumns = `id, project_id, kind, base_url, target, token_enc, jira_email, auth_user, issue_type,
	done_transition, reopen_transition, min_severity, auto_create, labels, enabled, created_at, updated_at`

func scanTracker(row pgx.Row) (Tracker, error) {
	var t Tracker
	err := row.Scan(&t.ID, &t.ProjectID, &t.Kind, &t.BaseURL, &t.Target, &t.tokenEnc, &t.JiraEmail, &t.AuthUser,
		&t.IssueType, &t.DoneTransition, &t.ReopenTransition, &t.MinSeverity, &t.AutoCreate, &t.Labels,
		&t.Enabled, &t.CreatedAt, &t.UpdatedAt)
	t.HasToken = len(t.tokenEnc) > 0
	if t.Labels == nil {
		t.Labels = []string{}
	}
	return t, err
}

// GetByProject returns the project's tracker.
func (r *Repository) GetByProject(ctx context.Context, projectID string) (Tracker, error) {
	t, err := scanTracker(r.db.QueryRow(ctx,
		`SELECT `+trackerColumns+` FROM issue_trackers WHERE project_id = $1`, projectID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Tracker{}, ErrNotFound
	}
	if err != nil {
		return Tracker{}, fmt.Errorf("get issue tracker: %w", err)
	}
	return t, nil
}

// Get returns a tracker by id.
func (r *Repository) Get(ctx context.Context, id string) (Tracker, error) {
	t, err := scanTracker(r.db.QueryRow(ctx,
		`SELECT `+trackerColumns+` FROM issue_trackers WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Tracker{}, ErrNotFound
	}
	if err != nil {
		return Tracker{}, fmt.Errorf("get issue tracker: %w", err)
	}
	return t, nil
}

// ListEnabled returns every enabled tracker.
func (r *Repository) ListEnabled(ctx context.Context) ([]Tracker, error) {
	rows, err := r.db.Query(ctx,
		`SELECT `+trackerColumns+` FROM issue_trackers WHERE enabled ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("list issue trackers: %w", err)
	}
	defer rows.Close()
	out := []Tracker{}
	for rows.Next() {
		t, err := scanTracker(rows)
		if err != nil {
			return nil, fmt.Errorf("scan issue tracker: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Put creates or replaces the project's tracker. A nil tokenEnc keeps the
// stored token. Pointing the tracker at a different system (kind, URL or
// target) drops the existing links: their issue ids belong to the old one.
func (r *Repository) Put(ctx context.Context, t Tracker, tokenEnc []byte) (Tracker, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Tracker{}, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	var prevID, prevKind, prevURL, prevTarget string
	err = tx.QueryRow(ctx,
		`SELECT id, kind, base_url, target FROM issue_trackers WHERE project_id = $1 FOR UPDATE`,
		t.ProjectID).Scan(&prevID, &prevKind, &prevURL, &prevTarget)
	exists := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return Tracker{}, fmt.Errorf("lock issue tracker: %w", err)
	}
	if exists && (prevKind != string(t.Kind) || prevURL != t.BaseURL || prevTarget != t.Target) {
		if _, err := tx.Exec(ctx, `DELETE FROM finding_issues WHERE tracker_id = $1`, prevID); err != nil {
			return Tracker{}, fmt.Errorf("drop stale links: %w", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM remediation_action_issues WHERE tracker_id = $1`, prevID); err != nil {
			return Tracker{}, fmt.Errorf("drop stale action links: %w", err)
		}
	}

	const q = `
		INSERT INTO issue_trackers (project_id, kind, base_url, target, token_enc, jira_email, auth_user, issue_type,
		    done_transition, reopen_transition, min_severity, auto_create, labels, enabled)
		VALUES ($1, $2, $3, $4, COALESCE($5, ''::bytea), $6, $7, $8, $9, $10, $11, $12, $13, $14)
		ON CONFLICT (project_id) DO UPDATE SET
		    kind = EXCLUDED.kind, base_url = EXCLUDED.base_url, target = EXCLUDED.target,
		    token_enc = COALESCE($5, issue_trackers.token_enc),
		    jira_email = EXCLUDED.jira_email, auth_user = EXCLUDED.auth_user, issue_type = EXCLUDED.issue_type,
		    done_transition = EXCLUDED.done_transition, reopen_transition = EXCLUDED.reopen_transition,
		    min_severity = EXCLUDED.min_severity, auto_create = EXCLUDED.auto_create,
		    labels = EXCLUDED.labels, enabled = EXCLUDED.enabled, updated_at = now()
		RETURNING ` + trackerColumns
	out, err := scanTracker(tx.QueryRow(ctx, q, t.ProjectID, t.Kind, t.BaseURL, t.Target, tokenEnc,
		t.JiraEmail, t.AuthUser, t.IssueType, t.DoneTransition, t.ReopenTransition, t.MinSeverity, t.AutoCreate,
		t.Labels, t.Enabled))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return Tracker{}, ErrNoProject
		}
		return Tracker{}, fmt.Errorf("put issue tracker: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Tracker{}, fmt.Errorf("commit: %w", err)
	}
	return out, nil
}

// Delete removes the project's tracker (and, by cascade, its links).
func (r *Repository) Delete(ctx context.Context, projectID string) error {
	if _, err := r.db.Exec(ctx, `DELETE FROM issue_trackers WHERE project_id = $1`, projectID); err != nil {
		return fmt.Errorf("delete issue tracker: %w", err)
	}
	return nil
}

const linkColumns = `fi.id, fi.finding_id, fi.tracker_id, it.kind, fi.external_id, fi.url, fi.state,
	fi.last_synced_at, fi.created_at`

const linkFrom = ` FROM finding_issues fi JOIN issue_trackers it ON it.id = fi.tracker_id`

func scanLinkInto(l *Link, extra ...any) []any {
	return append([]any{&l.ID, &l.FindingID, &l.TrackerID, &l.Kind, &l.ExternalID, &l.URL, &l.State,
		&l.LastSyncedAt, &l.CreatedAt}, extra...)
}

// GetLink returns the finding's linked issue.
func (r *Repository) GetLink(ctx context.Context, findingID string) (Link, error) {
	var l Link
	err := r.db.QueryRow(ctx, `SELECT `+linkColumns+linkFrom+` WHERE fi.finding_id = $1`, findingID).
		Scan(scanLinkInto(&l)...)
	if errors.Is(err, pgx.ErrNoRows) {
		return Link{}, ErrNoLink
	}
	if err != nil {
		return Link{}, fmt.Errorf("get finding issue: %w", err)
	}
	return l, nil
}

// LinkOnce returns the finding's link, calling create to make the external
// issue only if there is none. It holds a per-finding advisory lock for the
// duration, so concurrent callers (a click racing the auto-create sync) never
// open two issues for one finding. created reports whether create ran.
func (r *Repository) LinkOnce(ctx context.Context, findingID, trackerID string,
	create func(context.Context) (externalID, url string, err error),
) (link Link, created bool, err error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Link{}, false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('finding_issue:' || $1::text))`, findingID); err != nil {
		return Link{}, false, fmt.Errorf("lock finding: %w", err)
	}
	err = tx.QueryRow(ctx, `SELECT `+linkColumns+linkFrom+` WHERE fi.finding_id = $1`, findingID).
		Scan(scanLinkInto(&link)...)
	if err == nil {
		return link, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Link{}, false, fmt.Errorf("get finding issue: %w", err)
	}

	extID, url, err := create(ctx)
	if err != nil {
		return Link{}, false, err
	}
	err = tx.QueryRow(ctx, `
		WITH ins AS (
		    INSERT INTO finding_issues (finding_id, tracker_id, external_id, url, state)
		    VALUES ($1, $2, $3, $4, 'open')
		    RETURNING *
		)
		SELECT `+linkColumns+` FROM ins fi JOIN issue_trackers it ON it.id = fi.tracker_id`,
		findingID, trackerID, extID, url).Scan(scanLinkInto(&link)...)
	if err != nil {
		return Link{}, false, fmt.Errorf("insert finding issue: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Link{}, false, fmt.Errorf("commit: %w", err)
	}
	return link, true, nil
}

// ListSyncItems returns every link of a tracker with its finding's status.
func (r *Repository) ListSyncItems(ctx context.Context, trackerID string) ([]SyncItem, error) {
	rows, err := r.db.Query(ctx, `SELECT `+linkColumns+`, f.status`+linkFrom+`
		JOIN findings f ON f.id = fi.finding_id
		WHERE fi.tracker_id = $1 ORDER BY fi.created_at`, trackerID)
	if err != nil {
		return nil, fmt.Errorf("list finding issues: %w", err)
	}
	defer rows.Close()
	out := []SyncItem{}
	for rows.Next() {
		var it SyncItem
		if err := rows.Scan(scanLinkInto(&it.Link, &it.Status)...); err != nil {
			return nil, fmt.Errorf("scan finding issue: %w", err)
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// SetLinkState records the state both sides now agree on.
func (r *Repository) SetLinkState(ctx context.Context, linkID string, s State) error {
	if _, err := r.db.Exec(ctx,
		`UPDATE finding_issues SET state = $2, last_synced_at = now() WHERE id = $1`, linkID, s); err != nil {
		return fmt.Errorf("set finding issue state: %w", err)
	}
	return nil
}

// syncLockKey is the advisory-lock key that serializes sync runs across
// instances (two runs would race each other's transitions).
const syncLockKey = 0x7831_6973_7375 // "x1issu"

// TrySyncLock takes the instance-wide sync lock on a dedicated connection.
// ok=false means another run holds it. release unlocks and returns the
// connection.
func (r *Repository) TrySyncLock(ctx context.Context) (release func(), ok bool, err error) {
	conn, err := r.db.Acquire(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("acquire sync lock conn: %w", err)
	}
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, int64(syncLockKey)).Scan(&ok); err != nil {
		conn.Release()
		return nil, false, fmt.Errorf("sync lock: %w", err)
	}
	if !ok {
		conn.Release()
		return nil, false, nil
	}
	return func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock($1)`, int64(syncLockKey))
		conn.Release()
	}, true, nil
}

// severityRank orders severities in SQL (info=0 … critical=4).
const severityRank = `CASE %s WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END`

// AutoCreateCandidates returns up to limit live, non-duplicate findings of the
// project at or above minSeverity that have no issue yet, most urgent first.
func (r *Repository) AutoCreateCandidates(ctx context.Context, projectID string, min domain.Severity, limit int) ([]string, error) {
	q := `SELECT f.id FROM findings f
		WHERE f.project_id = $1
		  AND f.status IN ('open', 'confirmed')
		  AND f.duplicate_of IS NULL
		  AND` + archive.Finding("f") + `
		  AND ` + fmt.Sprintf(severityRank, "f.severity") + ` >= ` + fmt.Sprintf(severityRank, "$2::text") + `
		  AND NOT EXISTS (SELECT 1 FROM finding_issues fi WHERE fi.finding_id = f.id)
		ORDER BY ` + fmt.Sprintf(severityRank, "f.severity") + ` DESC, f.priority DESC, f.first_seen_at, f.id
		LIMIT $3`
	rows, err := r.db.Query(ctx, q, projectID, string(min), limit)
	if err != nil {
		return nil, fmt.Errorf("list auto-create candidates: %w", err)
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
