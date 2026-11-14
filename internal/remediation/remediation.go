// Package remediation tracks remediation work items: a project's open findings
// grouped by the one change that fixes them (a package upgrade, a base-image
// rebuild, an IaC rule on a file, a source file, a configuration change), each
// with an owner, a due date, a status and the findings it closes.
//
// The grouping is fixplan.Changes — the same code the fix plan endpoints
// read. A leader-elected sweep and a post-ingest pass propose changes for live
// findings not yet in an action; new findings of an existing action's change
// join it; with REMEDIATION_AUTO_CREATE every proposal becomes an action.
// An action closes itself once all its findings are remediated or false
// positives; its due date is its findings' earliest SLA deadline and its owner
// their assignee. One action can be filed as one issue-tracker ticket, synced
// both ways with the project's tracker.
package remediation

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
	"github.com/xilasec/xila-api/internal/fixplan"
	"github.com/xilasec/xila-api/internal/issuetracker"
)

// Sentinel errors.
var (
	ErrNotFound   = errors.New("remediation action not found")
	ErrNoProposal = errors.New("no proposed change with that kind and key")
	// ErrConflict: reopening would make a second live action for one change.
	ErrConflict = errors.New("another open action already tracks this change")
)

// Status is an action's state.
type Status string

// Action statuses.
const (
	StatusOpen       Status = "open"
	StatusInProgress Status = "in_progress"
	StatusDone       Status = "done"
	StatusWontDo     Status = "wont_do"
)

// Valid reports whether s is a known status.
func (s Status) Valid() bool {
	return s == StatusOpen || s == StatusInProgress || s == StatusDone || s == StatusWontDo
}

// Live reports whether the action is still being worked (open / in progress).
func (s Status) Live() bool { return s == StatusOpen || s == StatusInProgress }

// Close reasons.
const (
	ReasonFindingsResolved = "findings_resolved" // every finding remediated or a false positive
	ReasonManual           = "manual"            // a user closed it
	ReasonIssueClosed      = "issue_closed"      // its ticket was closed in the tracker
)

// liveStatuses is the SQL list of live statuses.
const liveStatuses = `('open', 'in_progress')`

// IssueLink is an action's ticket in the project's issue tracker.
type IssueLink struct {
	ID           string             `json:"id"`
	ActionID     string             `json:"action_id"`
	TrackerID    string             `json:"tracker_id"`
	Kind         issuetracker.Kind  `json:"kind"`
	ExternalID   string             `json:"external_id"`
	URL          string             `json:"url"`
	State        issuetracker.State `json:"state"`
	LastSyncedAt time.Time          `json:"last_synced_at"`
	CreatedAt    time.Time          `json:"created_at"`
}

// Action is one remediation work item.
type Action struct {
	ID          string       `json:"id"`
	ProjectID   string       `json:"project_id"`
	ProjectName string       `json:"project_name"`
	Kind        fixplan.Kind `json:"kind"`
	Key         string       `json:"key"`
	Title       string       `json:"title"`
	Target      string       `json:"target"`
	OwnerID     *string      `json:"owner_id"`
	OwnerEmail  *string      `json:"owner_email"`
	// OwnerManual: the owner was set by hand and no longer follows the
	// findings' assignees.
	OwnerManual    bool       `json:"owner_manual"`
	DueAt          *time.Time `json:"due_at"`
	Overdue        bool       `json:"overdue"`
	Status         Status     `json:"status"`
	CreatedBy      *string    `json:"created_by"`
	CreatedByEmail *string    `json:"created_by_email"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
	ClosedAt       *time.Time `json:"closed_at"`
	ClosedBy       *string    `json:"closed_by"`
	ClosedByEmail  *string    `json:"closed_by_email"`
	CloseReason    string     `json:"close_reason"`
	// Findings is every finding the action covers; OpenFindings the ones still
	// open or confirmed (duplicates of another finding not counted), and the
	// rest of the figures are over those.
	Findings     int             `json:"findings"`
	OpenFindings int             `json:"open_findings"`
	MaxSeverity  domain.Severity `json:"max_severity"`
	Priority     float64         `json:"priority"`
	KEV          int             `json:"kev"`
	Issue        *IssueLink      `json:"issue"`
}

// ActionFinding is a finding as an action lists it.
type ActionFinding struct {
	ID             string               `json:"id"`
	Title          string               `json:"title"`
	Severity       domain.Severity      `json:"severity"`
	Status         domain.FindingStatus `json:"status"`
	Scanner        string               `json:"scanner"`
	RuleID         string               `json:"rule_id"`
	CVE            []string             `json:"cve"`
	PackageName    string               `json:"package_name"`
	PackageVersion string               `json:"package_version"`
	FixedVersion   string               `json:"fixed_version"`
	FilePath       string               `json:"file_path"`
	Line           *int                 `json:"line"`
	Priority       float64              `json:"priority"`
	KEV            bool                 `json:"kev"`
	SLADueAt       *time.Time           `json:"sla_due_at"`
	AssigneeEmail  *string              `json:"assignee_email"`
	DuplicateOf    *string              `json:"duplicate_of"`
	AddedAt        time.Time            `json:"added_at"`
}

// Repository stores actions, their findings and their tickets.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

// severityRank orders severities (info=0 … critical=4); severityByRank maps back.
const severityRank = `CASE f.severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END`

var severityByRank = []domain.Severity{domain.SeverityInfo, domain.SeverityLow, domain.SeverityMedium,
	domain.SeverityHigh, domain.SeverityCritical}

var actionSelect = `SELECT a.id, a.project_id, p.name, a.kind, a.key, a.title, a.target,
		a.owner_id, (SELECT email FROM users WHERE id = a.owner_id), a.owner_manual,
		a.due_at, COALESCE(a.due_at < now() AND a.status IN ` + liveStatuses + `, false), a.status,
		a.created_by, (SELECT email FROM users WHERE id = a.created_by), a.created_at, a.updated_at,
		a.closed_at, a.closed_by, (SELECT email FROM users WHERE id = a.closed_by), a.close_reason,
		s.total, s.open, s.max_rank, s.priority, s.kev,
		i.id, i.tracker_id, it.kind, i.external_id, i.url, i.state, i.last_synced_at, i.created_at
	FROM remediation_actions a
	JOIN projects p ON p.id = a.project_id
	CROSS JOIN LATERAL (
		SELECT count(*) AS total,
		       count(*) FILTER (WHERE live) AS open,
		       COALESCE(max(rank) FILTER (WHERE live), -1) AS max_rank,
		       COALESCE(sum(f_priority) FILTER (WHERE live), 0) AS priority,
		       count(*) FILTER (WHERE live AND f_kev) AS kev
		FROM (SELECT f.status IN ('open', 'confirmed') AND f.duplicate_of IS NULL AND` + archive.Finding("f") + ` AS live,
		             ` + severityRank + ` AS rank, f.priority AS f_priority, f.kev AS f_kev
		      FROM remediation_action_findings raf JOIN findings f ON f.id = raf.finding_id
		      WHERE raf.action_id = a.id) x
	) s
	LEFT JOIN remediation_action_issues i ON i.action_id = a.id
	LEFT JOIN issue_trackers it ON it.id = i.tracker_id`

func scanAction(row pgx.Row) (Action, error) {
	var a Action
	var maxRank int
	var issueID, trackerID, extID, url, state *string
	var kind *issuetracker.Kind
	var synced, issueCreated *time.Time
	err := row.Scan(&a.ID, &a.ProjectID, &a.ProjectName, &a.Kind, &a.Key, &a.Title, &a.Target,
		&a.OwnerID, &a.OwnerEmail, &a.OwnerManual, &a.DueAt, &a.Overdue, &a.Status,
		&a.CreatedBy, &a.CreatedByEmail, &a.CreatedAt, &a.UpdatedAt,
		&a.ClosedAt, &a.ClosedBy, &a.ClosedByEmail, &a.CloseReason,
		&a.Findings, &a.OpenFindings, &maxRank, &a.Priority, &a.KEV,
		&issueID, &trackerID, &kind, &extID, &url, &state, &synced, &issueCreated)
	if err != nil {
		return Action{}, err
	}
	if maxRank >= 0 && maxRank < len(severityByRank) {
		a.MaxSeverity = severityByRank[maxRank]
	}
	if issueID != nil {
		a.Issue = &IssueLink{ID: *issueID, ActionID: a.ID, TrackerID: *trackerID, ExternalID: *extID, URL: *url,
			State: issuetracker.State(*state), LastSyncedAt: *synced, CreatedAt: *issueCreated}
		if kind != nil {
			a.Issue.Kind = *kind
		}
	}
	return a, nil
}

// Filter selects actions to list.
type Filter struct {
	ProjectIDs []string // nil = every project
	Statuses   []Status // empty = any
	Kind       fixplan.Kind
}

// List returns the matching actions, live first, then by due date (earliest
// first, none last) and the risk they remove.
func (r *Repository) List(ctx context.Context, f Filter, limit, offset int) ([]Action, error) {
	q := actionSelect + ` WHERE` + archive.Project("p")
	args := []any{}
	if f.ProjectIDs != nil {
		args = append(args, f.ProjectIDs)
		q += fmt.Sprintf(" AND a.project_id = ANY($%d::uuid[])", len(args))
	}
	if len(f.Statuses) > 0 {
		ss := make([]string, len(f.Statuses))
		for i, s := range f.Statuses {
			ss[i] = string(s)
		}
		args = append(args, ss)
		q += fmt.Sprintf(" AND a.status = ANY($%d::text[])", len(args))
	}
	if f.Kind != "" {
		args = append(args, string(f.Kind))
		q += fmt.Sprintf(" AND a.kind = $%d", len(args))
	}
	args = append(args, limit, offset)
	q += fmt.Sprintf(` ORDER BY a.status IN `+liveStatuses+` DESC, a.due_at ASC NULLS LAST, s.priority DESC,
		a.created_at, a.id LIMIT $%d OFFSET $%d`, len(args)-1, len(args))
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list remediation actions: %w", err)
	}
	defer rows.Close()
	out := []Action{}
	for rows.Next() {
		a, err := scanAction(rows)
		if err != nil {
			return nil, fmt.Errorf("scan remediation action: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Get returns one action.
func (r *Repository) Get(ctx context.Context, id string) (Action, error) {
	a, err := scanAction(r.db.QueryRow(ctx, actionSelect+` WHERE a.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Action{}, ErrNotFound
	}
	if err != nil {
		return Action{}, fmt.Errorf("get remediation action: %w", err)
	}
	return a, nil
}

// Findings returns the action's findings, live and most urgent first.
func (r *Repository) Findings(ctx context.Context, actionID string) ([]ActionFinding, error) {
	rows, err := r.db.Query(ctx, `
		SELECT f.id, f.title, f.severity, f.status, f.scanner, f.rule_id, f.cve, f.package_name,
		       f.package_version, f.fixed_version, f.file_path, f.line, f.priority, f.kev, f.sla_due_at,
		       (SELECT email FROM users WHERE id = f.assignee_id), f.duplicate_of, raf.added_at
		FROM remediation_action_findings raf JOIN findings f ON f.id = raf.finding_id
		WHERE raf.action_id = $1
		ORDER BY f.status IN ('open', 'confirmed') DESC, `+severityRank+` DESC, f.priority DESC, f.id`, actionID)
	if err != nil {
		return nil, fmt.Errorf("list action findings: %w", err)
	}
	defer rows.Close()
	out := []ActionFinding{}
	for rows.Next() {
		var f ActionFinding
		if err := rows.Scan(&f.ID, &f.Title, &f.Severity, &f.Status, &f.Scanner, &f.RuleID, &f.CVE,
			&f.PackageName, &f.PackageVersion, &f.FixedVersion, &f.FilePath, &f.Line, &f.Priority, &f.KEV,
			&f.SLADueAt, &f.AssigneeEmail, &f.DuplicateOf, &f.AddedAt); err != nil {
			return nil, fmt.Errorf("scan action finding: %w", err)
		}
		if f.CVE == nil {
			f.CVE = []string{}
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// LiveAction is the identity of a live action, for matching new findings to it.
type LiveAction struct {
	ID        string
	ProjectID string
	Kind      fixplan.Kind
	Key       string
	Target    string
}

// LiveActions returns the live actions of a project ("" = every project).
func (r *Repository) LiveActions(ctx context.Context, projectID string) ([]LiveAction, error) {
	rows, err := r.db.Query(ctx, `SELECT id, project_id, kind, key, target FROM remediation_actions
		WHERE status IN `+liveStatuses+` AND ($1 = '' OR project_id::text = $1)`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list live actions: %w", err)
	}
	defer rows.Close()
	out := []LiveAction{}
	for rows.Next() {
		var a LiveAction
		if err := rows.Scan(&a.ID, &a.ProjectID, &a.Kind, &a.Key, &a.Target); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// NewAction is an action to create from a proposed change.
type NewAction struct {
	ProjectID string
	Kind      fixplan.Kind
	Key       string
	Title     string
	Target    string
	CreatedBy *string // nil = the system (auto-create)
}

// Ensure returns the live action for the change, creating it if there is
// none, and adds the findings to it. Idempotent and safe against concurrent
// sweeps: the partial unique index admits one live action per change.
func (r *Repository) Ensure(ctx context.Context, n NewAction, findingIDs []string) (id string, created bool, err error) {
	err = r.db.QueryRow(ctx, `
		INSERT INTO remediation_actions (project_id, kind, key, title, target, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (project_id, kind, md5(key)) WHERE status IN `+liveStatuses+` DO NOTHING
		RETURNING id`, n.ProjectID, n.Kind, n.Key, n.Title, n.Target, n.CreatedBy).Scan(&id)
	created = err == nil
	if errors.Is(err, pgx.ErrNoRows) {
		err = r.db.QueryRow(ctx, `SELECT id FROM remediation_actions
			WHERE project_id = $1 AND kind = $2 AND md5(key) = md5($3) AND status IN `+liveStatuses,
			n.ProjectID, n.Kind, n.Key).Scan(&id)
	}
	if err != nil {
		return "", false, fmt.Errorf("ensure remediation action: %w", err)
	}
	if _, err := r.AddFindings(ctx, id, findingIDs); err != nil {
		return "", false, err
	}
	return id, created, nil
}

// AddFindings links findings to a live action, skipping any already in a
// live action (a finding is worked under one action at a time).
func (r *Repository) AddFindings(ctx context.Context, actionID string, findingIDs []string) (int, error) {
	tag, err := r.db.Exec(ctx, `
		INSERT INTO remediation_action_findings (action_id, finding_id)
		SELECT $1, fid FROM unnest($2::uuid[]) AS fid
		WHERE NOT EXISTS (
		    SELECT 1 FROM remediation_action_findings raf
		    JOIN remediation_actions ra ON ra.id = raf.action_id
		    WHERE raf.finding_id = fid AND ra.status IN `+liveStatuses+`)
		ON CONFLICT DO NOTHING`, actionID, findingIDs)
	if err != nil {
		return 0, fmt.Errorf("add action findings: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// SetTarget records a new target (a higher upgrade a joining finding needs).
func (r *Repository) SetTarget(ctx context.Context, actionID, target string) error {
	if _, err := r.db.Exec(ctx, `UPDATE remediation_actions SET target = $2, updated_at = now()
		WHERE id = $1 AND target IS DISTINCT FROM $2`, actionID, target); err != nil {
		return fmt.Errorf("set action target: %w", err)
	}
	return nil
}

// Refresh brings the live actions of a project ("" = every project) up to
// date with their findings: the due date is the earliest SLA deadline of the
// live ones, the owner (unless set by hand) the assignee owning most of them,
// and an action whose findings are all remediated or false positives (or
// gone) closes. Rows are written only when something changed. Returns the ids
// of the actions it closed.
func (r *Repository) Refresh(ctx context.Context, projectID string) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		WITH agg AS (
		    SELECT ra.id,
		           COALESCE(bool_and(f.status IN ('remediated', 'false_positive')), true) AS resolved,
		           min(f.sla_due_at) FILTER (WHERE f.status IN ('open', 'confirmed')) AS due,
		           (SELECT f2.assignee_id
		              FROM remediation_action_findings r2 JOIN findings f2 ON f2.id = r2.finding_id
		             WHERE r2.action_id = ra.id AND f2.status IN ('open', 'confirmed') AND f2.assignee_id IS NOT NULL
		             GROUP BY f2.assignee_id
		             ORDER BY count(*) DESC, max(f2.priority) DESC, f2.assignee_id
		             LIMIT 1) AS owner
		      FROM remediation_actions ra
		      LEFT JOIN remediation_action_findings raf ON raf.action_id = ra.id
		      LEFT JOIN findings f ON f.id = raf.finding_id
		     WHERE ra.status IN `+liveStatuses+` AND ($1 = '' OR ra.project_id::text = $1)
		     GROUP BY ra.id
		)
		UPDATE remediation_actions ra SET
		    due_at       = agg.due,
		    owner_id     = CASE WHEN ra.owner_manual THEN ra.owner_id ELSE agg.owner END,
		    status       = CASE WHEN agg.resolved THEN 'done' ELSE ra.status END,
		    closed_at    = CASE WHEN agg.resolved THEN now() ELSE ra.closed_at END,
		    closed_by    = CASE WHEN agg.resolved THEN NULL ELSE ra.closed_by END,
		    close_reason = CASE WHEN agg.resolved THEN '`+ReasonFindingsResolved+`' ELSE ra.close_reason END,
		    updated_at   = now()
		  FROM agg
		 WHERE ra.id = agg.id
		   AND (agg.resolved OR ra.due_at IS DISTINCT FROM agg.due
		        OR (NOT ra.owner_manual AND ra.owner_id IS DISTINCT FROM agg.owner))
		RETURNING ra.id, agg.resolved`, projectID)
	if err != nil {
		return nil, fmt.Errorf("refresh remediation actions: %w", err)
	}
	defer rows.Close()
	closed := []string{}
	for rows.Next() {
		var id string
		var resolved bool
		if err := rows.Scan(&id, &resolved); err != nil {
			return nil, err
		}
		if resolved {
			closed = append(closed, id)
		}
	}
	return closed, rows.Err()
}

// Patch is a user's change to an action. Nil fields are left alone.
type Patch struct {
	Status *Status
	Title  *string
	// SetOwner assigns OwnerID by hand (nil OwnerID = nobody); AutoOwner
	// hands the owner back to the findings' assignees.
	SetOwner  bool
	OwnerID   *string
	AutoOwner bool
}

// Update applies a user's patch. Closing records who and when; reopening
// clears that (ErrConflict when another live action already has the change).
func (r *Repository) Update(ctx context.Context, id string, p Patch, actorID string) error {
	var actor *string
	if actorID != "" {
		actor = &actorID
	}
	var status *string
	if p.Status != nil {
		status = new(string(*p.Status))
	}
	tag, err := r.db.Exec(ctx, `
		UPDATE remediation_actions SET
		    title        = COALESCE($2, title),
		    status       = COALESCE($3, status),
		    closed_at    = CASE WHEN $3 IS NULL OR $3 = status THEN closed_at
		                        WHEN $3 IN ('done', 'wont_do') THEN now() ELSE NULL END,
		    closed_by    = CASE WHEN $3 IS NULL OR $3 = status THEN closed_by
		                        WHEN $3 IN ('done', 'wont_do') THEN $4::uuid ELSE NULL END,
		    close_reason = CASE WHEN $3 IS NULL OR $3 = status THEN close_reason
		                        WHEN $3 IN ('done', 'wont_do') THEN '`+ReasonManual+`' ELSE '' END,
		    owner_id     = CASE WHEN $5 THEN $6::uuid WHEN $7 THEN NULL ELSE owner_id END,
		    owner_manual = CASE WHEN $5 THEN true WHEN $7 THEN false ELSE owner_manual END,
		    updated_at   = now()
		WHERE id = $1`, id, p.Title, status, actor, p.SetOwner, p.OwnerID, p.AutoOwner)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrConflict
		}
		return fmt.Errorf("update remediation action: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetStatusFromTracker moves an action as its ticket moved: done
// (ReasonIssueClosed) or reopened. Reopening an action whose change another
// live action now tracks is refused with ErrConflict.
func (r *Repository) SetStatusFromTracker(ctx context.Context, id string, s Status) error {
	reason := ""
	if !s.Live() {
		reason = ReasonIssueClosed
	}
	_, err := r.db.Exec(ctx, `
		UPDATE remediation_actions SET status = $2,
		    closed_at = CASE WHEN $2 IN ('done', 'wont_do') THEN now() ELSE NULL END,
		    closed_by = NULL, close_reason = $3, updated_at = now()
		WHERE id = $1`, id, string(s), reason)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrConflict
		}
		return fmt.Errorf("set action status: %w", err)
	}
	return nil
}

// ProjectOf returns the project an action belongs to.
func (r *Repository) ProjectOf(ctx context.Context, id string) (string, error) {
	var pid string
	err := r.db.QueryRow(ctx, `SELECT project_id FROM remediation_actions WHERE id = $1`, id).Scan(&pid)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return pid, err
}

const issueColumns = `i.id, i.action_id, i.tracker_id, it.kind, i.external_id, i.url, i.state, i.last_synced_at, i.created_at`

func issueDest(l *IssueLink, extra ...any) []any {
	return append([]any{&l.ID, &l.ActionID, &l.TrackerID, &l.Kind, &l.ExternalID, &l.URL, &l.State,
		&l.LastSyncedAt, &l.CreatedAt}, extra...)
}

// LinkIssueOnce returns the action's ticket, calling create to file it only if
// there is none. A per-action advisory lock held throughout means a double
// click never files two tickets. created reports whether create ran.
func (r *Repository) LinkIssueOnce(ctx context.Context, actionID, trackerID string,
	create func(context.Context) (externalID, url string, err error),
) (link IssueLink, created bool, err error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return IssueLink{}, false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('remediation_issue:' || $1::text))`, actionID); err != nil {
		return IssueLink{}, false, fmt.Errorf("lock action: %w", err)
	}
	err = tx.QueryRow(ctx, `SELECT `+issueColumns+` FROM remediation_action_issues i
		JOIN issue_trackers it ON it.id = i.tracker_id WHERE i.action_id = $1`, actionID).Scan(issueDest(&link)...)
	if err == nil {
		return link, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return IssueLink{}, false, fmt.Errorf("get action issue: %w", err)
	}
	extID, url, err := create(ctx)
	if err != nil {
		return IssueLink{}, false, err
	}
	err = tx.QueryRow(ctx, `
		WITH ins AS (
		    INSERT INTO remediation_action_issues (action_id, tracker_id, external_id, url, state)
		    VALUES ($1, $2, $3, $4, 'open') RETURNING *
		)
		SELECT `+issueColumns+` FROM ins i JOIN issue_trackers it ON it.id = i.tracker_id`,
		actionID, trackerID, extID, url).Scan(issueDest(&link)...)
	if err != nil {
		return IssueLink{}, false, fmt.Errorf("insert action issue: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return IssueLink{}, false, fmt.Errorf("commit: %w", err)
	}
	return link, true, nil
}

// IssueSyncItem is an action's ticket plus the action's current status.
type IssueSyncItem struct {
	IssueLink
	Status Status
}

// IssueSyncItems returns every action ticket filed in a tracker.
func (r *Repository) IssueSyncItems(ctx context.Context, trackerID string) ([]IssueSyncItem, error) {
	rows, err := r.db.Query(ctx, `SELECT `+issueColumns+`, a.status FROM remediation_action_issues i
		JOIN issue_trackers it ON it.id = i.tracker_id
		JOIN remediation_actions a ON a.id = i.action_id
		WHERE i.tracker_id = $1 ORDER BY i.created_at`, trackerID)
	if err != nil {
		return nil, fmt.Errorf("list action issues: %w", err)
	}
	defer rows.Close()
	out := []IssueSyncItem{}
	for rows.Next() {
		var it IssueSyncItem
		if err := rows.Scan(issueDest(&it.IssueLink, &it.Status)...); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// SetIssueState records the state both sides now agree on.
func (r *Repository) SetIssueState(ctx context.Context, linkID string, s issuetracker.State) error {
	if _, err := r.db.Exec(ctx, `UPDATE remediation_action_issues SET state = $2, last_synced_at = now()
		WHERE id = $1`, linkID, s); err != nil {
		return fmt.Errorf("set action issue state: %w", err)
	}
	return nil
}
