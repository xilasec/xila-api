// Package reportschedule renders a user's recurring report (project,
// portfolio or per-framework evidence) and delivers it by email (the
// rendered HTML as an attachment) or as a link-only notification to
// channels. A leader job runs due schedules as their owner: the owner's RBAC
// scope is resolved at send time, never cached, and a deactivated owner or
// one who lost access to the schedule's project fails the run rather than
// sending anything.
package reportschedule

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Kind is what a schedule renders.
type Kind string

// Supported kinds.
const (
	KindProject   Kind = "project"   // one project's report
	KindPortfolio Kind = "portfolio" // the owner's visible scope, as a portfolio report
	KindEvidence  Kind = "evidence"  // one project's evidence report for one framework
)

// Cadence is how often a schedule runs.
type Cadence string

// Supported cadences.
const (
	CadenceDaily   Cadence = "daily"
	CadenceWeekly  Cadence = "weekly"
	CadenceMonthly Cadence = "monthly"
)

// Sentinel errors.
var (
	ErrNotFound = errors.New("report schedule not found")
)

// Schedule is a user's recurring report.
type Schedule struct {
	ID                  string     `json:"id"`
	OwnerID             string     `json:"owner_id"`
	OwnerEmail          string     `json:"owner_email,omitempty"`
	Name                string     `json:"name"`
	Kind                Kind       `json:"kind"`
	ProjectID           *string    `json:"project_id"`
	ProjectName         string     `json:"project_name,omitempty"`
	FrameworkKey        string     `json:"framework_key,omitempty"`
	TemplateID          *string    `json:"template_id"`
	EngagementID        *string    `json:"engagement_id"`
	Cadence             Cadence    `json:"cadence"`
	Hour                int        `json:"hour"`
	Weekday             *int       `json:"weekday,omitempty"`
	DayOfMonth          *int       `json:"day_of_month,omitempty"`
	RecipientEmails     []string   `json:"recipient_emails"`
	RecipientChannelIDs []string   `json:"recipient_channel_ids"`
	Enabled             bool       `json:"enabled"`
	LastRunAt           *time.Time `json:"last_run_at"`
	LastRunStatus       string     `json:"last_run_status"`
	LastRunError        string     `json:"last_run_error,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// Run is one past render+delivery attempt, for a schedule's history.
type Run struct {
	ID         string     `json:"id"`
	ScheduleID string     `json:"schedule_id"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at"`
	Status     string     `json:"status"`
	Error      string     `json:"error,omitempty"`
	Recipients int        `json:"recipients"`
}

// Repository stores schedules and their run history.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

const scheduleColumns = `rs.id, rs.owner_id, u.email, rs.name, rs.kind, rs.project_id, COALESCE(p.name, ''),
	rs.framework_key, rs.template_id, rs.engagement_id, rs.cadence, rs.hour, rs.weekday, rs.day_of_month,
	rs.recipient_emails, rs.recipient_channel_ids, rs.enabled, rs.last_run_at, rs.last_run_status,
	rs.last_run_error, rs.created_at, rs.updated_at`

const scheduleFrom = ` FROM report_schedules rs
	JOIN users u ON u.id = rs.owner_id
	LEFT JOIN projects p ON p.id = rs.project_id`

func scanSchedule(row pgx.Row) (Schedule, error) {
	var s Schedule
	var kind, cadence string
	err := row.Scan(&s.ID, &s.OwnerID, &s.OwnerEmail, &s.Name, &kind, &s.ProjectID, &s.ProjectName,
		&s.FrameworkKey, &s.TemplateID, &s.EngagementID, &cadence, &s.Hour, &s.Weekday, &s.DayOfMonth,
		&s.RecipientEmails, &s.RecipientChannelIDs, &s.Enabled, &s.LastRunAt, &s.LastRunStatus,
		&s.LastRunError, &s.CreatedAt, &s.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Schedule{}, ErrNotFound
	}
	s.Kind, s.Cadence = Kind(kind), Cadence(cadence)
	return s, err
}

// ListByOwner returns owner's own schedules, newest first.
func (r *Repository) ListByOwner(ctx context.Context, ownerID string) ([]Schedule, error) {
	return queryList(ctx, r.db, `SELECT `+scheduleColumns+scheduleFrom+
		` WHERE rs.owner_id = $1 ORDER BY rs.created_at DESC`, ownerID)
}

// ListAll returns every schedule (admin), newest first.
func (r *Repository) ListAll(ctx context.Context) ([]Schedule, error) {
	return queryList(ctx, r.db, `SELECT `+scheduleColumns+scheduleFrom+` ORDER BY rs.created_at DESC`)
}

// ListEnabled returns every enabled schedule, for the due-run sweep.
func (r *Repository) ListEnabled(ctx context.Context) ([]Schedule, error) {
	return queryList(ctx, r.db, `SELECT `+scheduleColumns+scheduleFrom+` WHERE rs.enabled`)
}

func queryList(ctx context.Context, db *pgxpool.Pool, query string, args ...any) ([]Schedule, error) {
	rows, err := db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list report schedules: %w", err)
	}
	defer rows.Close()
	out := []Schedule{}
	for rows.Next() {
		s, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Get returns one schedule by id, regardless of owner (the service checks
// ownership).
func (r *Repository) Get(ctx context.Context, id string) (Schedule, error) {
	return scanSchedule(r.db.QueryRow(ctx, `SELECT `+scheduleColumns+scheduleFrom+` WHERE rs.id = $1`, id))
}

// Create inserts a schedule.
func (r *Repository) Create(ctx context.Context, s Schedule) (Schedule, error) {
	row := r.db.QueryRow(ctx, `INSERT INTO report_schedules
		(owner_id, name, kind, project_id, framework_key, template_id, engagement_id, cadence, hour,
		 weekday, day_of_month, recipient_emails, recipient_channel_ids, enabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) RETURNING id`,
		s.OwnerID, s.Name, string(s.Kind), s.ProjectID, s.FrameworkKey, s.TemplateID, s.EngagementID,
		string(s.Cadence), s.Hour, s.Weekday, s.DayOfMonth, nonNil(s.RecipientEmails), nonNil(s.RecipientChannelIDs), s.Enabled)
	var id string
	if err := row.Scan(&id); err != nil {
		return Schedule{}, err
	}
	return r.Get(ctx, id)
}

// nonNil turns a nil slice into an empty one, so it binds as an empty SQL
// array rather than NULL (the columns are NOT NULL).
func nonNil(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

// Update rewrites a schedule's configuration (not its run history).
func (r *Repository) Update(ctx context.Context, s Schedule) (Schedule, error) {
	tag, err := r.db.Exec(ctx, `UPDATE report_schedules SET name = $2, kind = $3, project_id = $4,
		framework_key = $5, template_id = $6, engagement_id = $7, cadence = $8, hour = $9, weekday = $10,
		day_of_month = $11, recipient_emails = $12, recipient_channel_ids = $13, enabled = $14, updated_at = now()
		WHERE id = $1`,
		s.ID, s.Name, string(s.Kind), s.ProjectID, s.FrameworkKey, s.TemplateID, s.EngagementID,
		string(s.Cadence), s.Hour, s.Weekday, s.DayOfMonth, nonNil(s.RecipientEmails), nonNil(s.RecipientChannelIDs), s.Enabled)
	if err != nil {
		return Schedule{}, err
	}
	if tag.RowsAffected() == 0 {
		return Schedule{}, ErrNotFound
	}
	return r.Get(ctx, s.ID)
}

// Delete removes a schedule (and, by cascade, its run history).
func (r *Repository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM report_schedules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordRun inserts the run's history row and updates the schedule's last-run
// summary, in one transaction.
func (r *Repository) RecordRun(ctx context.Context, scheduleID, status, errMsg string, recipients int) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if _, err := tx.Exec(ctx, `INSERT INTO report_schedule_runs
		(schedule_id, finished_at, status, error, recipients) VALUES ($1, now(), $2, $3, $4)`,
		scheduleID, status, errMsg, recipients); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE report_schedules
		SET last_run_at = now(), last_run_status = $2, last_run_error = $3 WHERE id = $1`,
		scheduleID, status, errMsg); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ListRuns returns a schedule's run history, newest first.
func (r *Repository) ListRuns(ctx context.Context, scheduleID string, limit int) ([]Run, error) {
	rows, err := r.db.Query(ctx, `SELECT id, schedule_id, started_at, finished_at, status, error, recipients
		FROM report_schedule_runs WHERE schedule_id = $1 ORDER BY started_at DESC LIMIT $2`, scheduleID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Run{}
	for rows.Next() {
		var run Run
		if err := rows.Scan(&run.ID, &run.ScheduleID, &run.StartedAt, &run.FinishedAt, &run.Status,
			&run.Error, &run.Recipients); err != nil {
			return nil, err
		}
		out = append(out, run)
	}
	return out, rows.Err()
}
