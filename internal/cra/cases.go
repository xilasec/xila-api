package cra

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/xilasec/xila-api/internal/archive"
)

// Article 14 reporting (Regulation (EU) 2024/2847, Art. 14(1)–(2)): a
// manufacturer that becomes aware of an actively exploited vulnerability in
// its product notifies the CSIRT designated as coordinator and ENISA through
// the single reporting platform — an early warning within 24 hours, a
// vulnerability notification within 72 hours, and a final report no later
// than 14 days after a corrective or mitigating measure is available.

// Reporting windows, measured from the awareness time (or, for the final
// report, from when a corrective measure became available). Absolute hours:
// a calendar "day" drifts an hour across a DST change.
const (
	EarlyWarningWindow = 24 * time.Hour
	NotificationWindow = 72 * time.Hour
	FinalReportWindow  = 14 * 24 * time.Hour
	// DueSoonLead is how long before a deadline cra.deadline_due_soon fires.
	DueSoonLead = 6 * time.Hour
)

// Errors.
var (
	ErrNotFound        = errors.New("cra case not found")
	ErrDuplicate       = errors.New("a reporting case already exists for this vulnerability")
	ErrNotInScope      = errors.New("project is not marked as in CRA scope")
	ErrFindingNotFound = errors.New("finding not found in this project")
	ErrTransition      = errors.New("invalid case transition")
	ErrInvalid         = errors.New("invalid case input")
)

// State is a case's position in the reporting workflow.
type State string

// Case states: open → early_warning_sent → notification_sent →
// final_report_sent → closed, or dismissed (with a reason) before closing.
const (
	StateOpen             State = "open"
	StateEarlyWarningSent State = "early_warning_sent"
	StateNotificationSent State = "notification_sent"
	StateFinalReportSent  State = "final_report_sent"
	StateClosed           State = "closed"
	StateDismissed        State = "dismissed"
)

// Active reports whether the case still has reporting work.
func (s State) Active() bool { return s != StateClosed && s != StateDismissed }

// Stage is one Article 14(2) submission.
type Stage string

// Submission stages, in order.
const (
	StageEarlyWarning Stage = "early_warning"
	StageNotification Stage = "notification"
	StageFinal        Stage = "final"
)

// Stages lists the stages in submission order.
var Stages = []Stage{StageEarlyWarning, StageNotification, StageFinal}

// Valid reports whether s is a known stage.
func (s Stage) Valid() bool {
	return s == StageEarlyWarning || s == StageNotification || s == StageFinal
}

// sentState is the state a submission of the stage moves the case to.
func (s Stage) sentState() State {
	switch s {
	case StageEarlyWarning:
		return StateEarlyWarningSent
	case StageNotification:
		return StateNotificationSent
	default:
		return StateFinalReportSent
	}
}

// NextStage is the submission a case in state s expects next ("" when none).
func (s State) NextStage() Stage {
	switch s {
	case StateOpen:
		return StageEarlyWarning
	case StateEarlyWarningSent:
		return StageNotification
	case StateNotificationSent:
		return StageFinal
	}
	return ""
}

// Triggers: what made the vulnerability count as actively exploited.
const (
	TriggerKEV        = "kev"        // listed in a Known Exploited Vulnerabilities catalog (KEV_SOURCES)
	TriggerWeaponized = "weaponized" // a weaponized public exploit (e.g. a Metasploit module)
	TriggerManual     = "manual"     // opened by hand (e.g. exploitation seen in incident response)
)

// Sensitivities the manufacturer may declare (Art. 14(2)(b)), as TLP labels.
var sensitivities = []string{"", "TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"}

// Deadline statuses.
const (
	DeadlineMet        = "met"         // submitted on time
	DeadlineLate       = "late"        // submitted after the deadline
	DeadlineMissed     = "missed"      // not submitted, deadline passed
	DeadlineDueSoon    = "due_soon"    // not submitted, within DueSoonLead of the deadline
	DeadlinePending    = "pending"     // not submitted, not yet due
	DeadlineNotStarted = "not_started" // the clock hasn't started (final: no corrective measure yet)
	DeadlineWaived     = "waived"      // case dismissed or closed before it was submitted
)

// Deadline is one stage's clock.
type Deadline struct {
	Stage  Stage      `json:"stage"`
	DueAt  *time.Time `json:"due_at"`
	SentAt *time.Time `json:"sent_at"`
	Status string     `json:"status"`
}

// DeadlineStatus classifies one stage's clock at now. Pure.
func DeadlineStatus(due, sent *time.Time, active bool, now time.Time) string {
	switch {
	case sent != nil && due != nil && sent.After(*due):
		return DeadlineLate
	case sent != nil:
		return DeadlineMet
	case !active:
		return DeadlineWaived
	case due == nil:
		return DeadlineNotStarted
	case !now.Before(*due):
		return DeadlineMissed
	case !now.Before(due.Add(-DueSoonLead)):
		return DeadlineDueSoon
	}
	return DeadlinePending
}

// CaseFinding is what the case shows of its finding (nil once deleted).
type CaseFinding struct {
	ID              string   `json:"id"`
	Title           string   `json:"title"`
	Description     string   `json:"description"`
	Scanner         string   `json:"scanner"`
	Status          string   `json:"status"`
	CVE             []string `json:"cve"`
	CWE             *int     `json:"cwe"`
	CVSS            *float64 `json:"cvss"`
	CVSSVector      *string  `json:"cvss_vector"`
	PackageName     string   `json:"package_name"`
	PackageVersion  string   `json:"package_version"`
	Purl            string   `json:"purl"`
	FixedVersion    string   `json:"fixed_version"`
	KEV             bool     `json:"kev"`
	KEVSources      []string `json:"kev_sources"` // the catalogs asserting it (cisa, enisa, vulncheck)
	ExploitMaturity string   `json:"exploit_maturity"`
}

// Case is one Article 14 reporting case: an actively exploited vulnerability
// in an in-scope project's product.
type Case struct {
	ID                    string       `json:"id"`
	ProjectID             string       `json:"project_id"`
	ProjectName           string       `json:"project_name"`
	ProductName           string       `json:"product_name"`
	ProductVersion        string       `json:"product_version"`
	MemberStates          []string     `json:"member_states"`
	FindingID             *string      `json:"finding_id"`
	Finding               *CaseFinding `json:"finding"`
	VulnID                string       `json:"vuln_id"`
	Title                 string       `json:"title"`
	Severity              string       `json:"severity"`
	Trigger               string       `json:"trigger"`
	State                 State        `json:"state"`
	AwareAt               time.Time    `json:"aware_at"`
	EarlyWarningDueAt     time.Time    `json:"early_warning_due_at"`
	NotificationDueAt     time.Time    `json:"notification_due_at"`
	CorrectiveAvailableAt *time.Time   `json:"corrective_available_at"`
	FinalReportDueAt      *time.Time   `json:"final_report_due_at"`
	EarlyWarningSentAt    *time.Time   `json:"early_warning_sent_at"`
	NotificationSentAt    *time.Time   `json:"notification_sent_at"`
	FinalReportSentAt     *time.Time   `json:"final_report_sent_at"`
	ClosedAt              *time.Time   `json:"closed_at"`
	DismissedReason       string       `json:"dismissed_reason"`
	Exploitation          string       `json:"exploitation"`
	CorrectiveMeasures    string       `json:"corrective_measures"`
	UserMitigations       string       `json:"user_mitigations"`
	Impact                string       `json:"impact"`
	MaliciousActor        string       `json:"malicious_actor"`
	Sensitivity           string       `json:"sensitivity"`
	CreatedAt             time.Time    `json:"created_at"`
	UpdatedAt             time.Time    `json:"updated_at"`
	// Derived at read time.
	NextStage Stage      `json:"next_stage"`
	Deadlines []Deadline `json:"deadlines"`
}

// derive fills the read-time fields at now.
func (c *Case) derive(now time.Time) {
	c.NextStage = c.State.NextStage()
	active := c.State.Active()
	ew, nt := c.EarlyWarningDueAt, c.NotificationDueAt
	c.Deadlines = []Deadline{
		{Stage: StageEarlyWarning, DueAt: &ew, SentAt: c.EarlyWarningSentAt, Status: DeadlineStatus(&ew, c.EarlyWarningSentAt, active, now)},
		{Stage: StageNotification, DueAt: &nt, SentAt: c.NotificationSentAt, Status: DeadlineStatus(&nt, c.NotificationSentAt, active, now)},
		{Stage: StageFinal, DueAt: c.FinalReportDueAt, SentAt: c.FinalReportSentAt, Status: DeadlineStatus(c.FinalReportDueAt, c.FinalReportSentAt, active, now)},
	}
}

// Compliant reports whether every stage due so far was submitted on time.
func (c Case) Compliant() bool {
	for _, d := range c.Deadlines {
		if d.Status == DeadlineLate || d.Status == DeadlineMissed {
			return false
		}
	}
	return true
}

// Event is one entry of a case's history.
type Event struct {
	ID         int64     `json:"id"`
	FromState  State     `json:"from_state"`
	ToState    State     `json:"to_state"`
	Stage      Stage     `json:"stage"`
	Payload    *Payload  `json:"payload"`
	Reference  string    `json:"reference"`
	Note       string    `json:"note"`
	ActorID    *string   `json:"actor_id"`
	ActorEmail string    `json:"actor_email"`
	CreatedAt  time.Time `json:"created_at"`
}

// Edit is a change to a case's report content (nil = unchanged).
type Edit struct {
	Exploitation          *string    `json:"exploitation"`
	CorrectiveMeasures    *string    `json:"corrective_measures"`
	UserMitigations       *string    `json:"user_mitigations"`
	Impact                *string    `json:"impact"`
	MaliciousActor        *string    `json:"malicious_actor"`
	Sensitivity           *string    `json:"sensitivity"`
	CorrectiveAvailableAt *time.Time `json:"corrective_available_at"`
}

// apply validates and applies the edit at now. Pure.
func (e Edit) apply(c *Case, now time.Time) error {
	if e.Sensitivity != nil {
		ok := false
		for _, s := range sensitivities {
			ok = ok || s == *e.Sensitivity
		}
		if !ok {
			return fmt.Errorf("%w: sensitivity must be a TLP label (TLP:CLEAR, TLP:GREEN, TLP:AMBER, TLP:AMBER+STRICT, TLP:RED)", ErrInvalid)
		}
		c.Sensitivity = *e.Sensitivity
	}
	if e.CorrectiveAvailableAt != nil {
		if e.CorrectiveAvailableAt.After(now) {
			return fmt.Errorf("%w: corrective_available_at is in the future", ErrInvalid)
		}
		if c.FinalReportSentAt != nil {
			return fmt.Errorf("%w: the final report was already submitted", ErrTransition)
		}
		at := e.CorrectiveAvailableAt.UTC()
		due := at.Add(FinalReportWindow)
		c.CorrectiveAvailableAt, c.FinalReportDueAt = &at, &due
	}
	for dst, src := range map[*string]*string{
		&c.Exploitation: e.Exploitation, &c.CorrectiveMeasures: e.CorrectiveMeasures,
		&c.UserMitigations: e.UserMitigations, &c.Impact: e.Impact, &c.MaliciousActor: e.MaliciousActor,
	} {
		if src != nil {
			if len(*src) > 20000 {
				return fmt.Errorf("%w: text fields are limited to 20000 characters", ErrInvalid)
			}
			*dst = *src
		}
	}
	return nil
}

// submit records the submission of stage at now. Pure: the case must expect
// exactly that stage next, and the final report needs a corrective measure.
func submit(c *Case, stage Stage, now time.Time) error {
	if !stage.Valid() {
		return fmt.Errorf("%w: stage must be early_warning, notification or final", ErrInvalid)
	}
	if next := c.State.NextStage(); next != stage {
		if next == "" {
			return fmt.Errorf("%w: a %s case takes no further submissions", ErrTransition, c.State)
		}
		return fmt.Errorf("%w: the next submission for this case is %s", ErrTransition, next)
	}
	if stage == StageFinal && c.CorrectiveAvailableAt == nil {
		return fmt.Errorf("%w: record when a corrective or mitigating measure became available first", ErrTransition)
	}
	t := now.UTC()
	switch stage {
	case StageEarlyWarning:
		c.EarlyWarningSentAt = &t
	case StageNotification:
		c.NotificationSentAt = &t
	case StageFinal:
		c.FinalReportSentAt = &t
	}
	c.State = stage.sentState()
	return nil
}

// dismiss ends an active case without reporting, with a reason. Pure.
func dismiss(c *Case, reason string, now time.Time) error {
	if reason == "" {
		return fmt.Errorf("%w: a reason is required to dismiss a case", ErrInvalid)
	}
	if !c.State.Active() || c.State == StateFinalReportSent {
		return fmt.Errorf("%w: a %s case can't be dismissed", ErrTransition, c.State)
	}
	t := now.UTC()
	c.State, c.DismissedReason, c.ClosedAt = StateDismissed, reason, &t
	return nil
}

// closeCase closes a case once its final report is in. Pure.
func closeCase(c *Case, now time.Time) error {
	if c.State != StateFinalReportSent {
		return fmt.Errorf("%w: only a case whose final report was submitted can be closed", ErrTransition)
	}
	t := now.UTC()
	c.State, c.ClosedAt = StateClosed, &t
	return nil
}

// --- persistence -----------------------------------------------------------

// caseSelect reads a case with its project's product and its finding.
const caseSelect = `
	SELECT c.id, c.project_id, p.name, p.cra_product_name, p.cra_product_version, p.cra_member_states,
	       c.finding_id, c.vuln_id, c.title, c.severity, c.trigger, c.state, c.aware_at,
	       c.early_warning_due_at, c.notification_due_at, c.corrective_available_at, c.final_report_due_at,
	       c.early_warning_sent_at, c.notification_sent_at, c.final_report_sent_at, c.closed_at,
	       c.dismissed_reason, c.exploitation, c.corrective_measures, c.user_mitigations, c.impact,
	       c.malicious_actor, c.sensitivity, c.created_at, c.updated_at,
	       f.id, COALESCE(f.title, ''), COALESCE(f.description, ''), COALESCE(f.scanner, ''), COALESCE(f.status, ''),
	       COALESCE(f.cve, '{}'), f.cwe, f.cvss::float8, f.cvss_vector, COALESCE(f.package_name, ''),
	       COALESCE(f.package_version, ''), COALESCE(f.purl, ''), COALESCE(f.fixed_version, ''),
	       COALESCE(f.kev, false), COALESCE(f.kev_sources, '{}'), COALESCE(f.exploit_maturity, '')
	FROM cra_cases c
	JOIN projects p ON p.id = c.project_id
	LEFT JOIN findings f ON f.id = c.finding_id`

func scanCase(row pgx.Row) (Case, error) {
	var c Case
	var fid *string
	var f CaseFinding
	err := row.Scan(&c.ID, &c.ProjectID, &c.ProjectName, &c.ProductName, &c.ProductVersion, &c.MemberStates,
		&c.FindingID, &c.VulnID, &c.Title, &c.Severity, &c.Trigger, &c.State, &c.AwareAt,
		&c.EarlyWarningDueAt, &c.NotificationDueAt, &c.CorrectiveAvailableAt, &c.FinalReportDueAt,
		&c.EarlyWarningSentAt, &c.NotificationSentAt, &c.FinalReportSentAt, &c.ClosedAt,
		&c.DismissedReason, &c.Exploitation, &c.CorrectiveMeasures, &c.UserMitigations, &c.Impact,
		&c.MaliciousActor, &c.Sensitivity, &c.CreatedAt, &c.UpdatedAt,
		&fid, &f.Title, &f.Description, &f.Scanner, &f.Status,
		&f.CVE, &f.CWE, &f.CVSS, &f.CVSSVector, &f.PackageName,
		&f.PackageVersion, &f.Purl, &f.FixedVersion, &f.KEV, &f.KEVSources, &f.ExploitMaturity)
	if err != nil {
		return Case{}, err
	}
	if fid != nil {
		f.ID = *fid
		c.Finding = &f
	}
	return c, nil
}

// Product is a project's CRA product declaration.
type Product struct {
	InScope bool   `json:"cra_in_scope"`
	Name    string `json:"product_name"`
	Version string `json:"product_version"`
	// MemberStates the product is made available in (ISO 3166-1 alpha-2).
	MemberStates []string `json:"member_states"`
}

// Product reads a project's CRA product declaration.
func (r *Repository) Product(ctx context.Context, projectID string) (Product, error) {
	var p Product
	err := r.db.QueryRow(ctx, `SELECT cra_in_scope, cra_product_name, cra_product_version, cra_member_states
		FROM projects WHERE id = $1`, projectID).Scan(&p.InScope, &p.Name, &p.Version, &p.MemberStates)
	if errors.Is(err, pgx.ErrNoRows) {
		return Product{}, ErrNotFound
	}
	return p, err
}

// SetProduct stores a project's CRA product declaration.
func (r *Repository) SetProduct(ctx context.Context, projectID string, p Product) error {
	tag, err := r.db.Exec(ctx, `UPDATE projects SET cra_in_scope = $2, cra_product_name = $3,
		cra_product_version = $4, cra_member_states = $5, updated_at = now() WHERE id = $1`,
		projectID, p.InScope, p.Name, p.Version, p.MemberStates)
	if err != nil {
		return fmt.Errorf("set cra product: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Get reads one case.
func (r *Repository) Get(ctx context.Context, id string) (Case, error) {
	c, err := scanCase(r.db.QueryRow(ctx, caseSelect+` WHERE c.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Case{}, ErrNotFound
	}
	if err != nil {
		return Case{}, fmt.Errorf("get cra case: %w", err)
	}
	return c, nil
}

// CaseFilter narrows a case list.
type CaseFilter struct {
	ProjectIDs []string // RBAC scope; nil = all (admin)
	ProjectID  string
	State      string // a State, "active" (default: every state), or ""
	Limit      int    // 0 = all
	Offset     int
}

// List lists cases, the most urgent first: active before finished, then by
// the earliest unsent deadline.
func (r *Repository) List(ctx context.Context, f CaseFilter) ([]Case, error) {
	q := caseSelect + ` WHERE ($1::uuid[] IS NULL OR c.project_id = ANY($1))
		AND ($2::uuid IS NULL OR c.project_id = $2)
		AND ($3 = '' OR ($3 = 'active' AND c.state NOT IN ('closed', 'dismissed')) OR c.state = $3)
		ORDER BY c.state IN ('closed', 'dismissed'),
		         CASE WHEN c.early_warning_sent_at IS NULL THEN c.early_warning_due_at
		              WHEN c.notification_sent_at IS NULL THEN c.notification_due_at
		              ELSE COALESCE(c.final_report_due_at, 'infinity') END,
		         c.created_at DESC, c.id
		LIMIT $4 OFFSET $5`
	var pid *string
	if f.ProjectID != "" {
		pid = &f.ProjectID
	}
	var limit *int
	if f.Limit > 0 {
		limit = &f.Limit
	}
	var scope any
	if f.ProjectIDs != nil {
		scope = f.ProjectIDs
	}
	rows, err := r.db.Query(ctx, q, scope, pid, f.State, limit, f.Offset)
	if err != nil {
		return nil, fmt.Errorf("list cra cases: %w", err)
	}
	defer rows.Close()
	out := []Case{}
	for rows.Next() {
		c, err := scanCase(rows)
		if err != nil {
			return nil, fmt.Errorf("scan cra case: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Events lists a case's history, oldest first.
func (r *Repository) Events(ctx context.Context, caseID string) ([]Event, error) {
	rows, err := r.db.Query(ctx, `SELECT id, from_state, to_state, stage, payload, reference, note,
		actor_id, actor_email, created_at FROM cra_case_events WHERE case_id = $1 ORDER BY id`, caseID)
	if err != nil {
		return nil, fmt.Errorf("list cra case events: %w", err)
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.FromState, &e.ToState, &e.Stage, &e.Payload, &e.Reference, &e.Note,
			&e.ActorID, &e.ActorEmail, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan cra case event: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Opened is a case just opened, for the alert.
type Opened struct {
	ID, ProjectID, ProjectName, VulnID, Title, Severity, Trigger string
	EarlyWarningDueAt                                            time.Time
}

// exploitedSQL selects, per (project, vulnerability), the best open finding
// of an in-scope project that is actively exploited: KEV-listed or with a
// weaponized exploit, on the default version, never a cross-tool duplicate.
// The vulnerability id is the lowest CVE, else the rule id — the key
// sbom.VulnState uses too. An archived finding (or project) is not exploited.
var exploitedSQL = `
	SELECT DISTINCT ON (f.project_id, v.vuln_id)
	       f.project_id, f.id, v.vuln_id, f.title, f.severity,
	       CASE WHEN f.kev THEN 'kev' ELSE 'weaponized' END AS trigger,
	       (f.fixed_version <> '' OR f.status = 'remediated') AS corrective
	FROM findings f
	JOIN projects p ON p.id = f.project_id AND p.cra_in_scope
	CROSS JOIN LATERAL (SELECT COALESCE((SELECT min(upper(x)) FROM unnest(f.cve) x), NULLIF(f.rule_id, ''), f.fingerprint) AS vuln_id) v
	WHERE f.status IN ('open', 'confirmed') AND f.duplicate_of IS NULL
	  AND f.version_id IN (SELECT id FROM project_versions WHERE is_default)
	  AND (f.kev OR f.exploit_maturity = 'weaponized')
	  AND` + archive.Finding("f") + `
	  AND ($1::uuid IS NULL OR f.project_id = $1)
	ORDER BY f.project_id, v.vuln_id, f.kev DESC, f.priority DESC, f.id`

// OpenExploited opens a case for every actively exploited vulnerability of an
// in-scope project (one project, or all with projectID "") that has none yet,
// aware at now. A dismissed or closed case is never reopened.
func (r *Repository) OpenExploited(ctx context.Context, projectID string, now time.Time) ([]Opened, error) {
	var pid *string
	if projectID != "" {
		pid = &projectID
	}
	rows, err := r.db.Query(ctx, `
		WITH ins AS (
			INSERT INTO cra_cases (project_id, finding_id, vuln_id, title, severity, trigger, aware_at,
			                       early_warning_due_at, notification_due_at, corrective_available_at, final_report_due_at)
			SELECT x.project_id, x.id, x.vuln_id, x.title, x.severity, x.trigger, $2::timestamptz, $3::timestamptz, $4::timestamptz,
			       CASE WHEN x.corrective THEN $2::timestamptz END, CASE WHEN x.corrective THEN $5::timestamptz END
			FROM (`+exploitedSQL+`) x
			ON CONFLICT (project_id, vuln_id) DO NOTHING
			RETURNING id, project_id, vuln_id, title, severity, trigger, early_warning_due_at),
		ev AS (
			INSERT INTO cra_case_events (case_id, to_state, note)
			SELECT id, 'open', CASE trigger WHEN 'kev' THEN 'Listed in a Known Exploited Vulnerabilities catalog'
			                                ELSE 'A weaponized public exploit is available' END
			FROM ins)
		SELECT ins.id, ins.project_id, p.name, ins.vuln_id, ins.title, ins.severity, ins.trigger, ins.early_warning_due_at
		FROM ins JOIN projects p ON p.id = ins.project_id ORDER BY p.name, ins.vuln_id`,
		pid, now.UTC(), now.Add(EarlyWarningWindow).UTC(), now.Add(NotificationWindow).UTC(), now.Add(FinalReportWindow).UTC())
	if err != nil {
		return nil, fmt.Errorf("open cra cases: %w", err)
	}
	defer rows.Close()
	var out []Opened
	for rows.Next() {
		var o Opened
		if err := rows.Scan(&o.ID, &o.ProjectID, &o.ProjectName, &o.VulnID, &o.Title, &o.Severity, &o.Trigger, &o.EarlyWarningDueAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// OpenManual opens a case for one finding by hand, aware at awareAt.
func (r *Repository) OpenManual(ctx context.Context, projectID, findingID, actorID, note string, awareAt time.Time) (Opened, error) {
	var actor *string
	if actorID != "" {
		actor = &actorID
	}
	var found, inScope bool
	var id, pid, vuln, title, severity, trigger *string
	var due *time.Time
	err := r.db.QueryRow(ctx, `
		WITH f AS (
			SELECT f.id, f.project_id, f.title, f.severity, p.cra_in_scope,
			       COALESCE((SELECT min(upper(x)) FROM unnest(f.cve) x), NULLIF(f.rule_id, ''), f.fingerprint) AS vuln_id,
			       (f.fixed_version <> '' OR f.status = 'remediated') AS corrective
			FROM findings f JOIN projects p ON p.id = f.project_id
			WHERE f.id = $1 AND f.project_id = $2),
		ins AS (
			INSERT INTO cra_cases (project_id, finding_id, vuln_id, title, severity, trigger, aware_at,
			                       early_warning_due_at, notification_due_at, corrective_available_at, final_report_due_at)
			SELECT project_id, id, vuln_id, title, severity, 'manual', $3::timestamptz, $4::timestamptz, $5::timestamptz,
			       CASE WHEN corrective THEN $3::timestamptz END, CASE WHEN corrective THEN $6::timestamptz END
			FROM f WHERE cra_in_scope
			ON CONFLICT (project_id, vuln_id) DO NOTHING
			RETURNING id, project_id, vuln_id, title, severity, trigger, early_warning_due_at),
		ev AS (
			INSERT INTO cra_case_events (case_id, to_state, note, actor_id, actor_email)
			SELECT id, 'open', $7::text, $8::uuid, COALESCE((SELECT email FROM users WHERE id = $8::uuid), '') FROM ins)
		SELECT EXISTS (SELECT 1 FROM f), COALESCE((SELECT cra_in_scope FROM f), false),
		       ins.id, ins.project_id, ins.vuln_id, ins.title, ins.severity, ins.trigger, ins.early_warning_due_at
		FROM (SELECT 1) one LEFT JOIN ins ON true`,
		findingID, projectID, awareAt.UTC(), awareAt.Add(EarlyWarningWindow).UTC(), awareAt.Add(NotificationWindow).UTC(),
		awareAt.Add(FinalReportWindow).UTC(), note, actor).
		Scan(&found, &inScope, &id, &pid, &vuln, &title, &severity, &trigger, &due)
	switch {
	case err != nil:
		return Opened{}, fmt.Errorf("open cra case: %w", err)
	case !found:
		return Opened{}, ErrFindingNotFound
	case !inScope:
		return Opened{}, ErrNotInScope
	case id == nil:
		return Opened{}, ErrDuplicate
	}
	return Opened{ID: *id, ProjectID: *pid, VulnID: *vuln, Title: *title, Severity: *severity, Trigger: *trigger,
		EarlyWarningDueAt: *due}, nil
}

// transition locks a case, lets mutate change it (and describe the event),
// then writes the case's mutable fields and the event in one transaction.
func (r *Repository) transition(ctx context.Context, id, actorID string, mutate func(c *Case) (Event, error)) (Case, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Case{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	c, err := scanCase(tx.QueryRow(ctx, caseSelect+` WHERE c.id = $1 FOR UPDATE OF c`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Case{}, ErrNotFound
	}
	if err != nil {
		return Case{}, fmt.Errorf("lock cra case: %w", err)
	}
	from := c.State
	ev, err := mutate(&c)
	if err != nil {
		return Case{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE cra_cases SET state = $2, early_warning_sent_at = $3, notification_sent_at = $4,
		final_report_sent_at = $5, closed_at = $6, dismissed_reason = $7, exploitation = $8, corrective_measures = $9,
		user_mitigations = $10, impact = $11, malicious_actor = $12, sensitivity = $13, corrective_available_at = $14,
		final_report_due_at = $15, updated_at = now() WHERE id = $1`,
		c.ID, c.State, c.EarlyWarningSentAt, c.NotificationSentAt, c.FinalReportSentAt, c.ClosedAt, c.DismissedReason,
		c.Exploitation, c.CorrectiveMeasures, c.UserMitigations, c.Impact, c.MaliciousActor, c.Sensitivity,
		c.CorrectiveAvailableAt, c.FinalReportDueAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23514" {
			return Case{}, fmt.Errorf("%w: %s", ErrInvalid, pgErr.Message)
		}
		return Case{}, fmt.Errorf("update cra case: %w", err)
	}
	var actor *string
	if actorID != "" {
		actor = &actorID
	}
	if _, err := tx.Exec(ctx, `INSERT INTO cra_case_events (case_id, from_state, to_state, stage, payload, reference, note, actor_id, actor_email)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE((SELECT email FROM users WHERE id = $8), ''))`,
		c.ID, from, c.State, ev.Stage, ev.Payload, ev.Reference, ev.Note, actor); err != nil {
		return Case{}, fmt.Errorf("record cra case event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Case{}, err
	}
	return c, nil
}

// MarkCorrective starts the final-report clock of every active case whose
// vulnerability now has a fix available or was remediated: corrective measure
// available at now, final report due 14 days later. The clock is per
// vulnerability, so any of the project's findings of it counts — not only the
// one the case was opened from (the same CVE is often reported at several
// locations, and the fix may show up on any of them first).
func (r *Repository) MarkCorrective(ctx context.Context, now time.Time) (int, error) {
	tag, err := r.db.Exec(ctx, `UPDATE cra_cases c SET corrective_available_at = $1, final_report_due_at = $2, updated_at = now()
		WHERE c.corrective_available_at IS NULL AND c.state NOT IN ('closed', 'dismissed')
		  AND EXISTS (
			SELECT 1 FROM findings f
			CROSS JOIN LATERAL (SELECT COALESCE((SELECT min(upper(x)) FROM unnest(f.cve) x), NULLIF(f.rule_id, ''), f.fingerprint) AS vuln_id) v
			WHERE f.project_id = c.project_id AND v.vuln_id = c.vuln_id
			  AND f.version_id IN (SELECT id FROM project_versions WHERE is_default)
			  AND (f.fixed_version <> '' OR f.status = 'remediated'))`, now.UTC(), now.Add(FinalReportWindow).UTC())
	if err != nil {
		return 0, fmt.Errorf("mark corrective measures: %w", err)
	}
	return int(tag.RowsAffected()), nil
}

// Alert is a case with the stages a sweep newly alerts about.
type Alert struct {
	CaseID, ProjectID, ProjectName, VulnID, Title, Severity string
	Stages                                                  []Stage
	DueAt                                                   time.Time // the earliest of the stages' deadlines
}

// pendingSQL lists every unsent stage of an active case with its deadline.
const pendingSQL = `
	SELECT c.id, s.stage, s.due_at
	FROM cra_cases c
	CROSS JOIN LATERAL (VALUES
		('early_warning', c.early_warning_due_at, c.early_warning_sent_at IS NULL AND c.state = 'open'),
		('notification', c.notification_due_at, c.notification_sent_at IS NULL AND c.state IN ('open', 'early_warning_sent')),
		('final', c.final_report_due_at, c.final_report_sent_at IS NULL AND c.state IN ('open', 'early_warning_sent', 'notification_sent'))
	) AS s(stage, due_at, pending)
	WHERE s.pending AND s.due_at IS NOT NULL`

// MarkMissed records, once per case and stage, every unsent deadline that
// has passed, and returns them for alerting. A stage already alerted as
// missed is never returned again, even across sweeps or replicas.
func (r *Repository) MarkMissed(ctx context.Context, now time.Time) ([]Alert, error) {
	return r.mark(ctx, `
		WITH hits AS (
			SELECT d.id, array_agg(d.stage ORDER BY d.due_at) AS stages, min(d.due_at) AS due_at
			FROM (`+pendingSQL+`) d JOIN cra_cases c ON c.id = d.id
			WHERE d.due_at <= $1 AND NOT d.stage = ANY(c.alerted_missed)
			GROUP BY d.id)
		UPDATE cra_cases c SET alerted_missed = c.alerted_missed || h.stages
		FROM hits h, projects p
		WHERE c.id = h.id AND p.id = c.project_id AND`+archive.Project("p")+` AND NOT c.alerted_missed && h.stages
		RETURNING c.id, c.project_id, p.name, c.vuln_id, c.title, c.severity, h.stages, h.due_at`, now.UTC())
}

// MarkDueSoon records, once per case and stage, every unsent deadline within
// lead of now, and returns them for alerting.
func (r *Repository) MarkDueSoon(ctx context.Context, now time.Time, lead time.Duration) ([]Alert, error) {
	return r.mark(ctx, `
		WITH hits AS (
			SELECT d.id, array_agg(d.stage ORDER BY d.due_at) AS stages, min(d.due_at) AS due_at
			FROM (`+pendingSQL+`) d JOIN cra_cases c ON c.id = d.id
			WHERE d.due_at > $1 AND d.due_at <= $1 + make_interval(secs => $2) AND NOT d.stage = ANY(c.alerted_due_soon)
			GROUP BY d.id)
		UPDATE cra_cases c SET alerted_due_soon = c.alerted_due_soon || h.stages
		FROM hits h, projects p
		WHERE c.id = h.id AND p.id = c.project_id AND`+archive.Project("p")+` AND NOT c.alerted_due_soon && h.stages
		RETURNING c.id, c.project_id, p.name, c.vuln_id, c.title, c.severity, h.stages, h.due_at`, now.UTC(), lead.Seconds())
}

func (r *Repository) mark(ctx context.Context, q string, args ...any) ([]Alert, error) {
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("mark cra deadlines: %w", err)
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(&a.CaseID, &a.ProjectID, &a.ProjectName, &a.VulnID, &a.Title, &a.Severity, &a.Stages, &a.DueAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
