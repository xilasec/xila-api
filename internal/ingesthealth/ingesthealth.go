// Package ingesthealth watches the data coming in, so a broken pipeline is
// noticed before its silence is mistaken for a clean bill of health: a
// scanner that stopped uploading, an upload that suddenly reports a fraction
// of what it used to (expired credentials, a scanner misconfigured to scan
// nothing), failed scans and ingest jobs, and connectors whose pulls fail.
package ingesthealth

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/notify"
)

// Anomaly kinds.
const (
	KindStale            = "stale"             // a scanner stopped uploading
	KindVolumeDrop       = "volume_drop"       // the last upload reported far fewer findings than usual
	KindFailedScan       = "failed_scan"       // the stream's latest scan failed
	KindConnectorFailing = "connector_failing" // a connector's last pull failed
	KindFailedJobs       = "failed_jobs"       // ingest jobs gave up recently
	KindMissing          = "missing"           // a declared scan expectation has no recent completed scan
)

// Detection thresholds.
const (
	minHistory      = 3                  // scans a stream needs before cadence means anything
	staleFactor     = 3                  // stale once silent for this many usual gaps…
	staleFloor      = 24 * time.Hour     // …and at least a day
	dropRatio       = 0.5                // last total below this share of the usual…
	dropMinBaseline = 10                 // …when the usual is at least this many findings
	historyWindow   = 10                 // previous scans considered
	failedJobWindow = 7 * 24 * time.Hour // failed ingest jobs counted over this window
)

// Anomaly is one thing wrong with a project's intake.
type Anomaly struct {
	Kind        string  `json:"kind"`
	ProjectID   string  `json:"project_id"`
	ProjectName string  `json:"project_name"`
	Scanner     string  `json:"scanner,omitempty"`
	AssetID     *string `json:"asset_id,omitempty"`
	// Branch is set for a KindMissing anomaly: the expectation's declared
	// branch ("" means the project's default version).
	Branch string    `json:"branch,omitempty"`
	Detail string    `json:"detail"`
	Since  time.Time `json:"since"` // when the problem became visible
}

// Key identifies an anomaly across sweeps.
func (a Anomaly) Key() string {
	asset := ""
	if a.AssetID != nil {
		asset = *a.AssetID
	}
	return a.Kind + "|" + a.ProjectID + "|" + a.Scanner + "|" + asset + "|" + a.Branch
}

// Point is one scan of a stream: when, how it ended, and how many findings it
// reported.
type Point struct {
	At     time.Time
	Failed bool
	Total  int
	Error  string
}

// Stream is one project's uploads from one scanner for one asset (default
// version), newest scan first.
type Stream struct {
	ProjectID, ProjectName, Scanner string
	AssetID                         *string
	Scans                           []Point
}

// Evaluate finds a stream's anomalies at now. Pure, for the table tests.
func Evaluate(s Stream, now time.Time) []Anomaly {
	if len(s.Scans) == 0 {
		return nil
	}
	mk := func(kind, detail string, since time.Time) Anomaly {
		return Anomaly{Kind: kind, ProjectID: s.ProjectID, ProjectName: s.ProjectName,
			Scanner: s.Scanner, AssetID: s.AssetID, Detail: detail, Since: since}
	}
	var out []Anomaly
	last := s.Scans[0]
	if last.Failed {
		out = append(out, mk(KindFailedScan, "the latest "+s.Scanner+" scan failed: "+last.Error, last.At))
	}

	// Stale: silent for several of the stream's usual gaps.
	if len(s.Scans) >= minHistory {
		var gaps []time.Duration
		for i := range min(len(s.Scans)-1, historyWindow) {
			gaps = append(gaps, s.Scans[i].At.Sub(s.Scans[i+1].At))
		}
		usual := median(gaps)
		if limit := max(staleFactor*usual, staleFloor); now.Sub(last.At) > limit {
			out = append(out, mk(KindStale, fmt.Sprintf("no %s upload for %s (usually every %s)",
				s.Scanner, round(now.Sub(last.At)), round(usual)), last.At.Add(limit)))
		}
	}

	// Volume drop: the last good scan reported far fewer findings than the ones
	// before it — the signature of a scanner that silently scanned nothing.
	var totals []int
	lastGood := -1
	for i, p := range s.Scans {
		if p.Failed {
			continue
		}
		if lastGood < 0 {
			lastGood = i
			continue
		}
		if len(totals) < 5 {
			totals = append(totals, p.Total)
		}
	}
	if lastGood >= 0 && len(totals) >= minHistory-1 {
		usual := median(totals)
		if got := s.Scans[lastGood].Total; usual >= dropMinBaseline && float64(got) < dropRatio*float64(usual) {
			out = append(out, mk(KindVolumeDrop, fmt.Sprintf("the latest %s scan reported %d findings; the previous ones ~%d",
				s.Scanner, got, usual), s.Scans[lastGood].At))
		}
	}
	return out
}

func median[T cmp.Ordered](xs []T) T {
	var zero T
	if len(xs) == 0 {
		return zero
	}
	s := slices.Clone(xs)
	slices.Sort(s)
	return s[len(s)/2]
}

func round(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
}

// Repository reads the inputs.
type Repository struct{ db *pgxpool.Pool }

// NewRepository constructs the repository.
func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

// Expectation is a declared scan cadence for a project: "scanner (or
// category) should report within max_age, on branch" — settable by the
// project owner, so Check reports a scanner that never ran, not only one
// that stopped (Evaluate needs 3+ scans of history to establish a cadence).
// Branch "" means the project's default version.
type Expectation struct {
	ID          string    `json:"id"`
	ProjectID   string    `json:"project_id"`
	Scanner     *string   `json:"scanner"`
	Category    *string   `json:"category"`
	Branch      string    `json:"branch"`
	MaxAgeHours int       `json:"max_age_hours"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ErrInvalidExpectation is returned when the expectation doesn't name exactly
// one of scanner/category, or max_age_hours isn't positive.
var ErrInvalidExpectation = errors.New("exactly one of scanner or category, and a positive max_age_hours, are required")

// ErrDuplicateExpectation is returned when the project already declares that
// scanner/category on that branch.
var ErrDuplicateExpectation = errors.New("that scanner/category and branch is already declared for this project")

// ErrNoProject is returned when an expectation names a project that doesn't exist.
var ErrNoProject = errors.New("project not found")

// Validate checks the expectation is well formed.
func (e Expectation) Validate() error {
	if (e.Scanner == nil) == (e.Category == nil) || e.MaxAgeHours < 1 {
		return ErrInvalidExpectation
	}
	return nil
}

const expectationColumns = `id, project_id, scanner, category, branch, max_age_hours, created_at, updated_at`

func scanExpectation(row pgx.Row) (Expectation, error) {
	var e Expectation
	err := row.Scan(&e.ID, &e.ProjectID, &e.Scanner, &e.Category, &e.Branch, &e.MaxAgeHours, &e.CreatedAt, &e.UpdatedAt)
	return e, err
}

// ListExpectations returns a project's declared scan expectations, oldest first.
func (r *Repository) ListExpectations(ctx context.Context, projectID string) ([]Expectation, error) {
	rows, err := r.db.Query(ctx,
		`SELECT `+expectationColumns+` FROM project_scan_expectations WHERE project_id = $1 ORDER BY created_at`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list scan expectations: %w", err)
	}
	defer rows.Close()
	out := []Expectation{}
	for rows.Next() {
		e, err := scanExpectation(rows)
		if err != nil {
			return nil, fmt.Errorf("scan expectation: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// CreateExpectation stores a new expectation for a project.
func (r *Repository) CreateExpectation(ctx context.Context, e Expectation) (Expectation, error) {
	if err := e.Validate(); err != nil {
		return Expectation{}, err
	}
	out, err := scanExpectation(r.db.QueryRow(ctx, `
		INSERT INTO project_scan_expectations (project_id, scanner, category, branch, max_age_hours)
		VALUES ($1, $2, $3, $4, $5) RETURNING `+expectationColumns,
		e.ProjectID, e.Scanner, e.Category, e.Branch, e.MaxAgeHours))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23503":
			return Expectation{}, ErrNoProject
		case "23505":
			return Expectation{}, ErrDuplicateExpectation
		}
	}
	if err != nil {
		return Expectation{}, fmt.Errorf("create scan expectation: %w", err)
	}
	return out, nil
}

// DeleteExpectation removes a project's expectation; ok is false when it
// didn't exist for that project.
func (r *Repository) DeleteExpectation(ctx context.Context, projectID, id string) (bool, error) {
	tag, err := r.db.Exec(ctx, `DELETE FROM project_scan_expectations WHERE id = $1 AND project_id = $2`, id, projectID)
	if err != nil {
		return false, fmt.Errorf("delete scan expectation: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// Check lists every anomaly in scope (nil = all projects), project first.
// Synthetic producers (advisory matching, policies) run on Xila's own
// schedule and aren't watched; connectors are watched by their own status.
func (r *Repository) Check(ctx context.Context, scope []string, now time.Time) ([]Anomaly, error) {
	rows, err := r.db.Query(ctx, `
		SELECT s.project_id, p.name, s.scanner, s.asset_id, s.status = 'failed', s.created_at,
		       (SELECT COALESCE(sum(value::int), 0) FROM jsonb_each_text(s.summary)), s.error
		FROM (SELECT *, row_number() OVER (PARTITION BY project_id, scanner, asset_id ORDER BY created_at DESC, id DESC) AS rn
		      FROM scans
		      WHERE status IN ('completed', 'failed') AND scanner NOT IN ('osv', 'policy')
		        AND version_id IN (SELECT id FROM project_versions WHERE is_default)
		        AND`+archive.Scan("")+`
		        AND ($1::uuid[] IS NULL OR project_id = ANY($1))) s
		JOIN projects p ON p.id = s.project_id
		WHERE s.rn <= $2
		ORDER BY p.name, s.project_id, s.scanner, s.asset_id NULLS FIRST, s.created_at DESC`, scope, historyWindow+1)
	if err != nil {
		return nil, fmt.Errorf("ingest health scans: %w", err)
	}
	var out []Anomaly
	var cur *Stream
	flush := func() {
		if cur != nil {
			out = append(out, Evaluate(*cur, now)...)
		}
	}
	for rows.Next() {
		var st Stream
		var p Point
		if err := rows.Scan(&st.ProjectID, &st.ProjectName, &st.Scanner, &st.AssetID, &p.Failed, &p.At, &p.Total, &p.Error); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan ingest health: %w", err)
		}
		if cur == nil || cur.ProjectID != st.ProjectID || cur.Scanner != st.Scanner || !sameAsset(cur.AssetID, st.AssetID) {
			flush()
			cur = &st
		}
		cur.Scans = append(cur.Scans, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("ingest health scans: %w", err)
	}
	flush()

	// Connectors whose last pull failed (none succeeded since).
	crow, err := r.db.Query(ctx, `
		SELECT c.project_id, p.name, c.name, c.last_error, c.last_pulled_at
		FROM connectors c JOIN projects p ON p.id = c.project_id
		WHERE c.enabled AND c.last_error <> '' AND c.last_pulled_at IS NOT NULL
		  AND (c.last_success_at IS NULL OR c.last_success_at < c.last_pulled_at)
		  AND ($1::uuid[] IS NULL OR c.project_id = ANY($1))`, scope)
	if err != nil {
		return nil, fmt.Errorf("ingest health connectors: %w", err)
	}
	for crow.Next() {
		var a Anomaly
		var name, msg string
		if err := crow.Scan(&a.ProjectID, &a.ProjectName, &name, &msg, &a.Since); err != nil {
			crow.Close()
			return nil, fmt.Errorf("scan connector: %w", err)
		}
		a.Kind, a.Scanner, a.Detail = KindConnectorFailing, name, "connector "+name+" failed its last pull: "+msg
		out = append(out, a)
	}
	crow.Close()
	if err := crow.Err(); err != nil {
		return nil, err
	}

	// Ingest jobs that exhausted their retries recently.
	jrow, err := r.db.Query(ctx, `
		SELECT sc.project_id, p.name, count(*)::int, min(j.created_at)
		FROM scan_jobs j JOIN scans sc ON sc.id = j.scan_id JOIN projects p ON p.id = sc.project_id
		WHERE j.status = 'failed' AND j.created_at > $2::timestamptz - make_interval(secs => $3)
		  AND ($1::uuid[] IS NULL OR sc.project_id = ANY($1))
		GROUP BY sc.project_id, p.name`, scope, now, failedJobWindow.Seconds())
	if err != nil {
		return nil, fmt.Errorf("ingest health jobs: %w", err)
	}
	for jrow.Next() {
		var a Anomaly
		var n int
		if err := jrow.Scan(&a.ProjectID, &a.ProjectName, &n, &a.Since); err != nil {
			jrow.Close()
			return nil, fmt.Errorf("scan jobs: %w", err)
		}
		a.Kind, a.Detail = KindFailedJobs, fmt.Sprintf("%d upload(s) failed to ingest in the last 7 days", n)
		out = append(out, a)
	}
	jrow.Close()
	if err := jrow.Err(); err != nil {
		return nil, fmt.Errorf("ingest health jobs: %w", err)
	}

	// Declared scan expectations with no completed scan within their window
	// (including one that has never run).
	erow, err := r.db.Query(ctx, `
		SELECT e.project_id, p.name, e.scanner, e.category, e.branch, e.max_age_hours,
		       (SELECT max(s.finished_at) FROM scans s
		        WHERE s.project_id = e.project_id AND s.status = 'completed'
		          AND (e.scanner IS NULL OR s.scanner = e.scanner)
		          AND (e.category IS NULL OR s.category = e.category)
		          AND (CASE WHEN e.branch = '' THEN s.version_id IN (
		                        SELECT id FROM project_versions WHERE project_id = e.project_id AND is_default)
		                    ELSE s.branch = e.branch END))
		FROM project_scan_expectations e JOIN projects p ON p.id = e.project_id
		WHERE ($1::uuid[] IS NULL OR e.project_id = ANY($1))`, scope)
	if err != nil {
		return nil, fmt.Errorf("ingest health expectations: %w", err)
	}
	defer erow.Close()
	for erow.Next() {
		var a Anomaly
		var scanner, category *string
		var maxAgeHours int
		var lastOK *time.Time
		if err := erow.Scan(&a.ProjectID, &a.ProjectName, &scanner, &category, &a.Branch, &maxAgeHours, &lastOK); err != nil {
			return nil, fmt.Errorf("scan expectation: %w", err)
		}
		limit := time.Duration(maxAgeHours) * time.Hour
		if lastOK != nil && now.Sub(*lastOK) <= limit {
			continue // satisfied
		}
		what := "category " + *category
		if scanner != nil {
			what, a.Scanner = *scanner, *scanner
		} else {
			a.Scanner = "category:" + *category
		}
		branchLabel := a.Branch
		if branchLabel == "" {
			branchLabel = "the default version"
		}
		a.Kind = KindMissing
		if lastOK == nil {
			a.Detail = fmt.Sprintf("expected %s on %s within %s: none has ever completed", what, branchLabel, round(limit))
			a.Since = now
		} else {
			a.Detail = fmt.Sprintf("expected %s on %s within %s: last completed %s ago",
				what, branchLabel, round(limit), round(now.Sub(*lastOK)))
			a.Since = lastOK.Add(limit)
		}
		out = append(out, a)
	}
	if err := erow.Err(); err != nil {
		return nil, fmt.Errorf("ingest health expectations: %w", err)
	}

	if out == nil {
		out = []Anomaly{}
	}
	return out, nil
}

func sameAsset(a, b *string) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

// Notifier queues alerts (notify.Service).
type Notifier interface {
	Notify(ctx context.Context, e notify.Event)
}

// Sweep compares the anomalies now with the open ones it recorded: each new
// one is alerted once (ingestion.anomaly), cleared ones are forgotten (and
// alert again if they come back). Leader-only.
func (r *Repository) Sweep(ctx context.Context, n Notifier, now time.Time) (int, error) {
	current, err := r.Check(ctx, nil, now)
	if err != nil {
		return 0, err
	}
	keys := make([]string, len(current))
	for i, a := range current {
		keys[i] = a.Key()
	}
	if _, err := r.db.Exec(ctx, `DELETE FROM ingestion_anomalies WHERE NOT (key = ANY($1))`, keys); err != nil {
		return 0, fmt.Errorf("clear anomalies: %w", err)
	}
	alerted := 0
	for _, a := range current {
		tag, err := r.db.Exec(ctx, `INSERT INTO ingestion_anomalies (key, project_id, kind, detail) VALUES ($1, $2, $3, $4)
			ON CONFLICT (key) DO NOTHING`, a.Key(), a.ProjectID, a.Kind, a.Detail)
		if err != nil {
			return alerted, fmt.Errorf("record anomaly: %w", err)
		}
		if tag.RowsAffected() == 0 {
			continue // already known
		}
		alerted++
		fields := map[string]string{"kind": a.Kind, "project": a.ProjectName}
		if a.Scanner != "" {
			fields["source"] = a.Scanner
		}
		n.Notify(ctx, notify.Event{
			Type: notify.EventIngestionAnomaly, Title: "Ingestion problem in " + a.ProjectName,
			Text: a.Detail, ProjectID: a.ProjectID, Fields: fields,
		})
	}
	return alerted, nil
}

// RunSweep checks hourly until ctx ends.
func (r *Repository) RunSweep(ctx context.Context, n Notifier) {
	tick := time.NewTicker(time.Hour)
	defer tick.Stop()
	for {
		if k, err := r.Sweep(ctx, n, time.Now()); err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "ingestion health sweep failed", "error", err)
		} else if k > 0 {
			slog.InfoContext(ctx, "ingestion health: new anomalies", "count", k)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Handler serves the live view.
type Handler struct{ repo *Repository }

// NewHandler constructs the handler.
func NewHandler(repo *Repository) *Handler { return &Handler{repo: repo} }

// Register mounts GET /ingestion-health (the caller's projects),
// GET /projects/{id}/ingestion-health, and a project's declared scan
// expectations (listing needs viewer; declaring/removing one is owner-level,
// gated by authz like an SLA — see internal/authz).
func (h *Handler) Register(r fiber.Router) {
	r.Get("/ingestion-health", h.list)
	r.Get("/projects/:projectID/ingestion-health", h.project)
	r.Get("/projects/:projectID/scan-expectations", h.listExpectations)
	r.Post("/projects/:projectID/scan-expectations", h.createExpectation)
	r.Delete("/projects/:projectID/scan-expectations/:expectationID", h.deleteExpectation)
}

func (h *Handler) list(c *fiber.Ctx) error {
	var scope []string
	if s := authz.VisibleScope(c); !s.AllAccess {
		scope = s.ProjectIDs
		if scope == nil {
			scope = []string{}
		}
	}
	out, err := h.repo.Check(c.UserContext(), scope, time.Now())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"anomalies": out})
}

func (h *Handler) project(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	out, err := h.repo.Check(c.UserContext(), []string{id}, time.Now())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"anomalies": out})
}

func (h *Handler) listExpectations(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	out, err := h.repo.ListExpectations(c.UserContext(), id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"expectations": out})
}

type expectationRequest struct {
	Scanner     *string `json:"scanner"`
	Category    *string `json:"category"`
	Branch      string  `json:"branch"`
	MaxAgeHours int     `json:"max_age_hours"`
}

// createExpectation handles POST /projects/{id}/scan-expectations: declare a
// scanner (or category) that should report within max_age_hours on branch
// ("" = the project's default version).
func (h *Handler) createExpectation(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var req expectationRequest
	if err := httpx.Parse(c, &req); err != nil {
		return err
	}
	out, err := h.repo.CreateExpectation(c.UserContext(), Expectation{
		ProjectID: id, Scanner: req.Scanner, Category: req.Category, Branch: req.Branch, MaxAgeHours: req.MaxAgeHours,
	})
	switch {
	case errors.Is(err, ErrInvalidExpectation):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, ErrDuplicateExpectation):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	case errors.Is(err, ErrNoProject):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	case err != nil:
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

// deleteExpectation handles DELETE /projects/{id}/scan-expectations/{expectationID}.
func (h *Handler) deleteExpectation(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	expectationID, err := httpx.ID(c, "expectationID")
	if err != nil {
		return err
	}
	ok, err := h.repo.DeleteExpectation(c.UserContext(), projectID, expectationID)
	if err != nil {
		return err
	}
	if !ok {
		return fiber.NewError(fiber.StatusNotFound, "scan expectation not found")
	}
	return c.SendStatus(fiber.StatusNoContent)
}
