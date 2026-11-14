// Package ingesthealth watches the data coming in, so a broken pipeline is
// noticed before its silence is mistaken for a clean bill of health: a
// scanner that stopped uploading, an upload that suddenly reports a fraction
// of what it used to (expired credentials, a scanner misconfigured to scan
// nothing), failed scans and ingest jobs, and connectors whose pulls fail.
package ingesthealth

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/gofiber/fiber/v2"
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
	Kind        string    `json:"kind"`
	ProjectID   string    `json:"project_id"`
	ProjectName string    `json:"project_name"`
	Scanner     string    `json:"scanner,omitempty"`
	AssetID     *string   `json:"asset_id,omitempty"`
	Detail      string    `json:"detail"`
	Since       time.Time `json:"since"` // when the problem became visible
}

// Key identifies an anomaly across sweeps.
func (a Anomaly) Key() string {
	asset := ""
	if a.AssetID != nil {
		asset = *a.AssetID
	}
	return a.Kind + "|" + a.ProjectID + "|" + a.Scanner + "|" + asset
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
	defer jrow.Close()
	for jrow.Next() {
		var a Anomaly
		var n int
		if err := jrow.Scan(&a.ProjectID, &a.ProjectName, &n, &a.Since); err != nil {
			return nil, fmt.Errorf("scan jobs: %w", err)
		}
		a.Kind, a.Detail = KindFailedJobs, fmt.Sprintf("%d upload(s) failed to ingest in the last 7 days", n)
		out = append(out, a)
	}
	if out == nil {
		out = []Anomaly{}
	}
	return out, jrow.Err()
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

// Register mounts GET /ingestion-health (the caller's projects) and
// GET /projects/{id}/ingestion-health.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/ingestion-health", h.list)
	r.Get("/projects/:projectID/ingestion-health", h.project)
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
