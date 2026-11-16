// Package retention is housekeeping: it deletes data past its configured
// lifetime so a long-running instance doesn't grow without bound. Every rule
// that deletes analysis data is off unless configured (deleting is a decision,
// not a default), and none can touch what the live views and lifecycle depend
// on: a version's current SBOM snapshots, a finding's last scan, the latest
// scan of a scan target (auto-close compares against it), or the default
// version of a project.
package retention

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/observability"
	"github.com/xilasec/xila-api/internal/project"
)

// Policy is what to keep. Zero values mean "keep forever".
type Policy struct {
	// BranchAge / ReleaseAge prune non-default branch / release versions (with
	// their findings and SBOMs) with no scan or SBOM for this long.
	BranchAge  time.Duration
	ReleaseAge time.Duration
	// SBOMKeep keeps the newest N snapshots of each artifact per version;
	// SBOMAge deletes older ones only once they're this old. Either alone works;
	// the newest snapshot is never deleted.
	SBOMKeep int
	SBOMAge  time.Duration
	// ScanAge deletes scan records older than this, except a finding's last
	// scan and the latest scan of each scan target.
	ScanAge time.Duration
	// LogAge deletes notification delivery-log entries and failed ingest jobs
	// (which hold the uploaded report, or its payload_ref object — see
	// payloadDeleter) older than this.
	LogAge time.Duration
	// AuditAge deletes audit log entries older than this, through the one
	// path the log's append-only trigger allows (audit_log_purge).
	AuditAge time.Duration
	// ArchiveAge purges projects, engagements, scans and findings archived
	// longer ago than this (internal/archive); until then they can be restored.
	ArchiveAge time.Duration
}

// Result counts what one run deleted.
type Result struct {
	Branches      int64 `json:"branches"`
	Releases      int64 `json:"releases"`
	SBOMSnapshots int64 `json:"sbom_snapshots"`
	Scans         int64 `json:"scans"`
	Deliveries    int64 `json:"deliveries"`
	FailedJobs    int64 `json:"failed_jobs"`
	AuditEntries  int64 `json:"audit_entries"`
	// Archived records purged past ARCHIVE_RETENTION.
	ArchivedProjects    int64 `json:"archived_projects"`
	ArchivedEngagements int64 `json:"archived_engagements"`
	ArchivedScans       int64 `json:"archived_scans"`
	ArchivedFindings    int64 `json:"archived_findings"`
}

func (r Result) total() int64 {
	return r.Branches + r.Releases + r.SBOMSnapshots + r.Scans + r.Deliveries + r.FailedJobs + r.AuditEntries +
		r.ArchivedProjects + r.ArchivedEngagements + r.ArchivedScans + r.ArchivedFindings
}

// versionPruner deletes stale versions (project.Repository).
type versionPruner interface {
	PruneStaleVersions(ctx context.Context, kind string, maxAge time.Duration) (int64, error)
}

// payloadDeleter removes an object-store payload a purged failed job
// referenced (internal/objectstore.Client satisfies it structurally). Nil
// when INGEST_PAYLOAD_STORE=postgres, since nothing lives outside the row.
type payloadDeleter interface {
	Delete(ctx context.Context, key string) error
}

// Service applies a Policy.
type Service struct {
	db       *pgxpool.Pool
	versions versionPruner
	archived *archive.Repository
	policy   Policy
	payloads payloadDeleter
}

// NewService constructs the housekeeper. payloads may be nil (postgres
// payload store: nothing to clean up outside scan_jobs itself).
func NewService(db *pgxpool.Pool, versions versionPruner, p Policy, payloads payloadDeleter) *Service {
	return &Service{db: db, versions: versions, archived: archive.NewRepository(db), policy: p, payloads: payloads}
}

// Policy returns the configured policy.
func (s *Service) Policy() Policy { return s.policy }

// Run applies every configured rule once. A failing rule doesn't stop the
// others; their errors are reported together with what was done.
func (s *Service) Run(ctx context.Context) (Result, error) {
	p := s.policy
	var res Result
	var errs []error
	step := func(name string, enabled bool, n *int64, fn func() (int64, error)) {
		if !enabled {
			return
		}
		got, err := fn()
		*n += got
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	step("branches", p.BranchAge > 0, &res.Branches, func() (int64, error) {
		return s.versions.PruneStaleVersions(ctx, project.KindBranch, p.BranchAge)
	})
	step("releases", p.ReleaseAge > 0, &res.Releases, func() (int64, error) {
		return s.versions.PruneStaleVersions(ctx, project.KindRelease, p.ReleaseAge)
	})
	step("sbom snapshots", p.SBOMKeep > 0 || p.SBOMAge > 0, &res.SBOMSnapshots, func() (int64, error) { return s.pruneSBOMs(ctx) })
	step("scans", p.ScanAge > 0, &res.Scans, func() (int64, error) { return s.pruneScans(ctx) })
	step("delivery log", p.LogAge > 0, &res.Deliveries, func() (int64, error) {
		return s.exec(ctx, `DELETE FROM notification_deliveries WHERE created_at < now() - make_interval(secs => $1)`, p.LogAge.Seconds())
	})
	step("failed ingest jobs", p.LogAge > 0, &res.FailedJobs, func() (int64, error) {
		return s.pruneFailedJobs(ctx, p.LogAge)
	})
	if p.ArchiveAge > 0 {
		// Through the same delete paths an explicit purge takes.
		got, err := s.archived.PurgeExpired(ctx, p.ArchiveAge)
		res.ArchivedProjects, res.ArchivedEngagements, res.ArchivedScans, res.ArchivedFindings =
			got.Projects, got.Engagements, got.Scans, got.Findings
		if err != nil {
			errs = append(errs, fmt.Errorf("archived records: %w", err))
		}
	}
	step("audit log", p.AuditAge > 0, &res.AuditEntries, func() (int64, error) {
		var n int64
		err := s.db.QueryRow(ctx, `SELECT audit_log_purge(now() - make_interval(secs => $1))`, p.AuditAge.Seconds()).Scan(&n)
		return n, err
	})
	if len(errs) > 0 {
		return res, fmt.Errorf("retention: %v", errs)
	}
	return res, nil
}

func (s *Service) exec(ctx context.Context, q string, args ...any) (int64, error) {
	tag, err := s.db.Exec(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// pruneSBOMs deletes snapshots beyond the newest SBOMKeep (at least 1) of
// their (project, version, artifact) — and, with SBOMAge, only once that old.
// Their components, dependencies and advisory matches cascade. The current
// snapshot is the newest, so findings and component views are untouched; what
// shrinks is history (timelines, snapshot diffs).
func (s *Service) pruneSBOMs(ctx context.Context) (int64, error) {
	keep := max(s.policy.SBOMKeep, 1)
	return s.exec(ctx, `
		DELETE FROM sboms WHERE id IN (
			SELECT id FROM (
				SELECT id, created_at,
				       row_number() OVER (PARTITION BY project_id, version_id, artifact ORDER BY created_at DESC, id DESC) AS n
				FROM sboms) ranked
			WHERE n > $1 AND ($2 = 0 OR created_at < now() - make_interval(secs => $2)))`,
		keep, s.policy.SBOMAge.Seconds())
}

// pruneScans deletes old scan records nothing depends on: not any finding's
// last scan (auto-close and "new this scan" read it), and not the newest scan
// of its target (version, asset, branch). A deleted scan that first reported a
// finding leaves first_scan_id empty — it only ever meant "new in that scan".
func (s *Service) pruneScans(ctx context.Context) (int64, error) {
	return s.exec(ctx, `
		DELETE FROM scans sc
		WHERE sc.created_at < now() - make_interval(secs => $1)
		  AND sc.status <> 'pending' AND sc.status <> 'processing'
		  AND NOT EXISTS (SELECT 1 FROM findings f WHERE f.last_scan_id = sc.id)
		  AND EXISTS (SELECT 1 FROM scans newer
		              WHERE newer.version_id IS NOT DISTINCT FROM sc.version_id
		                AND newer.asset_id IS NOT DISTINCT FROM sc.asset_id
		                AND newer.branch IS NOT DISTINCT FROM sc.branch
		                AND newer.created_at > sc.created_at)`,
		s.policy.ScanAge.Seconds())
}

// pruneFailedJobs deletes parked (status='failed') ingest jobs older than age
// — along with each one's payload_ref object, when INGEST_PAYLOAD_STORE=s3,
// since nothing else ever cleans those up for a job that exhausted its
// retries (a successfully processed job's object is deleted by
// scan.Service.ProcessJob; a parked one is kept, on purpose, so an operator
// can still fetch and inspect what failed, until this sweep removes it along
// with the row).
func (s *Service) pruneFailedJobs(ctx context.Context, age time.Duration) (int64, error) {
	if s.payloads != nil {
		rows, err := s.db.Query(ctx,
			`SELECT payload_ref FROM scan_jobs
			 WHERE status = 'failed' AND payload_ref IS NOT NULL
			   AND created_at < now() - make_interval(secs => $1)`,
			age.Seconds())
		if err != nil {
			return 0, fmt.Errorf("list failed job payloads: %w", err)
		}
		var refs []string
		for rows.Next() {
			var ref string
			if err := rows.Scan(&ref); err != nil {
				rows.Close()
				return 0, err
			}
			refs = append(refs, ref)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, err
		}
		for _, ref := range refs {
			if err := s.payloads.Delete(ctx, ref); err != nil {
				slog.WarnContext(ctx, "retention: delete queued payload", "ref", ref, "error", err)
			}
		}
	}
	return s.exec(ctx, `DELETE FROM scan_jobs WHERE status = 'failed' AND created_at < now() - make_interval(secs => $1)`, age.Seconds())
}

// RunEvery applies the policy daily (and once at start) until ctx ends.
// Leader-only.
func (s *Service) RunEvery(ctx context.Context, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		start := time.Now()
		res, err := s.Run(ctx)
		observability.RecordJob(ctx, "retention", start, err)
		if err != nil && ctx.Err() == nil {
			slog.WarnContext(ctx, "retention run failed", "error", err)
		}
		if res.total() > 0 {
			slog.InfoContext(ctx, "retention: deleted expired data", "branches", res.Branches, "releases", res.Releases,
				"sbom_snapshots", res.SBOMSnapshots, "scans", res.Scans, "deliveries", res.Deliveries, "failed_jobs", res.FailedJobs,
				"audit_entries", res.AuditEntries, "archived_projects", res.ArchivedProjects,
				"archived_engagements", res.ArchivedEngagements, "archived_scans", res.ArchivedScans,
				"archived_findings", res.ArchivedFindings)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// Handler exposes the policy and an on-demand run (instance admin).
type Handler struct{ svc *Service }

// NewHandler constructs the retention handler.
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Register mounts /retention (admin-only in authz).
func (h *Handler) Register(r fiber.Router) {
	r.Get("/retention", h.get)
	r.Post("/retention/run", h.run)
}

func (h *Handler) get(c *fiber.Ctx) error {
	p := h.svc.Policy()
	days := func(d time.Duration) float64 { return d.Hours() / 24 }
	return c.JSON(fiber.Map{
		"branch_days": days(p.BranchAge), "release_days": days(p.ReleaseAge),
		"sbom_keep": p.SBOMKeep, "sbom_days": days(p.SBOMAge),
		"scan_days": days(p.ScanAge), "log_days": days(p.LogAge), "audit_days": days(p.AuditAge),
		"archive_days": days(p.ArchiveAge),
	})
}

func (h *Handler) run(c *fiber.Ctx) error {
	res, err := h.svc.Run(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(res)
}
