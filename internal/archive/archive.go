// Package archive is "archive instead of delete" for projects, engagements,
// scans and findings. An archived record keeps its rows but drops out of every
// list, count, dedup election, gate, SLA sweep, notification and portfolio
// rollup; it can be restored within the retention window, after which the
// retention job purges it for real.
//
// Liveness has one definition per entity, the SQL fragments below. Every query
// that lists or counts one of these entities appends its fragment next to its
// other row rules (duplicate_of IS NULL, the default version), the way
// onDefaultVersion is used. A child record (engagement, scan, finding) of an
// archived project is archived *through* the project — the fragment reads the
// project — so archiving or restoring a project writes one row.
package archive

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Kind is an archivable entity.
type Kind string

// The archivable entities.
const (
	KindProject    Kind = "project"
	KindEngagement Kind = "engagement"
	KindScan       Kind = "scan"
	KindFinding    Kind = "finding"
)

// Errors.
var (
	ErrNotFound    = errors.New("not found")
	ErrNotArchived = errors.New("not archived")
	// ErrExpired is a record archived longer ago than the retention window: it
	// is due for purging and can no longer be restored.
	ErrExpired = errors.New("archived past the retention window; it can no longer be restored")
)

func col(alias, name string) string {
	if alias == "" {
		return name
	}
	return alias + "." + name
}

// archivedProjects selects the ids of archived projects (uncorrelated, so the
// planner hashes it once per query).
const archivedProjects = `(SELECT id FROM projects WHERE archived_at IS NOT NULL)`

// child is the liveness of a project-owned row: neither it nor its project is
// archived.
func child(alias string) string {
	return " " + col(alias, "archived_at") + " IS NULL AND " + col(alias, "project_id") + " NOT IN " + archivedProjects
}

// Project is the condition "this projects row is live"; alias is the table
// alias in the query ("" = unqualified). Like every fragment it starts with a
// space: `q += " AND" + archive.Project("p")`.
func Project(alias string) string { return " " + col(alias, "archived_at") + " IS NULL" }

// Engagement is the condition "this engagements row is live".
func Engagement(alias string) string { return child(alias) }

// Scan is the condition "this scans row is live".
func Scan(alias string) string { return child(alias) }

// Finding is the condition "this findings row is live": neither the finding
// (directly, or with the scan that alone reported it) nor its project is
// archived.
func Finding(alias string) string { return child(alias) }

// Only selects live rows, or with archived the archived ones (the
// `?archived=true` listings): `q += " AND" + archive.Only(archive.Scan(""), archived)`.
func Only(live string, archived bool) string {
	if archived {
		return " NOT (" + live + ")"
	}
	return live
}

// Repository archives, restores and purges records.
type Repository struct{ db *pgxpool.Pool }

// NewRepository constructs the repository.
func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

var tables = map[Kind]struct{ table, project string }{
	KindProject:    {"projects", "id"},
	KindEngagement: {"engagements", "project_id"},
	KindScan:       {"scans", "project_id"},
	KindFinding:    {"findings", "project_id"},
}

// state locks one record and reads its project and archive stamp.
func state(ctx context.Context, tx pgx.Tx, kind Kind, id string) (projectID string, archivedAt *time.Time, err error) {
	t, ok := tables[kind]
	if !ok {
		return "", nil, fmt.Errorf("archive: unknown kind %q", kind)
	}
	err = tx.QueryRow(ctx, `SELECT `+t.project+`, archived_at FROM `+t.table+` WHERE id = $1 FOR UPDATE`, id).Scan(&projectID, &archivedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, ErrNotFound
	}
	if err != nil {
		return "", nil, fmt.Errorf("archive %s: %w", kind, err)
	}
	return projectID, archivedAt, nil
}

// archiveTx archives one record (a no-op if it already is). A scan takes with
// it the findings it was the only live reporter of: its findings (last_scan_id)
// not also reported by another live scan. The only other reporter a finding
// records is the scan that first reported it, so "another live scan" is a
// different, unarchived first_scan_id. They share the scan's archived_at,
// which is how a restore finds them again.
func archiveTx(ctx context.Context, tx pgx.Tx, kind Kind, id, actor string) (string, error) {
	pid, at, err := state(ctx, tx, kind, id)
	if err != nil || at != nil {
		return pid, err
	}
	if _, err := tx.Exec(ctx, `UPDATE `+tables[kind].table+` SET archived_at = now(), archived_by = NULLIF($2, '')::uuid WHERE id = $1`,
		id, actor); err != nil {
		return "", fmt.Errorf("archive %s: %w", kind, err)
	}
	if kind == KindScan {
		if _, err := tx.Exec(ctx, `
			UPDATE findings f SET archived_at = now(), archived_by = NULLIF($2, '')::uuid
			WHERE f.last_scan_id = $1 AND f.archived_at IS NULL
			  AND NOT EXISTS (SELECT 1 FROM scans o WHERE o.id = f.first_scan_id AND o.id <> $1 AND o.archived_at IS NULL)`,
			id, actor); err != nil {
			return "", fmt.Errorf("archive scan findings: %w", err)
		}
	}
	return pid, nil
}

// Archive archives one record and returns its project. Archiving an archived
// record keeps its original stamp.
func (r *Repository) Archive(ctx context.Context, kind Kind, id, actor string) (string, error) {
	return r.inTx(ctx, func(tx pgx.Tx) (string, error) { return archiveTx(ctx, tx, kind, id, actor) })
}

// Restore brings an archived record back, refusing one archived longer ago
// than window (0 = no limit). A scan brings back the findings archived with
// it. Findings archived through their project need nothing: restoring the
// project restores them.
func (r *Repository) Restore(ctx context.Context, kind Kind, id string, window time.Duration) (string, error) {
	return r.inTx(ctx, func(tx pgx.Tx) (string, error) {
		pid, at, err := state(ctx, tx, kind, id)
		if err != nil {
			return "", err
		}
		if at == nil {
			return "", ErrNotArchived
		}
		if window > 0 && time.Since(*at) > window {
			return "", ErrExpired
		}
		if _, err := tx.Exec(ctx, `UPDATE `+tables[kind].table+` SET archived_at = NULL, archived_by = NULL WHERE id = $1`, id); err != nil {
			return "", fmt.Errorf("restore %s: %w", kind, err)
		}
		if kind == KindScan {
			if _, err := tx.Exec(ctx, `UPDATE findings SET archived_at = NULL, archived_by = NULL
				WHERE last_scan_id = $1 AND archived_at = $2`, id, *at); err != nil {
				return "", fmt.Errorf("restore scan findings: %w", err)
			}
		}
		return pid, nil
	})
}

// Purge deletes one record for good through its table's delete path (a
// project cascades to everything it owns; an engagement's scans stay with the
// project). A scan is archived first, so the findings only it reported go with
// it rather than lingering without a scan.
func (r *Repository) Purge(ctx context.Context, kind Kind, id, actor string) (string, error) {
	return r.inTx(ctx, func(tx pgx.Tx) (string, error) {
		pid, err := archiveTx(ctx, tx, kind, id, actor)
		if err != nil {
			return "", err
		}
		if kind == KindScan {
			if _, err := tx.Exec(ctx, `DELETE FROM findings WHERE last_scan_id = $1 AND archived_at IS NOT NULL`, id); err != nil {
				return "", fmt.Errorf("purge scan findings: %w", err)
			}
		}
		if _, err := tx.Exec(ctx, `DELETE FROM `+tables[kind].table+` WHERE id = $1`, id); err != nil {
			return "", fmt.Errorf("purge %s: %w", kind, err)
		}
		return pid, nil
	})
}

// Purged counts what PurgeExpired deleted.
type Purged struct {
	Projects    int64
	Engagements int64
	Scans       int64
	Findings    int64
}

// PurgeExpired deletes every record archived longer ago than age — children
// first, so a scan's findings go in the findings step and a project's
// remaining rows in its cascade.
func (r *Repository) PurgeExpired(ctx context.Context, age time.Duration) (Purged, error) {
	var p Purged
	for _, step := range []struct {
		table string
		n     *int64
	}{{"findings", &p.Findings}, {"scans", &p.Scans}, {"engagements", &p.Engagements}, {"projects", &p.Projects}} {
		tag, err := r.db.Exec(ctx, `DELETE FROM `+step.table+` WHERE archived_at < now() - make_interval(secs => $1)`, age.Seconds())
		if err != nil {
			return p, fmt.Errorf("purge archived %s: %w", step.table, err)
		}
		*step.n = tag.RowsAffected()
	}
	return p, nil
}

func (r *Repository) inTx(ctx context.Context, fn func(pgx.Tx) (string, error)) (string, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	pid, err := fn(tx)
	if err != nil {
		return "", err
	}
	return pid, tx.Commit(ctx)
}
