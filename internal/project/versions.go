package project

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/httpx"
)

// ErrVersionNotFound is returned when a project version does not exist.
var ErrVersionNotFound = errors.New("version not found")

// ErrDefaultVersion is returned when deleting a project's default version.
var ErrDefaultVersion = errors.New("the default version cannot be deleted; make another version the default first")

// Version is a branch or release of a project. Scans, SBOMs and findings belong
// to exactly one; the default version is what metrics, summaries, alerts and
// gates report.
type Version struct {
	ID         string     `json:"id"`
	ProjectID  string     `json:"project_id"`
	Name       string     `json:"name"`
	Kind       string     `json:"kind"` // "branch" | "release"
	IsDefault  bool       `json:"is_default"`
	CreatedAt  time.Time  `json:"created_at"`
	LastScanAt *time.Time `json:"last_scan_at"`
	OpenCount  int        `json:"open_findings"`
	ScanCount  int        `json:"scans"`
	SbomCount  int        `json:"sboms"`
}

var versionSelect = `
	SELECT v.id, v.project_id, v.name, v.kind, v.is_default, v.created_at,
	       (SELECT max(created_at) FROM scans s WHERE s.version_id = v.id AND` + archive.Scan("s") + `),
	       (SELECT count(*) FROM findings f WHERE f.version_id = v.id
	          AND f.status IN ('open', 'confirmed') AND f.duplicate_of IS NULL AND` + archive.Finding("f") + `),
	       (SELECT count(*) FROM scans s WHERE s.version_id = v.id AND` + archive.Scan("s") + `),
	       (SELECT count(*) FROM sboms s WHERE s.version_id = v.id)
	FROM project_versions v`

func scanVersion(row pgx.Row) (Version, error) {
	var v Version
	err := row.Scan(&v.ID, &v.ProjectID, &v.Name, &v.Kind, &v.IsDefault, &v.CreatedAt,
		&v.LastScanAt, &v.OpenCount, &v.ScanCount, &v.SbomCount)
	return v, err
}

// ListVersions returns a project's versions: the default first, then by most
// recent activity.
func (r *Repository) ListVersions(ctx context.Context, projectID string) ([]Version, error) {
	rows, err := r.db.Query(ctx, versionSelect+`
		WHERE v.project_id = $1
		ORDER BY v.is_default DESC, (SELECT max(created_at) FROM scans s WHERE s.version_id = v.id) DESC NULLS LAST, v.name`,
		projectID)
	if err != nil {
		return nil, fmt.Errorf("list versions: %w", err)
	}
	defer rows.Close()
	out := []Version{}
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, fmt.Errorf("scan version: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// GetVersion returns one version of a project.
func (r *Repository) GetVersion(ctx context.Context, projectID, versionID string) (Version, error) {
	v, err := scanVersion(r.db.QueryRow(ctx, versionSelect+` WHERE v.project_id = $1 AND v.id = $2`, projectID, versionID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Version{}, ErrVersionNotFound
	}
	if err != nil {
		return Version{}, fmt.Errorf("get version: %w", err)
	}
	return v, nil
}

// FindVersion looks up a project's version by name without creating it. An
// empty name means the default version.
func (r *Repository) FindVersion(ctx context.Context, projectID, name string) (string, bool, error) {
	var id string
	err := r.db.QueryRow(ctx, `SELECT id FROM project_versions WHERE project_id = $1
		AND (($2 = '' AND is_default) OR name = $2)`, projectID, name).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("find version: %w", err)
	}
	return id, true, nil
}

// SetDefaultVersion makes a version the project's default. Both writes happen in
// one transaction so the project is never without (or with two) defaults.
func (r *Repository) SetDefaultVersion(ctx context.Context, projectID, versionID string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM project_versions WHERE project_id = $1 AND id = $2)`,
		projectID, versionID).Scan(&exists); err != nil {
		return fmt.Errorf("set default version: %w", err)
	}
	if !exists {
		return ErrVersionNotFound
	}
	if _, err := tx.Exec(ctx, `UPDATE project_versions SET is_default = false WHERE project_id = $1 AND is_default AND id <> $2`,
		projectID, versionID); err != nil {
		return fmt.Errorf("clear default version: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE project_versions SET is_default = true WHERE id = $1`, versionID); err != nil {
		return fmt.Errorf("set default version: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// DeleteVersion removes a non-default version with everything on it (scans,
// SBOMs, findings).
func (r *Repository) DeleteVersion(ctx context.Context, projectID, versionID string) error {
	var isDefault bool
	err := r.db.QueryRow(ctx, `DELETE FROM project_versions WHERE project_id = $1 AND id = $2 AND NOT is_default
		RETURNING false`, projectID, versionID).Scan(&isDefault)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, gerr := r.GetVersion(ctx, projectID, versionID); gerr == nil {
			return ErrDefaultVersion
		}
		return ErrVersionNotFound
	}
	if err != nil {
		return fmt.Errorf("delete version: %w", err)
	}
	return nil
}

// Version kinds.
const (
	KindBranch  = "branch"
	KindRelease = "release"
)

// PruneStaleVersions deletes versions of one kind (never the default) whose
// last scan or SBOM — or, with neither, their creation — is older than
// maxAge, with their findings and SBOMs: merged or abandoned feature branches,
// or long-dead release lines. Returns how many went.
func (r *Repository) PruneStaleVersions(ctx context.Context, kind string, maxAge time.Duration) (int64, error) {
	tag, err := r.db.Exec(ctx, `
		DELETE FROM project_versions v
		WHERE v.kind = $1 AND NOT v.is_default
		  AND GREATEST(v.created_at,
		               (SELECT max(created_at) FROM scans s WHERE s.version_id = v.id),
		               (SELECT max(created_at) FROM sboms s WHERE s.version_id = v.id))
		      < now() - make_interval(secs => $2)`, kind, maxAge.Seconds())
	if err != nil {
		return 0, fmt.Errorf("prune stale %s versions: %w", kind, err)
	}
	return tag.RowsAffected(), nil
}

// --- HTTP ---

// ListVersions handles GET /projects/{id}/versions.
func (h *Handler) ListVersions(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	vs, err := h.repo.ListVersions(c.UserContext(), id)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"versions": vs})
}

type updateVersionRequest struct {
	IsDefault *bool `json:"is_default"`
}

// UpdateVersion handles PATCH /projects/{id}/versions/{versionID}: make it the
// default (the only mutable property — a version is named by its scans).
func (h *Handler) UpdateVersion(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	versionID, err := httpx.ID(c, "versionID")
	if err != nil {
		return err
	}
	var body updateVersionRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	if body.IsDefault == nil || !*body.IsDefault {
		return fiber.NewError(fiber.StatusBadRequest, "set is_default: true on the version that should become the default")
	}
	if err := h.repo.SetDefaultVersion(c.UserContext(), projectID, versionID); errors.Is(err, ErrVersionNotFound) {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	} else if err != nil {
		return err
	}
	v, err := h.repo.GetVersion(c.UserContext(), projectID, versionID)
	if err != nil {
		return err
	}
	return c.JSON(v)
}

// DeleteVersion handles DELETE /projects/{id}/versions/{versionID}.
func (h *Handler) DeleteVersion(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	versionID, err := httpx.ID(c, "versionID")
	if err != nil {
		return err
	}
	switch err := h.repo.DeleteVersion(c.UserContext(), projectID, versionID); {
	case errors.Is(err, ErrVersionNotFound):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	case errors.Is(err, ErrDefaultVersion):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	case err != nil:
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}
