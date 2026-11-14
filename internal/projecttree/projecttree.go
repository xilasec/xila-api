// Package projecttree resolves the projects a rollup covers. A project may
// have children (projects.parent_id, at most MaxDepth levels, same org, no
// cycles — all enforced by the projects_hierarchy trigger); a rollup over a
// project with ?include_children=true covers it and every descendant. The
// result is the project-id set the existing per-project queries already
// filter on, so a rollup is the same SQL over a wider set, never a second
// query style.
package projecttree

import (
	"context"
	"fmt"
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"

	"github.com/xilasec/xila-api/internal/auth"
)

// MaxDepth is how many levels a project tree may have (a root is level 1).
// The projects_hierarchy trigger (migration 000073) enforces it.
const MaxDepth = 5

// Querier runs one query (a pool or a transaction).
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// subtreeSQL is the project $1 and — when $2 is true, or $2 is NULL and the
// project is a collection — every descendant.
const subtreeSQL = `
	SELECT COALESCE(array_agg(s.descendant_id::text ORDER BY s.depth, s.descendant_id), '{}')
	FROM projects p CROSS JOIN LATERAL project_subtree(p.id) s
	WHERE p.id = $1 AND (s.depth = 0 OR COALESCE($2::boolean, p.is_collection))`

// IncludeChildren parses ?include_children=: nil when absent (the project
// decides: a collection includes its children, anything else doesn't).
func IncludeChildren(c *fiber.Ctx) (*bool, error) {
	raw := c.Query("include_children")
	if raw == "" {
		return nil, nil
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusBadRequest, "include_children must be true or false")
	}
	return &v, nil
}

// Rollup returns the project ids a request on projectID covers: the project
// itself, plus every descendant when ?include_children= says so (default:
// true for a collection). Every descendant is visible to whoever may read the
// project — grants inherit down the tree — except to an actor confined to one
// project (a project-scoped token or federated session), which never reaches
// past that project.
func Rollup(c *fiber.Ctx, q Querier, projectID string) ([]string, error) {
	include, err := IncludeChildren(c)
	if err != nil {
		return nil, err
	}
	if auth.CurrentActor(c).ProjectID != "" {
		return []string{projectID}, nil
	}
	return Subtree(c.UserContext(), q, projectID, include)
}

// Subtree returns projectID followed by its descendants (nearest first) when
// include is true — or nil and the project is a collection — else just
// projectID.
func Subtree(ctx context.Context, q Querier, projectID string, include *bool) ([]string, error) {
	var ids []string
	if err := q.QueryRow(ctx, subtreeSQL, projectID, include).Scan(&ids); err != nil {
		return nil, fmt.Errorf("project subtree: %w", err)
	}
	if len(ids) == 0 {
		return []string{projectID}, nil // no such project: the caller 404s as before
	}
	return ids, nil
}
