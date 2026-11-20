// Package inbox is the per-user in-app notification feed (M13 13.8): one row
// per (user, event), filled by notify.Service.Notify alongside every outbound
// channel (its Fill is called from that one place), so every current and
// future event reaches it. Recipients are the finding's assignee for
// finding.assigned, the event's resolved UserIDs for mention (comment
// @mentions), a project's watchers (project_watches) for its other events,
// and instance admins for events naming no project — each still filtered by
// project visibility and by user_notification_prefs.muted_events.
//
// Visibility is rechecked on every read, not just at write time: a user who
// lost access to an item's project (or their admin flag) stops seeing it,
// even though the row itself stays until retention purges it.
package inbox

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/membership"
	"github.com/xilasec/xila-api/internal/notify"
)

// Item is one inbox entry.
type Item struct {
	ID        string     `json:"id"`
	EventType string     `json:"event_type"`
	Title     string     `json:"title"`
	Body      string     `json:"body"`
	Link      string     `json:"link"`
	ProjectID *string    `json:"project_id"`
	FindingID *string    `json:"finding_id"`
	CreatedAt time.Time  `json:"created_at"`
	ReadAt    *time.Time `json:"read_at"`
}

// Repository is the inbox_items store.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// visibleSQL holds for an item aliased i still being visible to its i.user_id:
// an instance admin sees everything, including a project-less (global/system)
// item; everyone else needs a live grant on i.project_id. Same rule personal
// notification delivery re-checks (notify.personalAccessSQL).
const visibleSQL = `EXISTS (
	SELECT 1 FROM users au WHERE au.id = i.user_id AND (
		au.is_admin OR (i.project_id IS NOT NULL AND EXISTS (
			SELECT 1 FROM (` + membership.ProjectGrantsSQL + `) g
			 WHERE g.user_id = i.user_id AND g.project_id = i.project_id))
	)
)`

// Fill writes one inbox item per recipient of e: the finding's assignee for
// EventFindingAssigned, e.UserIDs for EventMention (already resolved — e.g.
// comment @mentions), a project's watchers for its other events, and instance
// admins for events naming no project. A recipient is skipped when they can no
// longer see the project, or muted the event type
// (user_notification_prefs.muted_events). Best-effort: called from
// notify.Service.Notify, which must never fail the operation that raised the
// event.
func (r *Repository) Fill(ctx context.Context, e notify.Event) error {
	mentionIDs := e.UserIDs
	if mentionIDs == nil {
		mentionIDs = []string{}
	}
	const q = `
		WITH candidates AS (
			SELECT m::uuid AS user_id FROM unnest($4::text[]) AS m WHERE $1 = 'mention'
			UNION
			SELECT f.assignee_id FROM findings f
			 WHERE $1 = 'finding.assigned' AND f.id = NULLIF($3, '')::uuid AND f.assignee_id IS NOT NULL
			UNION
			SELECT w.user_id FROM project_watches w
			 WHERE $1 NOT IN ('finding.assigned', 'mention') AND $2 <> '' AND w.project_id = NULLIF($2, '')::uuid
			UNION
			SELECT a.id FROM users a WHERE $2 = '' AND a.is_admin
		)
		INSERT INTO inbox_items (user_id, event_type, title, body, link, project_id, finding_id)
		SELECT c.user_id, $1, $5, $6, $7, NULLIF($2, '')::uuid, NULLIF($3, '')::uuid
		FROM candidates c
		JOIN users u ON u.id = c.user_id AND u.disabled_at IS NULL AND u.kind = 'user'
		LEFT JOIN user_notification_prefs pr ON pr.user_id = c.user_id
		WHERE NOT ($1 = ANY(COALESCE(pr.muted_events, '{}')))
		  AND (u.is_admin OR $2 = '' OR EXISTS (
		        SELECT 1 FROM (` + membership.ProjectGrantsSQL + `) g
		         WHERE g.user_id = c.user_id AND g.project_id = NULLIF($2, '')::uuid))`
	if _, err := r.db.Exec(ctx, q, e.Type, e.ProjectID, e.FindingID, mentionIDs, e.Title, e.Text, link(e)); err != nil {
		return fmt.Errorf("fill inbox: %w", err)
	}
	return nil
}

// link derives the UI deep link for an event: the finding when it names one,
// else the project, else none.
func link(e notify.Event) string {
	switch {
	case e.FindingID != "":
		return "/findings/" + e.FindingID
	case e.ProjectID != "":
		return "/projects/" + e.ProjectID
	default:
		return ""
	}
}

// Filter narrows List: "" (everything), "unread", "mentions" or "assigned".
type Filter struct {
	Mode   string
	Limit  int
	Offset int
}

// List returns one user's inbox, newest first, re-checking project visibility
// now rather than trusting Fill's write-time check.
func (r *Repository) List(ctx context.Context, userID string, f Filter) ([]Item, error) {
	rows, err := r.db.Query(ctx, `
		SELECT i.id, i.event_type, i.title, i.body, i.link, i.project_id, i.finding_id, i.created_at, i.read_at
		FROM inbox_items i
		WHERE i.user_id = $1
		  AND ($2 = '' OR ($2 = 'unread' AND i.read_at IS NULL)
		               OR ($2 = 'mentions' AND i.event_type = 'mention')
		               OR ($2 = 'assigned' AND i.event_type = 'finding.assigned'))
		  AND `+visibleSQL+`
		ORDER BY i.created_at DESC, i.id DESC
		LIMIT $3 OFFSET $4`, userID, f.Mode, f.Limit, f.Offset)
	if err != nil {
		return nil, fmt.Errorf("list inbox: %w", err)
	}
	defer rows.Close()
	out := []Item{}
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.ID, &it.EventType, &it.Title, &it.Body, &it.Link, &it.ProjectID, &it.FindingID, &it.CreatedAt, &it.ReadAt); err != nil {
			return nil, fmt.Errorf("scan inbox item: %w", err)
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// UnreadCount is the number of unread, still-visible items — cheap: no row
// payload, just a count the header bell polls.
func (r *Repository) UnreadCount(ctx context.Context, userID string) (int, error) {
	var n int
	err := r.db.QueryRow(ctx, `
		SELECT count(*) FROM inbox_items i
		WHERE i.user_id = $1 AND i.read_at IS NULL AND `+visibleSQL, userID).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("unread inbox count: %w", err)
	}
	return n, nil
}

// MarkRead marks ids (owned by userID) read, or every unread item when all is
// true, and reports how many rows changed.
func (r *Repository) MarkRead(ctx context.Context, userID string, ids []string, all bool) (int64, error) {
	tag, err := r.db.Exec(ctx, `
		UPDATE inbox_items SET read_at = now()
		WHERE user_id = $1 AND read_at IS NULL AND ($3 OR id = ANY($2::uuid[]))`,
		userID, ids, all)
	if err != nil {
		return 0, fmt.Errorf("mark inbox read: %w", err)
	}
	return tag.RowsAffected(), nil
}
