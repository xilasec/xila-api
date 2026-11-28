package finding

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/xilasec/xila-api/internal/domain"
)

// ErrCommentNotFound / ErrAttachmentNotFound are returned for missing sub-resources.
var (
	ErrCommentNotFound    = errors.New("comment not found")
	ErrAttachmentNotFound = errors.New("attachment not found")
)

// withActor attributes the writes of a transaction in the finding history: the
// findings_events trigger records xila.actor and xila.note on every status,
// severity and assignee change. Transaction-local, so it never leaks to the next
// user of the pooled connection.
func withActor(ctx context.Context, tx pgx.Tx, actor, note string) error {
	if _, err := tx.Exec(ctx, `SELECT set_config('xila.actor', $1, true), set_config('xila.note', $2, true)`,
		actor, note); err != nil {
		return fmt.Errorf("set actor: %w", err)
	}
	return nil
}

// Event is one entry of a finding's history.
type Event struct {
	ID        int64     `json:"id"`
	Kind      string    `json:"kind"`            // created | status | severity | assignee | tags | custom_field | comment | attachment
	Field     string    `json:"field,omitempty"` // the custom field's key (kind custom_field)
	From      *string   `json:"from"`
	To        *string   `json:"to"`
	Actor     string    `json:"actor"`      // user id, or system / vex / …
	ActorName string    `json:"actor_name"` // the user's email when the actor is a user
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}

// History returns every change to a finding, oldest first.
func (r *Repository) History(ctx context.Context, findingID string) ([]Event, error) {
	rows, err := r.db.Query(ctx, `
		SELECT e.id, e.kind, COALESCE(e.field, ''), e.from_value, e.to_value, e.actor, COALESCE(u.email, e.actor), e.note, e.created_at
		FROM finding_events e
		LEFT JOIN users u ON u.id::text = e.actor
		WHERE e.finding_id = $1
		ORDER BY e.id`, findingID)
	if err != nil {
		return nil, fmt.Errorf("finding history: %w", err)
	}
	defer rows.Close()
	out := []Event{}
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.Kind, &e.Field, &e.From, &e.To, &e.Actor, &e.ActorName, &e.Note, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan event: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Comment is a note on a finding.
type Comment struct {
	ID        string    `json:"id"`
	FindingID string    `json:"finding_id"`
	AuthorID  *string   `json:"author_id"`
	Author    string    `json:"author"`
	Body      string    `json:"body"`
	CreatedAt time.Time `json:"created_at"`
}

// AddComment posts a comment as authorID and records it in the history.
func (r *Repository) AddComment(ctx context.Context, findingID, authorID, body string) (Comment, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Comment{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	c, err := addCommentTx(ctx, tx, findingID, authorID, body)
	if err != nil {
		return Comment{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Comment{}, fmt.Errorf("commit: %w", err)
	}
	return c, nil
}

// addCommentTx is AddComment inside tx: the comment and its history event.
func addCommentTx(ctx context.Context, tx pgx.Tx, findingID, authorID, body string) (Comment, error) {
	var c Comment
	err := tx.QueryRow(ctx, `
		INSERT INTO finding_comments (finding_id, project_id, author_id, author, body)
		SELECT f.id, f.project_id, NULLIF($2, '')::uuid, COALESCE((SELECT email FROM users WHERE id = NULLIF($2, '')::uuid), ''), $3
		FROM findings f WHERE f.id = $1
		RETURNING id, finding_id, author_id, author, body, created_at`, findingID, authorID, body).
		Scan(&c.ID, &c.FindingID, &c.AuthorID, &c.Author, &c.Body, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Comment{}, ErrNotFound
	}
	if err != nil {
		return Comment{}, fmt.Errorf("add comment: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO finding_events (finding_id, project_id, kind, to_value, actor)
		SELECT id, project_id, 'comment', $2, $3 FROM findings WHERE id = $1`,
		findingID, c.ID, authorID); err != nil {
		return Comment{}, fmt.Errorf("record comment: %w", err)
	}
	return c, nil
}

// AddExternalCommentTx stores, in tx, a comment written outside Xila (an
// issue tracker's): no Xila author, author is the label shown for it, and the
// history records actor.
func AddExternalCommentTx(ctx context.Context, tx pgx.Tx, findingID, author, body, actor string) (Comment, error) {
	var c Comment
	err := tx.QueryRow(ctx, `
		INSERT INTO finding_comments (finding_id, project_id, author_id, author, body)
		SELECT f.id, f.project_id, NULL, $2, $3 FROM findings f WHERE f.id = $1
		RETURNING id, finding_id, author_id, author, body, created_at`, findingID, author, body).
		Scan(&c.ID, &c.FindingID, &c.AuthorID, &c.Author, &c.Body, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Comment{}, ErrNotFound
	}
	if err != nil {
		return Comment{}, fmt.Errorf("add external comment: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO finding_events (finding_id, project_id, kind, to_value, actor)
		SELECT id, project_id, 'comment', $2, $3 FROM findings WHERE id = $1`,
		findingID, c.ID, actor); err != nil {
		return Comment{}, fmt.Errorf("record external comment: %w", err)
	}
	return c, nil
}

// Comments lists a finding's comments, oldest first.
func (r *Repository) Comments(ctx context.Context, findingID string) ([]Comment, error) {
	rows, err := r.db.Query(ctx, `SELECT id, finding_id, author_id, author, body, created_at
		FROM finding_comments WHERE finding_id = $1 ORDER BY created_at, id`, findingID)
	if err != nil {
		return nil, fmt.Errorf("list comments: %w", err)
	}
	defer rows.Close()
	out := []Comment{}
	for rows.Next() {
		var c Comment
		if err := rows.Scan(&c.ID, &c.FindingID, &c.AuthorID, &c.Author, &c.Body, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan comment: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Comment returns one comment of a finding.
func (r *Repository) Comment(ctx context.Context, findingID, commentID string) (Comment, error) {
	var c Comment
	err := r.db.QueryRow(ctx, `SELECT id, finding_id, author_id, author, body, created_at
		FROM finding_comments WHERE finding_id = $1 AND id = $2`, findingID, commentID).
		Scan(&c.ID, &c.FindingID, &c.AuthorID, &c.Author, &c.Body, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Comment{}, ErrCommentNotFound
	}
	if err != nil {
		return Comment{}, fmt.Errorf("get comment: %w", err)
	}
	return c, nil
}

// DeleteComment removes a comment. The history keeps that one was made.
func (r *Repository) DeleteComment(ctx context.Context, findingID, commentID string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM finding_comments WHERE finding_id = $1 AND id = $2`, findingID, commentID)
	if err != nil {
		return fmt.Errorf("delete comment: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrCommentNotFound
	}
	return nil
}

// Attachment is a file of evidence on a finding (metadata; Data only on download).
type Attachment struct {
	ID          string    `json:"id"`
	FindingID   string    `json:"finding_id"`
	Filename    string    `json:"filename"`
	ContentType string    `json:"content_type"`
	Size        int       `json:"size"`
	SHA256      string    `json:"sha256"`
	UploadedBy  *string   `json:"uploaded_by"`
	Uploader    string    `json:"uploader"`
	CreatedAt   time.Time `json:"created_at"`
	Data        []byte    `json:"-"`
}

const attachmentColumns = `id, finding_id, filename, content_type, size, sha256, uploaded_by, uploader, created_at`

func scanAttachment(row pgx.Row, withData bool) (Attachment, error) {
	var a Attachment
	dest := []any{&a.ID, &a.FindingID, &a.Filename, &a.ContentType, &a.Size, &a.SHA256, &a.UploadedBy, &a.Uploader, &a.CreatedAt}
	if withData {
		dest = append(dest, &a.Data)
	}
	return a, row.Scan(dest...)
}

// AddAttachment stores a file on a finding and records it in the history.
func (r *Repository) AddAttachment(ctx context.Context, findingID, uploaderID, filename, contentType string, data []byte) (Attachment, error) {
	sum := sha256.Sum256(data)
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Attachment{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	a, err := scanAttachment(tx.QueryRow(ctx, `
		INSERT INTO finding_attachments (finding_id, project_id, filename, content_type, size, sha256, data, uploaded_by, uploader)
		SELECT f.id, f.project_id, $2, $3, $4, $5, $6, NULLIF($7, '')::uuid, COALESCE((SELECT email FROM users WHERE id = NULLIF($7, '')::uuid), '')
		FROM findings f WHERE f.id = $1
		RETURNING `+attachmentColumns,
		findingID, filename, contentType, len(data), hex.EncodeToString(sum[:]), data, uploaderID), false)
	if errors.Is(err, pgx.ErrNoRows) {
		return Attachment{}, ErrNotFound
	}
	if err != nil {
		return Attachment{}, fmt.Errorf("add attachment: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO finding_events (finding_id, project_id, kind, to_value, actor)
		SELECT id, project_id, 'attachment', $2, $3 FROM findings WHERE id = $1`,
		findingID, filename, uploaderID); err != nil {
		return Attachment{}, fmt.Errorf("record attachment: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Attachment{}, fmt.Errorf("commit: %w", err)
	}
	return a, nil
}

// Attachments lists a finding's files (without their bytes), newest first.
func (r *Repository) Attachments(ctx context.Context, findingID string) ([]Attachment, error) {
	rows, err := r.db.Query(ctx, `SELECT `+attachmentColumns+` FROM finding_attachments
		WHERE finding_id = $1 ORDER BY created_at DESC, id`, findingID)
	if err != nil {
		return nil, fmt.Errorf("list attachments: %w", err)
	}
	defer rows.Close()
	out := []Attachment{}
	for rows.Next() {
		a, err := scanAttachment(rows, false)
		if err != nil {
			return nil, fmt.Errorf("scan attachment: %w", err)
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Attachment returns one file with its bytes.
func (r *Repository) Attachment(ctx context.Context, findingID, attachmentID string) (Attachment, error) {
	a, err := scanAttachment(r.db.QueryRow(ctx, `SELECT `+attachmentColumns+`, data FROM finding_attachments
		WHERE finding_id = $1 AND id = $2`, findingID, attachmentID), true)
	if errors.Is(err, pgx.ErrNoRows) {
		return Attachment{}, ErrAttachmentNotFound
	}
	if err != nil {
		return Attachment{}, fmt.Errorf("get attachment: %w", err)
	}
	return a, nil
}

// DeleteAttachment removes a file.
func (r *Repository) DeleteAttachment(ctx context.Context, findingID, attachmentID string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM finding_attachments WHERE finding_id = $1 AND id = $2`, findingID, attachmentID)
	if err != nil {
		return fmt.Errorf("delete attachment: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrAttachmentNotFound
	}
	return nil
}

// Change is a bulk edit: any of status (with exception reason / expiry),
// severity and assignee, applied to many findings at once. VexJustification /
// VexResponse accompany a status moved to false_positive or wont_fix; any
// other status clears them regardless of what is given.
type Change struct {
	Status           *domain.FindingStatus
	Reason           string
	ExpiresAt        *time.Time
	VexJustification domain.VexJustification
	VexResponse      []domain.VexResponse
	Severity         *domain.Severity
	// SetAssignee applies AssigneeID (nil = unassign); false leaves it alone.
	SetAssignee bool
	AssigneeID  *string
	// SetTags replaces each finding's tags with Tags; otherwise AddTags and
	// RemoveTags edit them. All normalized (NormalizeTags) by the caller.
	SetTags    bool
	Tags       []string
	AddTags    []string
	RemoveTags []string
}

// Empty reports whether the change does nothing.
func (c Change) Empty() bool {
	return c.Status == nil && c.Severity == nil && !c.SetAssignee && !c.touchesTags()
}

func (c Change) touchesTags() bool {
	return c.SetTags || len(c.AddTags) > 0 || len(c.RemoveTags) > 0
}

// MaxTags bounds one finding's tags.
const MaxTags = 20

// ErrTooManyTags is returned when a change would leave a finding with more
// than MaxTags tags.
var ErrTooManyTags = fmt.Errorf("a finding can carry at most %d tags", MaxTags)

// ErrInvalidTag is returned for a tag NormalizeTags rejects.
var ErrInvalidTag = errors.New("tags are 1–50 characters: lowercase letters, digits and . _ : / -, starting with a letter or digit")

var tagPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,49}$`)

// NormalizeTags lowercases and trims tags, drops duplicates, sorts them, and
// rejects any that isn't a plain label (so tags stay filterable and safe in
// URLs, CSV and chips).
func NormalizeTags(in []string) ([]string, error) {
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.ToLower(strings.TrimSpace(t))
		if !tagPattern.MatchString(t) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidTag, t)
		}
		out = append(out, t)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// Apply makes one change to every finding in ids, in one transaction,
// attributed to actor in each finding's history. It mirrors SetStatus /
// SetSeverity exactly (resolved_at, exception fields + audit row, base
// priority) and returns the updated findings. The caller regroups duplicates
// afterwards when severity changed — severity elects a group's primary. No
// ids (a bulk edit whose every finding became a pending assessment) changes
// nothing.
func (r *Repository) Apply(ctx context.Context, ids []string, c Change, actor string) ([]Finding, error) {
	if len(ids) == 0 {
		return []Finding{}, nil
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if err := withActor(ctx, tx, actor, c.Reason); err != nil {
		return nil, err
	}
	if err := applyChange(ctx, tx, ids, c, actor); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	if c.Severity != nil {
		// Priority from every input, not the bare severity weight.
		if _, _, err := r.Reprioritize(ctx, PriorityScope{FindingIDs: ids}); err != nil {
			return nil, err
		}
	}
	found, err := readFindings(ctx, r.db, ids)
	if err != nil {
		return nil, err
	}
	return found, r.decided(ctx, found, actor, c.Status != nil, c.Severity != nil)
}

// applyChange writes c to the findings in ids inside tx (whose actor is
// already set). Shared by Apply and an approved assessment.
func applyChange(ctx context.Context, tx pgx.Tx, ids []string, c Change, actor string) error {
	if c.Status != nil {
		if *c.Status == domain.FindingRiskAccepted {
			return ErrRiskAcceptanceRequired
		}
		if err := leaveAcceptances(ctx, tx, ids, actor, "status set to "+string(*c.Status)); err != nil {
			return err
		}
		reason, by := "", ""
		var expires *time.Time
		justification := domain.VexJustification("")
		var response []domain.VexResponse
		if isExceptionStatus(*c.Status) {
			reason, by, expires = c.Reason, actor, c.ExpiresAt
			justification, response = c.VexJustification, c.VexResponse
		}
		// status_decided_at is stamped here because this branch is reached only
		// from Apply (a person's bulk edit); a triage-carry propagation later
		// compares against it to avoid overturning a more recent, targeted
		// decision on one instance.
		if _, err := tx.Exec(ctx, `
			UPDATE findings
			SET status = $2,
			    resolved_at = CASE WHEN $2 IN ('false_positive', 'remediated', 'wont_fix')
			                       THEN now() ELSE NULL END,
			    exception_reason = $3, exception_by = $4, exception_expires_at = $5,
			    status_decided_at = now(), vex_justification = $6, vex_response = $7, updated_at = now()
			WHERE id = ANY($1) AND status IS DISTINCT FROM $2`,
			ids, *c.Status, reason, by, expires, justification, vexResponseStrings(response)); err != nil {
			return fmt.Errorf("bulk status: %w", err)
		}
		if isExceptionStatus(*c.Status) {
			if _, err := tx.Exec(ctx, `
				INSERT INTO finding_exceptions (finding_id, project_id, status, reason, actor, expires_at)
				SELECT id, project_id, $2, $3, $4, $5 FROM findings WHERE id = ANY($1)`,
				ids, *c.Status, reason, by, expires); err != nil {
				return fmt.Errorf("bulk exception audit: %w", err)
			}
		}
	}
	if c.Severity != nil {
		if _, err := tx.Exec(ctx, `
			UPDATE findings SET severity = $2, severity_manual = true, updated_at = now()
			WHERE id = ANY($1) AND (severity IS DISTINCT FROM $2 OR NOT severity_manual)`, ids, *c.Severity); err != nil {
			return fmt.Errorf("bulk severity: %w", err)
		}
	}
	if c.SetAssignee {
		if _, err := tx.Exec(ctx, `UPDATE findings SET assignee_id = $2, updated_at = now()
			WHERE id = ANY($1) AND assignee_id IS DISTINCT FROM $2`, ids, c.AssigneeID); err != nil {
			return fmt.Errorf("bulk assign: %w", err)
		}
	}
	if c.touchesTags() {
		// New set = (replacement or current) ∪ added − removed, sorted; only rows
		// whose tags actually change are written (and logged as history).
		var tooMany bool
		if err := tx.QueryRow(ctx, `
			WITH next AS (
				SELECT id, ARRAY(SELECT DISTINCT x FROM unnest(CASE WHEN $2 THEN $3::text[] ELSE tags END || $4::text[]) x
				                 WHERE x <> ALL($5::text[]) ORDER BY x) AS tags
				FROM findings WHERE id = ANY($1)
			), upd AS (
				UPDATE findings f SET tags = next.tags, updated_at = now()
				FROM next WHERE f.id = next.id AND f.tags IS DISTINCT FROM next.tags
				RETURNING cardinality(f.tags) AS n
			)
			SELECT COALESCE(bool_or(n > $6), false) FROM upd`,
			ids, c.SetTags, nonNil(c.Tags), nonNil(c.AddTags), nonNil(c.RemoveTags), MaxTags).Scan(&tooMany); err != nil {
			return fmt.Errorf("bulk tags: %w", err)
		}
		if tooMany {
			return ErrTooManyTags
		}
	}
	return nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// readFindings reads the findings in ids back inside tx, highest priority first.
func readFindings(ctx context.Context, tx interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}, ids []string) ([]Finding, error) {
	rows, err := tx.Query(ctx, `SELECT `+findingColumns+` FROM findings WHERE id = ANY($1) ORDER BY priority DESC, id`, ids)
	if err != nil {
		return nil, fmt.Errorf("bulk read back: %w", err)
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, fmt.Errorf("scan finding: %w", err)
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ProjectsOf returns each finding's project, for authorizing a bulk edit.
// Unknown ids are absent from the map.
func (r *Repository) ProjectsOf(ctx context.Context, ids []string) (map[string]string, error) {
	rows, err := r.db.Query(ctx, `SELECT id, project_id FROM findings WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, fmt.Errorf("projects of findings: %w", err)
	}
	defer rows.Close()
	out := make(map[string]string, len(ids))
	for rows.Next() {
		var id, pid string
		if err := rows.Scan(&id, &pid); err != nil {
			return nil, fmt.Errorf("scan: %w", err)
		}
		out[id] = pid
	}
	return out, rows.Err()
}

// ApplyFeedTags adds the tags advisory feed rules attached to the findings a
// scan recorded (metadata.feed_tags, set by the advisory matcher) — additive,
// never removing a tag, writing only rows whose tags change and never past
// MaxTags. The rules re-apply on every match.
func (r *Repository) ApplyFeedTags(ctx context.Context, scanID string) error {
	_, err := r.db.Exec(ctx, `
		WITH next AS (
			SELECT id, ARRAY(SELECT DISTINCT x FROM unnest(tags || ARRAY(
			           SELECT jsonb_array_elements_text(metadata->'feed_tags'))) x ORDER BY x) AS tags
			FROM findings
			WHERE last_scan_id = $1 AND jsonb_typeof(metadata->'feed_tags') = 'array'
		)
		UPDATE findings f SET tags = next.tags, updated_at = now()
		FROM next
		WHERE f.id = next.id AND f.tags IS DISTINCT FROM next.tags AND cardinality(next.tags) <= $2`,
		scanID, MaxTags)
	if err != nil {
		return fmt.Errorf("feed tags: %w", err)
	}
	return nil
}
