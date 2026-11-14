package finding

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/httpx"
)

// ErrConflict: the finding changed since the caller read it (If-Match).
var ErrConflict = errors.New("the finding changed since you loaded it")

// FieldsEdit is PATCH /findings/{id}/fields. Absent fields keep their value.
type FieldsEdit struct {
	// Title / Severity override the scanner's value; the override sticks
	// across scans (and triage rules) until ResetTitle / ResetSeverity.
	Title         *string          `json:"title"`
	Severity      *domain.Severity `json:"severity"`
	ResetTitle    bool             `json:"reset_title"`
	ResetSeverity bool             `json:"reset_severity"`
	// PlannedRemediationAt: "YYYY-MM-DD", or null to clear.
	PlannedRemediationAt json.RawMessage `json:"planned_remediation_at"`
}

// EditFields applies e to a finding, as actor, when it is still at version
// ifMatch (its updated_at; nil = no check). The check and the write share a
// row lock, so two people editing the same finding can't lose either edit.
func (r *Repository) EditFields(ctx context.Context, id string, e FieldsEdit, actor string, ifMatch *time.Time) (Finding, error) {
	var planned *time.Time
	setPlanned := len(e.PlannedRemediationAt) > 0
	if setPlanned && string(e.PlannedRemediationAt) != "null" {
		var s string
		if err := json.Unmarshal(e.PlannedRemediationAt, &s); err != nil {
			return Finding{}, fmt.Errorf("%w: planned_remediation_at must be YYYY-MM-DD or null", ErrInvalidEdit)
		}
		d, err := time.Parse(time.DateOnly, s)
		if err != nil {
			return Finding{}, fmt.Errorf("%w: planned_remediation_at must be YYYY-MM-DD or null", ErrInvalidEdit)
		}
		planned = &d
	}
	if e.Title != nil {
		t := strings.TrimSpace(*e.Title)
		if t == "" {
			return Finding{}, ErrEmptyTitle
		}
		e.Title = &t
	}
	if e.Severity != nil && !e.Severity.Valid() {
		return Finding{}, fmt.Errorf("%w: invalid severity", ErrInvalidEdit)
	}
	if (e.Title != nil && e.ResetTitle) || (e.Severity != nil && e.ResetSeverity) {
		return Finding{}, fmt.Errorf("%w: set a value or reset it, not both", ErrInvalidEdit)
	}

	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Finding{}, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if err := withActor(ctx, tx, actor, "edited the finding"); err != nil {
		return Finding{}, err
	}
	var updated time.Time
	var severity domain.Severity
	if err := tx.QueryRow(ctx, `SELECT updated_at, severity FROM findings WHERE id = $1 FOR UPDATE`, id).Scan(&updated, &severity); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Finding{}, ErrNotFound
		}
		return Finding{}, fmt.Errorf("lock finding: %w", err)
	}
	if ifMatch != nil && !updated.Equal(*ifMatch) {
		return Finding{}, ErrConflict
	}
	if _, err := tx.Exec(ctx, `
		UPDATE findings SET
			title           = COALESCE($2, title),
			title_manual    = CASE WHEN $2::text IS NOT NULL THEN true WHEN $4 THEN false ELSE title_manual END,
			severity        = COALESCE($3, severity),
			severity_manual = CASE WHEN $3::text IS NOT NULL THEN true WHEN $5 THEN false ELSE severity_manual END,
			planned_remediation_at = CASE WHEN $6 THEN $7::date ELSE planned_remediation_at END,
			updated_at = now()
		WHERE id = $1`, id, e.Title, e.Severity, e.ResetTitle, e.ResetSeverity, setPlanned, planned); err != nil {
		return Finding{}, fmt.Errorf("edit finding: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Finding{}, fmt.Errorf("commit: %w", err)
	}
	if e.Severity != nil && *e.Severity != severity {
		// Priority from every input; then the project regroups, since severity
		// elects a dedup group's primary.
		projects, _, err := r.Reprioritize(ctx, PriorityScope{FindingIDs: []string{id}})
		if err != nil {
			return Finding{}, err
		}
		for _, p := range projects {
			if _, err := r.Deduplicate(ctx, p); err != nil {
				return Finding{}, err
			}
		}
	}
	return r.Get(ctx, id)
}

// SetCustom merges set into a finding's custom-field values and drops unset,
// as actor (the findings_events_custom trigger records one history row per
// changed field). Values must already be validated (customfield.Service).
// It returns the values afterwards; a write that changes nothing touches
// nothing.
func (r *Repository) SetCustom(ctx context.Context, id string, set map[string]any, unset []string, actor, note string) (map[string]any, error) {
	if set == nil {
		set = map[string]any{}
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if err := withActor(ctx, tx, actor, note); err != nil {
		return nil, err
	}
	var out map[string]any
	err = tx.QueryRow(ctx, `
		WITH next AS (SELECT id, (custom || $2::jsonb) - $3::text[] AS custom FROM findings WHERE id = $1),
		upd AS (
			UPDATE findings f SET custom = next.custom, updated_at = now()
			FROM next WHERE f.id = next.id AND f.custom IS DISTINCT FROM next.custom
			RETURNING f.custom
		)
		SELECT COALESCE((SELECT custom FROM upd), next.custom) FROM next`, id, set, nonNil(unset)).Scan(&out)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("set custom fields: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return out, nil
}

// ErrInvalidEdit: the edit itself is malformed (400).
var ErrInvalidEdit = errors.New("invalid edit")

// ifMatch reads If-Match: the finding's updated_at as the client last saw it
// (RFC 3339; quotes and a weak "W/" prefix tolerated). Absent = no check.
func ifMatch(c *fiber.Ctx) (*time.Time, error) {
	v := strings.TrimSpace(c.Get(fiber.HeaderIfMatch))
	if v == "" || v == "*" {
		return nil, nil
	}
	v = strings.Trim(strings.TrimPrefix(v, "W/"), `"`)
	t, err := time.Parse(time.RFC3339Nano, v)
	if err != nil {
		return nil, fiber.NewError(fiber.StatusBadRequest, "If-Match must be the finding's updated_at (RFC 3339)")
	}
	return &t, nil
}

// conflict answers 412 with the finding as it is now, so the client can show
// what changed and let the person decide.
func (h *Handler) conflict(c *fiber.Ctx, id string) error {
	cur, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		return err
	}
	return c.Status(fiber.StatusPreconditionFailed).JSON(fiber.Map{"error": ErrConflict.Error(), "finding": cur})
}

// precondition checks If-Match before a write that doesn't take the row lock
// itself (status, assignee, tags, write-up). done reports that it answered
// the request (412 with the current finding); the caller then stops. A check
// that races a concurrent write in the instant between is still possible
// here — EditFields, which locks, is exact.
func (h *Handler) precondition(c *fiber.Ctx, id string) (done bool, err error) {
	want, err := ifMatch(c)
	if err != nil || want == nil {
		return false, err
	}
	cur, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return false, fiber.NewError(fiber.StatusNotFound, "finding not found")
	}
	if err != nil {
		return false, err
	}
	if !cur.UpdatedAt.Equal(*want) {
		return true, c.Status(fiber.StatusPreconditionFailed).JSON(fiber.Map{"error": ErrConflict.Error(), "finding": cur})
	}
	return false, nil
}

// EditFields handles PATCH /findings/{id}/fields.
func (h *Handler) EditFields(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "findingID")
	if err != nil {
		return err
	}
	var body FieldsEdit
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	want, err := ifMatch(c)
	if err != nil {
		return err
	}
	f, err := h.repo.EditFields(c.UserContext(), id, body, auth.UserID(c), want)
	switch {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "finding not found")
	case errors.Is(err, ErrConflict):
		return h.conflict(c, id)
	case errors.Is(err, ErrEmptyTitle), errors.Is(err, ErrInvalidEdit):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case err != nil:
		return err
	}
	return c.JSON(f)
}

// SourceRef is what a finding's source link is built from.
func (r *Repository) SourceRef(ctx context.Context, id string) (repoURL, commit, branch string, err error) {
	err = r.db.QueryRow(ctx, `
		SELECT p.repo_url, COALESCE(s.commit_sha, ''), COALESCE(CASE WHEN v.kind = 'branch' THEN v.name END, '')
		FROM findings f
		JOIN projects p ON p.id = f.project_id
		LEFT JOIN scans s ON s.id = f.last_scan_id
		LEFT JOIN project_versions v ON v.id = f.version_id
		WHERE f.id = $1`, id).Scan(&repoURL, &commit, &branch)
	return
}

// SourceURL links path:line into the repository at ref (a commit, else a
// branch, else HEAD), in the URL scheme of the forge hosting repoURL: GitHub,
// GitLab, Bitbucket, Azure DevOps, Gitea/Forgejo. An unrecognized host, a
// non-http(s) URL, or a path that isn't repository-relative gets no link —
// a guessed link is worse than none.
func SourceURL(repoURL, ref, path string, line *int) (string, bool) {
	repo := strings.TrimSpace(repoURL)
	// git@host:org/repo(.git) → https://host/org/repo
	if rest, ok := strings.CutPrefix(repo, "git@"); ok {
		host, p, found := strings.Cut(rest, ":")
		if !found {
			return "", false
		}
		repo = "https://" + host + "/" + p
	}
	u, err := url.Parse(repo)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", false
	}
	u.User = nil
	u.Path = strings.TrimSuffix(strings.TrimRight(u.Path, "/"), ".git")
	path = strings.TrimSpace(path)
	if path == "" || strings.Contains(path, "://") || strings.Contains(path, "..") {
		return "", false
	}
	path = strings.TrimLeft(strings.TrimPrefix(path, "./"), "/")
	if ref == "" {
		ref = "HEAD"
	}
	escaped := make([]string, 0, 8)
	for _, seg := range strings.Split(path, "/") {
		escaped = append(escaped, url.PathEscape(seg))
	}
	p := strings.Join(escaped, "/")
	base := u.Scheme + "://" + u.Host + u.Path
	host := strings.ToLower(u.Hostname())
	ln := 0
	if line != nil && *line > 0 {
		ln = *line
	}
	switch {
	case host == "github.com" || strings.HasPrefix(host, "github."):
		return base + "/blob/" + url.PathEscape(ref) + "/" + p + anchor("#L", ln), true
	case host == "gitlab.com" || strings.HasPrefix(host, "gitlab."):
		return base + "/-/blob/" + url.PathEscape(ref) + "/" + p + anchor("#L", ln), true
	case host == "bitbucket.org":
		return base + "/src/" + url.PathEscape(ref) + "/" + p + anchor("#lines-", ln), true
	case host == "dev.azure.com" || strings.HasSuffix(host, ".visualstudio.com"):
		q := url.Values{"path": {"/" + path}}
		if ref != "HEAD" {
			if isCommitish(ref) {
				q.Set("version", "GC"+ref)
			} else {
				q.Set("version", "GB"+ref)
			}
		}
		if ln > 0 {
			q.Set("line", strconv.Itoa(ln))
			q.Set("lineEnd", strconv.Itoa(ln))
			q.Set("lineStartColumn", "1")
			q.Set("lineEndColumn", "1")
		}
		return base + "?" + q.Encode(), true
	case host == "codeberg.org" || strings.HasPrefix(host, "gitea.") || strings.HasPrefix(host, "forgejo."):
		kind := "branch"
		if isCommitish(ref) {
			kind = "commit"
		}
		return base + "/src/" + kind + "/" + url.PathEscape(ref) + "/" + p + anchor("#L", ln), true
	}
	return "", false
}

func anchor(prefix string, line int) string {
	if line <= 0 {
		return ""
	}
	return prefix + strconv.Itoa(line)
}

// isCommitish: a 7–40 (or 64) character hex string, i.e. a commit, not a branch.
func isCommitish(ref string) bool {
	if n := len(ref); n < 7 || (n > 40 && n != 64) {
		return false
	}
	for _, r := range ref {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}
