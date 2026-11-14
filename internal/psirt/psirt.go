// Package psirt publishes CSAF 2.0 security advisories
// (document.category csaf_security_advisory) about the instance's own
// products — the PSIRT side of vulnerability management.
//
// An advisory is a draft per project (the product) until an admin publishes
// it. Publishing appends a revision, bumps the tracking version and freezes
// the rendered CSAF document; republishing (after edits) does it again with a
// required note; withdrawing appends a final revision. Only frozen documents
// are ever distributed — the admin download, and with PSIRT_PUBLIC the CSAF
// provider directory (/.well-known/csaf/provider-metadata.json and
// /csaf/advisories/…) — so draft edits stay private until republished.
package psirt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// State is an advisory's lifecycle state.
type State string

const (
	StateDraft     State = "draft"
	StatePublished State = "published"
	StateWithdrawn State = "withdrawn"
)

// VersionRef is one affected or fixed product version: a project version
// (VersionID; its name is resolved on save), an explicit version, or a range
// (a vers: string such as "vers:semver/>=1.0.0|<1.4.2").
type VersionRef struct {
	VersionID string `json:"version_id,omitempty"`
	Version   string `json:"version,omitempty"`
	Range     string `json:"range,omitempty"`
}

// Acknowledgment credits the people or organization who reported or helped.
type Acknowledgment struct {
	Names        []string `json:"names,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Summary      string   `json:"summary,omitempty"`
	URLs         []string `json:"urls,omitempty"`
}

// Revision is one entry of the advisory's revision history.
type Revision struct {
	Number  int       `json:"number"`
	Date    time.Time `json:"date"`
	Summary string    `json:"summary"`
}

// Advisory is a security advisory about one project's product.
type Advisory struct {
	ID               string           `json:"id"`
	ProjectID        string           `json:"project_id"`
	ProjectName      string           `json:"project_name"`
	TrackingID       string           `json:"tracking_id"`
	State            State            `json:"state"`
	Title            string           `json:"title"`
	ProductName      string           `json:"product_name"`
	Summary          string           `json:"summary"`
	Details          string           `json:"details"`
	CVE              string           `json:"cve"`
	CWE              string           `json:"cwe"`
	CWEName          string           `json:"cwe_name"`
	CVSSVector       string           `json:"cvss_vector"`
	Affected         []VersionRef     `json:"affected"`
	Fixed            []VersionRef     `json:"fixed"`
	Remediation      string           `json:"remediation"`
	Acknowledgments  []Acknowledgment `json:"acknowledgments"`
	SourceAdvisoryID *string          `json:"source_advisory_id"`
	Version          int              `json:"version"`
	InitialReleaseAt *time.Time       `json:"initial_release_at"`
	CurrentReleaseAt *time.Time       `json:"current_release_at"`
	Revisions        []Revision       `json:"revisions"`
	// Unpublished reports edits since the last publish (the frozen document
	// no longer matches the draft fields).
	Unpublished bool      `json:"unpublished_changes"`
	CreatedBy   *string   `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Errors returned by the repository and service.
var (
	ErrNotFound       = errors.New("advisory not found")
	ErrInvalid        = errors.New("invalid advisory")
	ErrNoProject      = errors.New("project not found")
	ErrUnknownVersion = errors.New("a version_id is not a version of this project")
	ErrState          = errors.New("not allowed in the advisory's current state")
	ErrNoteRequired   = errors.New("a note describing the change is required")
	ErrNotPublished   = errors.New("the advisory has not been published")
	ErrPublisher      = errors.New("the CSAF publisher is not configured (PSIRT_PUBLISHER_NAME, PSIRT_PUBLISHER_NAMESPACE)")
)

var (
	cveRe = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	cweRe = regexp.MustCompile(`^CWE-[1-9]\d{0,5}$`)
)

// Validate checks and normalizes the editable fields.
func (a *Advisory) Validate() error {
	trim := func(s *string) { *s = strings.TrimSpace(*s) }
	for _, s := range []*string{&a.Title, &a.ProductName, &a.Summary, &a.Details, &a.CVE, &a.CWE, &a.CWEName, &a.CVSSVector, &a.Remediation} {
		trim(s)
	}
	if a.Title == "" {
		return errors.New("title is required")
	}
	if a.Summary == "" {
		return errors.New("summary is required")
	}
	a.CVE = strings.ToUpper(a.CVE)
	if a.CVE != "" && !cveRe.MatchString(a.CVE) {
		return errors.New("cve must look like CVE-2026-12345")
	}
	a.CWE = strings.ToUpper(a.CWE)
	if a.CWE != "" && !cweRe.MatchString(a.CWE) {
		return errors.New("cwe must look like CWE-79")
	}
	if a.CWE != "" && a.CWEName == "" {
		return errors.New("cwe_name is required with a cwe (CSAF names the weakness)")
	}
	if a.CWE == "" {
		a.CWEName = ""
	}
	if a.CVSSVector != "" {
		if _, err := parseCVSS3(a.CVSSVector); err != nil {
			return err
		}
	}
	if len(a.Affected) == 0 {
		return errors.New("at least one affected version or range is required")
	}
	for _, list := range [][]VersionRef{a.Affected, a.Fixed} {
		for i := range list {
			r := &list[i]
			trim(&r.VersionID)
			trim(&r.Version)
			trim(&r.Range)
			n := 0
			for _, s := range []string{r.VersionID, r.Version, r.Range} {
				if s != "" {
					n++
				}
			}
			// version_id resolves into version on save, so both may be set.
			if n == 0 || (r.Range != "" && n != 1) {
				return errors.New("each version entry sets version_id, version, or range")
			}
		}
	}
	if a.Fixed == nil {
		a.Fixed = []VersionRef{}
	}
	if a.Acknowledgments == nil {
		a.Acknowledgments = []Acknowledgment{}
	}
	for i := range a.Acknowledgments {
		ack := &a.Acknowledgments[i]
		trim(&ack.Organization)
		trim(&ack.Summary)
		if len(ack.Names) == 0 && ack.Organization == "" {
			return errors.New("an acknowledgment names people or an organization")
		}
	}
	return nil
}

// Repository stores advisories (psirt_advisories, psirt_revisions).
type Repository struct{ db *pgxpool.Pool }

// NewRepository constructs the store.
func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

const advisoryColumns = `a.id, a.project_id, p.name, a.tracking_id, a.state, a.title, a.product_name,
	a.summary, a.details, a.cve, a.cwe, a.cwe_name, a.cvss_vector, a.affected, a.fixed, a.remediation,
	a.acknowledgments, a.source_advisory_id, a.version, a.initial_release_at, a.current_release_at,
	a.document IS NOT NULL AND a.updated_at > a.current_release_at,
	a.created_by, a.created_at, a.updated_at`

const advisoryFrom = ` FROM psirt_advisories a JOIN projects p ON p.id = a.project_id`

func scanAdvisory(row pgx.Row) (Advisory, error) {
	var a Advisory
	var affected, fixed, acks []byte
	err := row.Scan(&a.ID, &a.ProjectID, &a.ProjectName, &a.TrackingID, &a.State, &a.Title, &a.ProductName,
		&a.Summary, &a.Details, &a.CVE, &a.CWE, &a.CWEName, &a.CVSSVector, &affected, &fixed, &a.Remediation,
		&acks, &a.SourceAdvisoryID, &a.Version, &a.InitialReleaseAt, &a.CurrentReleaseAt, &a.Unpublished,
		&a.CreatedBy, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return a, err
	}
	for _, f := range []struct {
		raw []byte
		dst any
	}{{affected, &a.Affected}, {fixed, &a.Fixed}, {acks, &a.Acknowledgments}} {
		if err := json.Unmarshal(f.raw, f.dst); err != nil {
			return a, fmt.Errorf("decode advisory: %w", err)
		}
	}
	a.Revisions = []Revision{}
	return a, nil
}

// Filter narrows List.
type Filter struct {
	ProjectID string
	State     State
	Limit     int
	Offset    int
}

// List returns advisories, most recently updated first.
func (r *Repository) List(ctx context.Context, f Filter) ([]Advisory, error) {
	rows, err := r.db.Query(ctx, `SELECT `+advisoryColumns+advisoryFrom+`
		WHERE ($1 = '' OR a.project_id::text = $1) AND ($2 = '' OR a.state = $2)
		ORDER BY a.updated_at DESC, a.id LIMIT $3 OFFSET $4`, f.ProjectID, string(f.State), f.Limit, f.Offset)
	if err != nil {
		return nil, fmt.Errorf("list advisories: %w", err)
	}
	defer rows.Close()
	out := []Advisory{}
	for rows.Next() {
		a, err := scanAdvisory(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Get returns one advisory with its revision history.
func (r *Repository) Get(ctx context.Context, id string) (Advisory, error) {
	a, err := scanAdvisory(r.db.QueryRow(ctx, `SELECT `+advisoryColumns+advisoryFrom+` WHERE a.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Advisory{}, ErrNotFound
	}
	if err != nil {
		return Advisory{}, err
	}
	a.Revisions, err = revisions(ctx, r.db, id)
	return a, err
}

type querier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func revisions(ctx context.Context, q querier, id string) ([]Revision, error) {
	rows, err := q.Query(ctx, `SELECT number, date, summary FROM psirt_revisions WHERE advisory_id = $1 ORDER BY number`, id)
	if err != nil {
		return nil, fmt.Errorf("revisions: %w", err)
	}
	defer rows.Close()
	out := []Revision{}
	for rows.Next() {
		var rev Revision
		if err := rows.Scan(&rev.Number, &rev.Date, &rev.Summary); err != nil {
			return nil, err
		}
		out = append(out, rev)
	}
	return out, rows.Err()
}

// resolveVersions fills Version from each VersionID (which must belong to the
// project) and the product name from the project when empty.
func resolveVersions(ctx context.Context, q querier, a *Advisory) error {
	var projectName string
	if err := q.QueryRow(ctx, `SELECT name FROM projects WHERE id = $1`, a.ProjectID).Scan(&projectName); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNoProject
		}
		return err
	}
	if a.ProductName == "" {
		a.ProductName = projectName
	}
	for _, list := range [][]VersionRef{a.Affected, a.Fixed} {
		for i := range list {
			if list[i].VersionID == "" {
				continue
			}
			var name string
			err := q.QueryRow(ctx, `SELECT name FROM project_versions WHERE id::text = $1 AND project_id = $2`,
				list[i].VersionID, a.ProjectID).Scan(&name)
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrUnknownVersion
			}
			if err != nil {
				return err
			}
			list[i].Version = name
		}
	}
	return nil
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

// Create stores a new draft, numbering it <prefix>-<year>-<NNNN>.
func (r *Repository) Create(ctx context.Context, a Advisory, prefix string, actor *string) (Advisory, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Advisory{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if err := resolveVersions(ctx, tx, &a); err != nil {
		return Advisory{}, err
	}
	// Serialize numbering across replicas.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('psirt_tracking_id'))`); err != nil {
		return Advisory{}, err
	}
	stem := fmt.Sprintf("%s-%d-", prefix, time.Now().UTC().Year())
	var next int
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(max(substring(tracking_id FROM length($1) + 1)::int), 0) + 1
		FROM psirt_advisories WHERE tracking_id LIKE $1 || '%' AND substring(tracking_id FROM length($1) + 1) ~ '^[0-9]+$'`,
		stem).Scan(&next); err != nil {
		return Advisory{}, fmt.Errorf("number advisory: %w", err)
	}
	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO psirt_advisories (project_id, tracking_id, title, product_name, summary, details, cve, cwe,
			cwe_name, cvss_vector, affected, fixed, remediation, acknowledgments, source_advisory_id, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16) RETURNING id`,
		a.ProjectID, fmt.Sprintf("%s%04d", stem, next), a.Title, a.ProductName, a.Summary, a.Details, a.CVE, a.CWE,
		a.CWEName, a.CVSSVector, mustJSON(a.Affected), mustJSON(a.Fixed), a.Remediation, mustJSON(a.Acknowledgments),
		a.SourceAdvisoryID, actor).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return Advisory{}, ErrNoProject
		}
		return Advisory{}, fmt.Errorf("insert advisory: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Advisory{}, err
	}
	return r.Get(ctx, id)
}

// Update replaces a draft's or published advisory's editable fields (a
// published advisory's distributed document changes only on republish). A
// withdrawn advisory is final.
func (r *Repository) Update(ctx context.Context, a Advisory) (Advisory, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Advisory{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	var state State
	if err := tx.QueryRow(ctx, `SELECT project_id, state FROM psirt_advisories WHERE id = $1 FOR UPDATE`, a.ID).
		Scan(&a.ProjectID, &state); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Advisory{}, ErrNotFound
		}
		return Advisory{}, err
	}
	if state == StateWithdrawn {
		return Advisory{}, ErrState
	}
	if err := resolveVersions(ctx, tx, &a); err != nil {
		return Advisory{}, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE psirt_advisories SET title = $2, product_name = $3, summary = $4, details = $5, cve = $6, cwe = $7,
			cwe_name = $8, cvss_vector = $9, affected = $10, fixed = $11, remediation = $12, acknowledgments = $13,
			updated_at = clock_timestamp()
		WHERE id = $1`,
		a.ID, a.Title, a.ProductName, a.Summary, a.Details, a.CVE, a.CWE, a.CWEName, a.CVSSVector,
		mustJSON(a.Affected), mustJSON(a.Fixed), a.Remediation, mustJSON(a.Acknowledgments)); err != nil {
		return Advisory{}, fmt.Errorf("update advisory: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Advisory{}, err
	}
	return r.Get(ctx, a.ID)
}

// Delete removes a draft that was never published (a published advisory may
// only be withdrawn: consumers already have it).
func (r *Repository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM psirt_advisories WHERE id = $1 AND version = 0`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		if _, err := r.Get(ctx, id); err != nil {
			return err
		}
		return ErrState
	}
	return nil
}

// release appends a revision and freezes the rendered document, inside one
// transaction holding the advisory's row lock. note names the revision given
// the advisory's new version; render receives the advisory with its new
// revision history and version.
func (r *Repository) release(ctx context.Context, id string, to State, actor *string, allowed func(State) bool,
	note func(version int) (string, error), render func(Advisory) (json.RawMessage, error)) (Advisory, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Advisory{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	a, err := scanAdvisory(tx.QueryRow(ctx, `SELECT `+advisoryColumns+advisoryFrom+` WHERE a.id = $1 FOR UPDATE OF a`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Advisory{}, ErrNotFound
	}
	if err != nil {
		return Advisory{}, err
	}
	if !allowed(a.State) {
		return Advisory{}, ErrState
	}
	if a.Revisions, err = revisions(ctx, tx, id); err != nil {
		return Advisory{}, err
	}
	// Second precision: CSAF dates are compared by consumers as given, and
	// the frozen document must say exactly what the database does.
	now := time.Now().UTC().Truncate(time.Second)
	a.Version++
	a.State = to
	if a.InitialReleaseAt == nil {
		a.InitialReleaseAt = &now
	}
	a.CurrentReleaseAt = &now
	summary, err := note(a.Version)
	if err != nil {
		return Advisory{}, err
	}
	rev := Revision{Number: a.Version, Date: now, Summary: summary}
	a.Revisions = append(a.Revisions, rev)
	doc, err := render(a)
	if err != nil {
		return Advisory{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO psirt_revisions (advisory_id, number, date, summary, actor_id) VALUES ($1,$2,$3,$4,$5)`,
		id, rev.Number, rev.Date, rev.Summary, actor); err != nil {
		return Advisory{}, fmt.Errorf("revision: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		UPDATE psirt_advisories SET state = $2, version = $3, initial_release_at = $4, current_release_at = $5,
			document = $6, updated_at = $5
		WHERE id = $1`, id, a.State, a.Version, a.InitialReleaseAt, a.CurrentReleaseAt, []byte(doc)); err != nil {
		return Advisory{}, fmt.Errorf("release: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Advisory{}, err
	}
	return r.Get(ctx, id)
}

// Document returns the frozen CSAF document of a published (or withdrawn)
// advisory.
func (r *Repository) Document(ctx context.Context, id string) (json.RawMessage, error) {
	var doc []byte
	err := r.db.QueryRow(ctx, `SELECT document FROM psirt_advisories WHERE id = $1`, id).Scan(&doc)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if doc == nil {
		return nil, ErrNotPublished
	}
	return doc, nil
}

// Distributed is one released document in the provider directory.
type Distributed struct {
	TrackingID       string
	InitialReleaseAt time.Time
	CurrentReleaseAt time.Time
	Document         json.RawMessage
}

// Released lists every published or withdrawn advisory's frozen document,
// most recently released first.
func (r *Repository) Released(ctx context.Context) ([]Distributed, error) {
	rows, err := r.db.Query(ctx, `
		SELECT tracking_id, initial_release_at, current_release_at, document FROM psirt_advisories
		WHERE document IS NOT NULL ORDER BY current_release_at DESC, tracking_id`)
	if err != nil {
		return nil, fmt.Errorf("released advisories: %w", err)
	}
	defer rows.Close()
	out := []Distributed{}
	for rows.Next() {
		var d Distributed
		var doc []byte
		if err := rows.Scan(&d.TrackingID, &d.InitialReleaseAt, &d.CurrentReleaseAt, &doc); err != nil {
			return nil, err
		}
		d.Document = doc
		out = append(out, d)
	}
	return out, rows.Err()
}
