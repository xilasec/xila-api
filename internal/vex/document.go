package vex

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
)

// ScopeKind is how a stored VEX document's product set is chosen.
type ScopeKind string

const (
	// ScopeProject names one project version.
	ScopeProject ScopeKind = "project"
	// ScopeVersions names several versions/branches of one project.
	ScopeVersions ScopeKind = "versions"
	// ScopeVulnerability names one CVE/GHSA across every project (admin-only
	// to create: it reads and documents every project's data, not just one
	// the caller edits).
	ScopeVulnerability ScopeKind = "vulnerability"
)

var scopeKinds = []ScopeKind{ScopeProject, ScopeVersions, ScopeVulnerability}

// Target is one project version a project/versions-scope document names:
// either an explicit version, or a branch name resolved live at publish
// (so a document tracks a renamed-in-place branch; a deleted one fails the
// next publish rather than silently going stale).
type Target struct {
	VersionID string `json:"version_id,omitempty"`
	Branch    string `json:"branch,omitempty"`
}

// DocRevisionMeta is one entry of a document's revision history, as the API
// reports it (the rendered content itself is fetched separately).
type DocRevisionMeta struct {
	Number      int       `json:"number"`
	PublishedAt time.Time `json:"published_at"`
}

// Document is a stored, versioned VEX document: configured once, (re-)published
// on demand from current data.
type Document struct {
	ID          string    `json:"id"`
	DocumentID  string    `json:"document_id"`
	Format      string    `json:"format"`
	SpecVersion string    `json:"spec_version,omitempty"`
	ScopeKind   ScopeKind `json:"scope_kind"`
	// ProjectID/Slug/Name are set for scope=project/versions; empty for
	// scope=vulnerability (which spans every project).
	ProjectID   string   `json:"project_id,omitempty"`
	ProjectSlug string   `json:"project_slug,omitempty"`
	ProjectName string   `json:"project_name,omitempty"`
	Targets     []Target `json:"targets,omitempty"`
	// VulnID is set only for scope=vulnerability.
	VulnID             string            `json:"vuln_id,omitempty"`
	Author             string            `json:"author"`
	PublisherName      string            `json:"publisher_name"`
	PublisherNamespace string            `json:"publisher_namespace"`
	PublisherContact   string            `json:"publisher_contact"`
	ContentHash        string            `json:"-"`
	Serial             string            `json:"-"`
	Version            int               `json:"version"`
	PublishedAt        *time.Time        `json:"published_at"`
	Revisions          []DocRevisionMeta `json:"revisions,omitempty"`
	CreatedBy          *string           `json:"created_by"`
	CreatedAt          time.Time         `json:"created_at"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

// Errors returned by the document repository and service.
var (
	ErrDocNotFound       = errors.New("vex document not found")
	ErrDocUnknownVersion = errors.New("a target names a version that is not a version of this project")
	ErrDocForbidden      = errors.New("not allowed to manage this document")
	ErrDocNotPublished   = errors.New("the document has never been published")
	ErrDocNoRevision     = errors.New("revision not found")
)

// Validate checks and normalizes the editable fields.
func (d *Document) Validate() error {
	d.Format = strings.ToLower(strings.TrimSpace(d.Format))
	if !slices.Contains(ExportFormats, d.Format) {
		return fmt.Errorf("format must be one of: %s", strings.Join(ExportFormats, ", "))
	}
	d.SpecVersion = strings.TrimSpace(d.SpecVersion)
	if d.SpecVersion != "" {
		if d.Format != FormatCycloneDX {
			return errors.New("spec_version only applies to the cyclonedx format")
		}
		if !slices.Contains(CDXSpecVersions, d.SpecVersion) {
			return fmt.Errorf("spec_version must be one of: %s", strings.Join(CDXSpecVersions, ", "))
		}
	}
	d.ScopeKind = ScopeKind(strings.ToLower(strings.TrimSpace(string(d.ScopeKind))))
	if !slices.Contains(scopeKinds, d.ScopeKind) {
		return fmt.Errorf("scope must be one of: %s, %s, %s", ScopeProject, ScopeVersions, ScopeVulnerability)
	}
	if d.ScopeKind != ScopeProject && d.Format == FormatCycloneDX {
		return errors.New("cyclonedx only supports a project-scope document with a single target")
	}

	switch d.ScopeKind {
	case ScopeVulnerability:
		d.VulnID = strings.ToUpper(strings.TrimSpace(d.VulnID))
		if d.VulnID == "" {
			return errors.New("vuln_id is required for a vulnerability-scope document")
		}
		d.ProjectID, d.Targets = "", nil
	case ScopeProject, ScopeVersions:
		d.VulnID = ""
		if d.ProjectID == "" {
			return errors.New("project_id is required")
		}
		if d.ScopeKind == ScopeProject && len(d.Targets) != 1 {
			return errors.New("a project-scope document names exactly one version or branch")
		}
		if d.ScopeKind == ScopeVersions && len(d.Targets) == 0 {
			return errors.New("a versions-scope document names at least one version or branch")
		}
		for i := range d.Targets {
			t := &d.Targets[i]
			t.VersionID = strings.TrimSpace(t.VersionID)
			t.Branch = strings.TrimSpace(t.Branch)
			if (t.VersionID == "") == (t.Branch == "") {
				return errors.New("each target names exactly one of version_id or branch")
			}
		}
	}

	d.Author = strings.TrimSpace(d.Author)
	d.PublisherName = strings.TrimSpace(d.PublisherName)
	d.PublisherNamespace = strings.TrimRight(strings.TrimSpace(d.PublisherNamespace), "/")
	d.PublisherContact = strings.TrimSpace(d.PublisherContact)
	return nil
}

// DocumentRepository stores VEX documents and their frozen revisions. It
// reuses *Repository's export queries (ExportScope, ExportFindings,
// ListByProject) and the package's export builders to render a document's
// content — never a second mapping of findings onto VEX statements.
type DocumentRepository struct {
	db  *pgxpool.Pool
	vex *Repository
}

// NewDocumentRepository constructs a DocumentRepository.
func NewDocumentRepository(db *pgxpool.Pool, vex *Repository) *DocumentRepository {
	return &DocumentRepository{db: db, vex: vex}
}

const documentColumns = `d.id, d.document_id, d.format, d.spec_version, d.scope_kind, d.project_id,
	COALESCE(p.slug, ''), COALESCE(p.name, ''), d.targets, COALESCE(d.vuln_id, ''),
	d.author, d.publisher_name, d.publisher_namespace, d.publisher_contact, d.serial,
	d.content_hash, d.version, d.published_at, d.created_by, d.created_at, d.updated_at`

const documentFrom = ` FROM vex_documents d LEFT JOIN projects p ON p.id = d.project_id`

func scanDocument(row pgx.Row) (Document, error) {
	var d Document
	var targets []byte
	err := row.Scan(&d.ID, &d.DocumentID, &d.Format, &d.SpecVersion, &d.ScopeKind, &d.ProjectID,
		&d.ProjectSlug, &d.ProjectName, &targets, &d.VulnID,
		&d.Author, &d.PublisherName, &d.PublisherNamespace, &d.PublisherContact, &d.Serial,
		&d.ContentHash, &d.Version, &d.PublishedAt, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt)
	if err != nil {
		return d, err
	}
	if err := json.Unmarshal(targets, &d.Targets); err != nil {
		return d, fmt.Errorf("decode vex document targets: %w", err)
	}
	if d.Targets == nil {
		d.Targets = []Target{}
	}
	d.Revisions = []DocRevisionMeta{}
	return d, nil
}

// Filter narrows List.
type Filter struct {
	// AllAccess (instance admin) lists every document, including
	// vulnerability-scope ones. Otherwise only project/versions-scope
	// documents in ProjectIDs are returned.
	AllAccess  bool
	ProjectIDs []string
	Limit      int
	Offset     int
}

// List returns documents, most recently updated first.
func (r *DocumentRepository) List(ctx context.Context, f Filter) ([]Document, error) {
	rows, err := r.db.Query(ctx, `SELECT `+documentColumns+documentFrom+`
		WHERE $1 OR (d.scope_kind <> 'vulnerability' AND d.project_id::text = ANY($2))
		ORDER BY d.updated_at DESC, d.id LIMIT $3 OFFSET $4`,
		f.AllAccess, f.ProjectIDs, f.Limit, f.Offset)
	if err != nil {
		return nil, fmt.Errorf("list vex documents: %w", err)
	}
	defer rows.Close()
	out := []Document{}
	for rows.Next() {
		d, err := scanDocument(rows)
		if err != nil {
			return nil, fmt.Errorf("scan vex document: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

type querier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func revisionMetas(ctx context.Context, q querier, id string) ([]DocRevisionMeta, error) {
	rows, err := q.Query(ctx, `SELECT number, published_at FROM vex_document_revisions
		WHERE document_id = $1 ORDER BY number`, id)
	if err != nil {
		return nil, fmt.Errorf("list vex document revisions: %w", err)
	}
	defer rows.Close()
	out := []DocRevisionMeta{}
	for rows.Next() {
		var rev DocRevisionMeta
		if err := rows.Scan(&rev.Number, &rev.PublishedAt); err != nil {
			return nil, err
		}
		out = append(out, rev)
	}
	return out, rows.Err()
}

// Get returns one document with its revision history.
func (r *DocumentRepository) Get(ctx context.Context, id string) (Document, error) {
	d, err := scanDocument(r.db.QueryRow(ctx, `SELECT `+documentColumns+documentFrom+` WHERE d.id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Document{}, ErrDocNotFound
	}
	if err != nil {
		return Document{}, fmt.Errorf("get vex document: %w", err)
	}
	d.Revisions, err = revisionMetas(ctx, r.db, id)
	return d, err
}

func marshalTargets(ts []Target) []byte {
	if ts == nil {
		ts = []Target{}
	}
	b, _ := json.Marshal(ts)
	return b
}

// validateTargets checks the project exists and every explicit version_id
// belongs to it (a branch name is resolved live at publish instead).
func validateTargets(ctx context.Context, q querier, d Document) error {
	if d.ScopeKind == ScopeVulnerability {
		return nil
	}
	var exists bool
	err := q.QueryRow(ctx, `SELECT true FROM projects WHERE id = $1`, d.ProjectID).Scan(&exists)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoProject
	}
	if err != nil {
		return err
	}
	for _, t := range d.Targets {
		if t.VersionID == "" {
			continue
		}
		var ok bool
		err := q.QueryRow(ctx, `SELECT true FROM project_versions WHERE id::text = $1 AND project_id = $2`,
			t.VersionID, d.ProjectID).Scan(&ok)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrDocUnknownVersion
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Create stores a new, unpublished document, numbering it <prefix>-<year>-<NNNN>.
func (r *DocumentRepository) Create(ctx context.Context, d Document, prefix string, actor *string) (Document, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Document{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if err := validateTargets(ctx, tx, d); err != nil {
		return Document{}, err
	}
	// Serialize numbering across replicas.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('vex_document_id'))`); err != nil {
		return Document{}, err
	}
	stem := fmt.Sprintf("%s-%d-", prefix, time.Now().UTC().Year())
	var next int
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(max(substring(document_id FROM length($1) + 1)::int), 0) + 1
		FROM vex_documents WHERE document_id LIKE $1 || '%' AND substring(document_id FROM length($1) + 1) ~ '^[0-9]+$'`,
		stem).Scan(&next); err != nil {
		return Document{}, fmt.Errorf("number vex document: %w", err)
	}
	var projectID *string
	if d.ProjectID != "" {
		projectID = &d.ProjectID
	}
	var vulnID *string
	if d.VulnID != "" {
		vulnID = &d.VulnID
	}
	serial := uuid.NewString()
	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO vex_documents (document_id, format, spec_version, scope_kind, project_id, targets, vuln_id,
			author, publisher_name, publisher_namespace, publisher_contact, serial, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id`,
		fmt.Sprintf("%s%04d", stem, next), d.Format, d.SpecVersion, d.ScopeKind, projectID, marshalTargets(d.Targets), vulnID,
		d.Author, d.PublisherName, d.PublisherNamespace, d.PublisherContact, serial, actor).Scan(&id)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return Document{}, ErrNoProject
		}
		return Document{}, fmt.Errorf("insert vex document: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Document{}, err
	}
	return r.Get(ctx, id)
}

// Update replaces a document's editable fields. Its version, content hash and
// revision history are untouched: a scope or metadata change takes effect on
// the next publish, which will see different content and append a revision.
func (r *DocumentRepository) Update(ctx context.Context, d Document) (Document, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Document{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT true FROM vex_documents WHERE id = $1 FOR UPDATE`, d.ID).Scan(&exists); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Document{}, ErrDocNotFound
		}
		return Document{}, err
	}
	if err := validateTargets(ctx, tx, d); err != nil {
		return Document{}, err
	}
	var projectID *string
	if d.ProjectID != "" {
		projectID = &d.ProjectID
	}
	var vulnID *string
	if d.VulnID != "" {
		vulnID = &d.VulnID
	}
	if _, err := tx.Exec(ctx, `
		UPDATE vex_documents SET format = $2, spec_version = $3, scope_kind = $4, project_id = $5, targets = $6,
			vuln_id = $7, author = $8, publisher_name = $9, publisher_namespace = $10, publisher_contact = $11,
			updated_at = clock_timestamp()
		WHERE id = $1`,
		d.ID, d.Format, d.SpecVersion, d.ScopeKind, projectID, marshalTargets(d.Targets), vulnID,
		d.Author, d.PublisherName, d.PublisherNamespace, d.PublisherContact); err != nil {
		return Document{}, fmt.Errorf("update vex document: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Document{}, err
	}
	return r.Get(ctx, d.ID)
}

// Delete removes a document and its revisions.
func (r *DocumentRepository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM vex_documents WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete vex document: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrDocNotFound
	}
	return nil
}

// RevisionContent returns one revision's frozen, rendered content.
func (r *DocumentRepository) RevisionContent(ctx context.Context, documentID string, number int) (json.RawMessage, error) {
	var content []byte
	err := r.db.QueryRow(ctx, `SELECT content FROM vex_document_revisions WHERE document_id = $1 AND number = $2`,
		documentID, number).Scan(&content)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDocNoRevision
	}
	if err != nil {
		return nil, fmt.Errorf("vex document revision content: %w", err)
	}
	return content, nil
}

// ProjectsWithVuln returns every project with a current finding or a stored
// VEX statement naming vulnID, for a vulnerability-scope document's render.
func (r *DocumentRepository) ProjectsWithVuln(ctx context.Context, vulnID string) ([]string, error) {
	q := `
		SELECT DISTINCT f.project_id FROM findings f
		JOIN project_versions v ON v.id = f.version_id AND v.is_default
		WHERE f.duplicate_of IS NULL AND ` + archive.Finding("f") + ` AND (
			EXISTS (SELECT 1 FROM unnest(f.cve) c WHERE upper(c) = upper($1)) OR upper(f.rule_id) = upper($1)
		)
		UNION
		SELECT DISTINCT vs.project_id FROM vex_statements vs WHERE upper(vs.vuln_id) = upper($1)`
	rows, err := r.db.Query(ctx, q, vulnID)
	if err != nil {
		return nil, fmt.Errorf("projects with vuln: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var pid string
		if err := rows.Scan(&pid); err != nil {
			return nil, err
		}
		out = append(out, pid)
	}
	return out, rows.Err()
}

// resolve derives the (scope, statements) a document's render speaks about,
// reusing *Repository's export queries and BuildStatements — the exact
// mapping an ad hoc /projects/{id}/vex/export uses, never a second one.
func (r *DocumentRepository) resolve(ctx context.Context, d Document) (ExportScope, []ExportStatement, error) {
	switch d.ScopeKind {
	case ScopeProject:
		t := d.Targets[0]
		scope, err := r.vex.ExportScope(ctx, d.ProjectID, t.VersionID, t.Branch, "")
		if err != nil {
			return ExportScope{}, nil, err
		}
		findings, err := r.vex.ExportFindings(ctx, d.ProjectID, scope.VersionID)
		if err != nil {
			return ExportScope{}, nil, err
		}
		stored, err := r.vex.ListByProject(ctx, d.ProjectID)
		if err != nil {
			return ExportScope{}, nil, err
		}
		scope.Title = fmt.Sprintf("VEX for %s (%s)", cmpOr(scope.ProjectName, scope.ProjectSlug), scope.VersionName)
		return scope, BuildStatements(scope, findings, stored), nil

	case ScopeVersions:
		var base ExportScope
		groups := make([][]ExportStatement, 0, len(d.Targets))
		for i, t := range d.Targets {
			scope, err := r.vex.ExportScope(ctx, d.ProjectID, t.VersionID, t.Branch, "")
			if err != nil {
				return ExportScope{}, nil, err
			}
			if i == 0 {
				base = scope
			}
			findings, err := r.vex.ExportFindings(ctx, d.ProjectID, scope.VersionID)
			if err != nil {
				return ExportScope{}, nil, err
			}
			stored, err := r.vex.ListByProject(ctx, d.ProjectID)
			if err != nil {
				return ExportScope{}, nil, err
			}
			groups = append(groups, BuildStatements(scope, findings, stored))
		}
		base.VersionID, base.VersionName = "", ""
		base.Title = fmt.Sprintf("VEX for %s across %d version(s)", cmpOr(base.ProjectName, base.ProjectSlug), len(d.Targets))
		return base, MergeStatements(groups...), nil

	case ScopeVulnerability:
		projectIDs, err := r.ProjectsWithVuln(ctx, d.VulnID)
		if err != nil {
			return ExportScope{}, nil, err
		}
		groups := make([][]ExportStatement, 0, len(projectIDs))
		for _, pid := range projectIDs {
			scope, err := r.vex.ExportScope(ctx, pid, "", "", "")
			if err != nil {
				return ExportScope{}, nil, err
			}
			findings, err := r.vex.ExportFindings(ctx, pid, scope.VersionID)
			if err != nil {
				return ExportScope{}, nil, err
			}
			stored, err := r.vex.ListByProject(ctx, pid)
			if err != nil {
				return ExportScope{}, nil, err
			}
			groups = append(groups, FilterByVuln(BuildStatements(scope, findings, stored), d.VulnID))
		}
		scope := ExportScope{Title: fmt.Sprintf("VEX for %s across %d project(s)", d.VulnID, len(projectIDs))}
		return scope, MergeStatements(groups...), nil
	}
	return ExportScope{}, nil, fmt.Errorf("unknown scope kind %q", d.ScopeKind)
}

func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// epoch is the fixed reference timestamp a baseline rendering uses, so the
// content hash never changes merely because wall-clock time passed between
// two publishes.
var epoch = time.Unix(0, 0).UTC()

func render(format, specVersion string, scope ExportScope, stmts []ExportStatement, serial string, now time.Time) any {
	switch format {
	case FormatCycloneDX:
		spec := cmpOr(specVersion, CDXSpecVersions[0])
		return CycloneDXVEX(scope, stmts, serial, spec, now)
	case FormatCSAF:
		return CSAFVEX(scope, stmts, now)
	default:
		return OpenVEX(scope, stmts, now)
	}
}

func contentHash(doc any) (string, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Publish (re-)renders the document from current data and appends a revision
// only when the content actually changed since the last publish. The
// comparison hash is computed from a baseline rendering — version 1, no
// revision history, a fixed reference timestamp — so the comparison never
// sees the ever-growing revision history or the document's own publish-time
// noise; only the underlying findings/statements and the document's own
// configured identity (publisher, author, scope) can change it.
func (r *DocumentRepository) Publish(ctx context.Context, id string) (Document, bool, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return Document{}, false, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit

	d, err := scanDocument(tx.QueryRow(ctx, `SELECT `+documentColumns+documentFrom+` WHERE d.id = $1 FOR UPDATE OF d`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Document{}, false, ErrDocNotFound
	}
	if err != nil {
		return Document{}, false, err
	}
	if d.Revisions, err = revisionMetas(ctx, tx, id); err != nil {
		return Document{}, false, err
	}

	scope, stmts, err := r.resolve(ctx, d)
	if err != nil {
		return Document{}, false, err
	}
	scope.DocID = d.DocumentID
	scope.PublisherName, scope.PublisherNamespace, scope.PublisherContact = d.PublisherName, d.PublisherNamespace, d.PublisherContact
	if d.Author != "" {
		scope.Author = d.Author
	}

	baseline := scope
	baseline.TrackVersion, baseline.Revisions = 1, nil
	hash, err := contentHash(render(d.Format, d.SpecVersion, baseline, stmts, d.Serial, epoch))
	if err != nil {
		return Document{}, false, err
	}
	if hash == d.ContentHash && d.Version > 0 {
		return d, false, nil // no underlying change since the last publish
	}

	now := time.Now().UTC()
	d.Version++
	d.PublishedAt = &now
	d.Revisions = append(d.Revisions, DocRevisionMeta{Number: d.Version, PublishedAt: now})
	final := scope
	final.TrackVersion = d.Version
	for _, rev := range d.Revisions {
		final.Revisions = append(final.Revisions, DocRevision{Number: rev.Number, Date: rev.PublishedAt, Summary: "Published by Xila."})
	}
	rendered := render(d.Format, d.SpecVersion, final, stmts, d.Serial, now)
	content, err := json.Marshal(rendered)
	if err != nil {
		return Document{}, false, err
	}

	if _, err := tx.Exec(ctx, `INSERT INTO vex_document_revisions (document_id, number, published_at, content) VALUES ($1,$2,$3,$4)`,
		id, d.Version, now, content); err != nil {
		return Document{}, false, fmt.Errorf("insert vex document revision: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE vex_documents SET version = $2, content_hash = $3, published_at = $4, updated_at = $4
		WHERE id = $1`, id, d.Version, hash, now); err != nil {
		return Document{}, false, fmt.Errorf("publish vex document: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Document{}, false, err
	}
	d.ContentHash = hash
	return d, true, nil
}
