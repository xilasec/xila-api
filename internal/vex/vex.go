// Package vex stores and applies VEX (Vulnerability Exploitability eXchange)
// statements: an authoritative analysis of whether a vulnerability actually
// affects a product.
//
// This answers the most expensive question in vulnerability management. A scanner
// can only tell you a vulnerable package is *present*; it cannot tell you whether
// the vulnerable code path exists in your build, or whether you already mitigated
// it. VEX is where that judgement — from an upstream vendor, or from your own team,
// made once — gets written down. Statements persist and are re-applied on every
// ingest, so a CVE analysed as not-affected does not come back to the queue the
// next time a scanner reports it.
package vex

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
)

// ErrNotFound is returned when a statement does not exist.
var ErrNotFound = errors.New("vex statement not found")

// ErrNoProject is returned when a statement references a missing project.
var ErrNoProject = errors.New("project not found")

// Status is a VEX analysis outcome (the four states OpenVEX and CycloneDX agree on).
type Status string

const (
	// StatusNotAffected: the vulnerable component is present but cannot be exploited here.
	StatusNotAffected Status = "not_affected"
	// StatusAffected: confirmed to affect this product — the opposite of noise.
	StatusAffected Status = "affected"
	// StatusFixed: this build already contains the fix.
	StatusFixed Status = "fixed"
	// StatusUnderInvestigation: no conclusion yet; changes nothing.
	StatusUnderInvestigation Status = "under_investigation"
)

var statuses = []Status{StatusNotAffected, StatusAffected, StatusFixed, StatusUnderInvestigation}

// Valid reports whether s is a known VEX status.
func (s Status) Valid() bool {
	for _, x := range statuses {
		if x == s {
			return true
		}
	}
	return false
}

// Statement is one analysis: for this project, vulnerability X against product Y
// has status Z, because J.
type Statement struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	// VulnID is the advisory as it names itself (CVE-…, GHSA-…).
	VulnID string `json:"vuln_id"`
	// Product is a PURL or package name. Empty means every product in the project —
	// which is what a document that names only a CVE amounts to.
	Product       string    `json:"product"`
	Status        Status    `json:"status"`
	Justification string    `json:"justification"`
	Detail        string    `json:"detail"`
	Source        string    `json:"source"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Repository provides access to the vex_statements table.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository { return &Repository{db: db} }

const statementColumns = `id, project_id, vuln_id, product, status, justification, detail,
	source, created_at, updated_at`

func scanStatement(row pgx.Row) (Statement, error) {
	var s Statement
	err := row.Scan(&s.ID, &s.ProjectID, &s.VulnID, &s.Product, &s.Status, &s.Justification,
		&s.Detail, &s.Source, &s.CreatedAt, &s.UpdatedAt)
	return s, err
}

// Upsert stores a statement, replacing any prior analysis of the same
// (project, vulnerability, product) — a re-uploaded document is a correction, not
// an addition.
func (r *Repository) Upsert(ctx context.Context, s Statement) (Statement, error) {
	const q = `
		INSERT INTO vex_statements (project_id, vuln_id, product, status, justification, detail, source)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (project_id, vuln_id, product) DO UPDATE SET
			status = EXCLUDED.status, justification = EXCLUDED.justification,
			detail = EXCLUDED.detail, source = EXCLUDED.source, updated_at = now()
		RETURNING ` + statementColumns
	out, err := scanStatement(r.db.QueryRow(ctx, q,
		s.ProjectID, s.VulnID, s.Product, s.Status, s.Justification, s.Detail, s.Source))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23503" {
		return Statement{}, ErrNoProject
	}
	if err != nil {
		return Statement{}, fmt.Errorf("upsert vex statement: %w", err)
	}
	return out, nil
}

// ListByProject returns a project's statements, newest first.
func (r *Repository) ListByProject(ctx context.Context, projectID string) ([]Statement, error) {
	const q = `SELECT ` + statementColumns + ` FROM vex_statements
		WHERE project_id = $1 ORDER BY created_at DESC`
	rows, err := r.db.Query(ctx, q, projectID)
	if err != nil {
		return nil, fmt.Errorf("list vex statements: %w", err)
	}
	defer rows.Close()

	out := []Statement{}
	for rows.Next() {
		s, err := scanStatement(rows)
		if err != nil {
			return nil, fmt.Errorf("scan vex statement: %w", err)
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// Delete removes a statement; the next ingest stops suppressing what it covered.
func (r *Repository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM vex_statements WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete vex statement: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ErrNoVersion is returned when an export names a version the project lacks.
var ErrNoVersion = errors.New("project version not found")

// ExportScope resolves what an export speaks about: the project, and the version
// named by versionID or branch (neither = the project's default version). A
// project that has no version yet exports as an empty "main". userID names the
// requester, recorded as the document's author.
func (r *Repository) ExportScope(ctx context.Context, projectID, versionID, branch, userID string) (ExportScope, error) {
	const q = `
		SELECT p.slug, p.name, COALESCE(v.id::text, ''), COALESCE(v.name, ''),
		       COALESCE((SELECT email FROM users WHERE id::text = $4), '')
		FROM projects p
		LEFT JOIN project_versions v ON v.project_id = p.id AND CASE
			WHEN $2 <> '' THEN v.id::text = $2
			WHEN $3 <> '' THEN v.name = $3
			ELSE v.is_default END
		WHERE p.id = $1`
	s := ExportScope{ProjectID: projectID}
	err := r.db.QueryRow(ctx, q, projectID, versionID, branch, userID).
		Scan(&s.ProjectSlug, &s.ProjectName, &s.VersionID, &s.VersionName, &s.Author)
	if errors.Is(err, pgx.ErrNoRows) {
		return ExportScope{}, ErrNoProject
	}
	if err != nil {
		return ExportScope{}, fmt.Errorf("vex export scope: %w", err)
	}
	if s.VersionID == "" {
		if versionID != "" || branch != "" {
			return ExportScope{}, ErrNoVersion
		}
		s.VersionName = "main"
	}
	return s, nil
}

// ExportFindings returns the version's findings a VEX export speaks about: every
// non-duplicate one that carries a CVE or a CVE/GHSA rule id, each with the time
// its triage last changed (its latest status event, else when last seen).
func (r *Repository) ExportFindings(ctx context.Context, projectID, versionID string) ([]ExportFinding, error) {
	if versionID == "" {
		return []ExportFinding{}, nil
	}
	q := `
		SELECT f.id, f.project_id, f.version_id, f.scanner, f.rule_id, f.title, f.severity, f.cve,
		       f.package_name, f.package_version, f.fixed_version, f.purl, f.status,
		       COALESCE(acc.justification, f.exception_reason), COALESCE(acc.approver, f.exception_by),
		       COALESCE(acc.expires_at, f.exception_expires_at), f.last_seen_at,
		       COALESCE((SELECT max(e.created_at) FROM finding_events e
		                 WHERE e.finding_id = f.id AND e.kind = 'status'), f.last_seen_at)
		FROM findings f
		LEFT JOIN LATERAL (
			-- A risk_accepted finding's reason and expiry are its approved acceptance's.
			SELECT ra.justification, ra.approver, ra.expires_at
			FROM risk_acceptance_findings ram JOIN risk_acceptances ra ON ra.id = ram.acceptance_id
			WHERE ram.finding_id = f.id AND ram.removed_at IS NULL AND ra.state = 'approved'
		) acc ON f.status = 'risk_accepted'
		WHERE f.project_id = $1 AND f.version_id = $2 AND f.duplicate_of IS NULL AND` + archive.Finding("f") + `
		  AND (cardinality(f.cve) > 0 OR f.rule_id ~* '^(CVE|GHSA)-')
		ORDER BY f.id`
	rows, err := r.db.Query(ctx, q, projectID, versionID)
	if err != nil {
		return nil, fmt.Errorf("vex export findings: %w", err)
	}
	defer rows.Close()
	out := []ExportFinding{}
	for rows.Next() {
		var e ExportFinding
		f := &e.Finding
		if err := rows.Scan(&f.ID, &f.ProjectID, &f.VersionID, &f.Scanner, &f.RuleID, &f.Title, &f.Severity, &f.CVE,
			&f.PackageName, &f.PackageVersion, &f.FixedVersion, &f.Purl, &f.Status,
			&f.ExceptionReason, &f.ExceptionBy, &f.ExceptionExpiresAt, &f.LastSeenAt, &e.TriagedAt); err != nil {
			return nil, fmt.Errorf("scan vex export finding: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
