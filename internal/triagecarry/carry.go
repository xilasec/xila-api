// Package triagecarry carries manual triage decisions (a false positive, a
// won't-fix, or reopening either of those) across a project's branches and to
// new versions — opt-in per project (M13 13.1).
//
// A finding is unique per (version, fingerprint), and each version has its own
// lifecycle: triage a false positive on a feature branch and the same issue
// comes back as "open" on main after the merge, and a new release starts from
// scratch. With carry enabled, the decision made on one version reaches every
// other in-scope version of the project that still has the issue open or
// confirmed, and reaches a brand-new finding (a new scan, or a new version's
// first scan) the moment it is ingested.
//
// Only false_positive, wont_fix and their reopen (open) carry — see Eligible.
// A risk acceptance deliberately never carries: it is a decision about one
// version's exposure, not a statement that the finding itself is wrong or
// fixed everywhere (see README/CLAUDE.md). confirmed and remediated don't
// carry either: confirmed only affirms the scanner's own default, and
// remediated means the scanner itself stopped reporting it on that version,
// which says nothing about any other version.
//
// The most recent decision per fingerprint wins, and a decision never
// overturns a more recent one already on its specific target — see
// Service.applyDecision.
package triagecarry

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
)

// Decision is one project's canonical carried decision for a fingerprint: the
// most recent eligible status change made anywhere in the project's in-scope
// versions. Kept so a carry can be explained (who decided what, where, when)
// and reapplied idempotently.
type Decision struct {
	ProjectID   string
	Fingerprint string
	Status      domain.FindingStatus
	Reason      string
	ExpiresAt   *time.Time
	// VexJustification and VexResponse are the decision's structured
	// analysis (13.2), applied with it.
	VexJustification domain.VexJustification
	VexResponse      []domain.VexResponse
	Actor            string
	SourceFindingID  string
	SourceVersionID  string
	SourceBranch     string
	DecidedAt        time.Time
}

// Repository stores each project's canonical carried decision per fingerprint
// (triage_carries: one row per (project_id, fingerprint)).
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

// Upsert records d as the latest known decision for its (project,
// fingerprint). A decision already on file that is at least as recent as d
// wins instead: recorded reports false and nothing is written, so a replayed
// or out-of-order event is a no-op.
func (r *Repository) Upsert(ctx context.Context, d Decision) (recorded bool, err error) {
	tag, err := r.db.Exec(ctx, `
		INSERT INTO triage_carries (project_id, fingerprint, status, reason, expires_at,
			actor, source_finding_id, source_version_id, source_branch, decided_at,
			vex_justification, vex_response, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now())
		ON CONFLICT (project_id, fingerprint) DO UPDATE SET
			status = $3, reason = $4, expires_at = $5, actor = $6,
			source_finding_id = $7, source_version_id = $8, source_branch = $9,
			decided_at = $10, vex_justification = $11, vex_response = $12, updated_at = now()
		WHERE triage_carries.decided_at < $10`,
		d.ProjectID, d.Fingerprint, d.Status, d.Reason, d.ExpiresAt, d.Actor,
		nullableUUID(d.SourceFindingID), nullableUUID(d.SourceVersionID), d.SourceBranch, d.DecidedAt,
		d.VexJustification, vexResponseStrings(d.VexResponse))
	if err != nil {
		return false, fmt.Errorf("record carried decision: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// Get returns the canonical decision for one fingerprint of a project, if any.
func (r *Repository) Get(ctx context.Context, projectID, fingerprint string) (Decision, bool, error) {
	var d Decision
	var sourceFindingID, sourceVersionID *string
	var response []string
	err := r.db.QueryRow(ctx, `
		SELECT project_id, fingerprint, status, reason, expires_at, actor,
			source_finding_id::text, source_version_id::text, source_branch, decided_at,
			vex_justification, vex_response
		FROM triage_carries WHERE project_id = $1 AND fingerprint = $2`,
		projectID, fingerprint).
		Scan(&d.ProjectID, &d.Fingerprint, &d.Status, &d.Reason, &d.ExpiresAt, &d.Actor,
			&sourceFindingID, &sourceVersionID, &d.SourceBranch, &d.DecidedAt,
			&d.VexJustification, &response)
	if errors.Is(err, pgx.ErrNoRows) {
		return Decision{}, false, nil
	}
	if err != nil {
		return Decision{}, false, fmt.Errorf("get carried decision: %w", err)
	}
	for _, v := range response {
		d.VexResponse = append(d.VexResponse, domain.VexResponse(v))
	}
	if sourceFindingID != nil {
		d.SourceFindingID = *sourceFindingID
	}
	if sourceVersionID != nil {
		d.SourceVersionID = *sourceVersionID
	}
	return d, true, nil
}

func nullableUUID(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// vexResponseStrings is rs as the text[] the column holds (never NULL).
func vexResponseStrings(rs []domain.VexResponse) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, string(r))
	}
	return out
}
