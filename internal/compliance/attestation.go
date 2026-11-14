package compliance

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// AttestationInput is what an attester records for a manual control.
type AttestationInput struct {
	Note        string
	EvidenceURL string
	ExpiresAt   *time.Time
}

// manualControl resolves a framework's control by code and checks that it is
// a manual one.
func (r *Repository) manualControl(ctx context.Context, frameworkKey, code string) (string, error) {
	var id, assessment string
	err := r.db.QueryRow(ctx, `
		SELECT c.id, c.assessment FROM controls c JOIN frameworks fw ON fw.id = c.framework_id
		WHERE fw.key = $1 AND c.code = $2`, frameworkKey, code).Scan(&id, &assessment)
	if errors.Is(err, pgx.ErrNoRows) {
		if _, ferr := r.framework(ctx, frameworkKey); ferr != nil {
			return "", ferr
		}
		return "", ErrControlNotFound
	}
	if err != nil {
		return "", fmt.Errorf("resolve control: %w", err)
	}
	if assessment != "manual" {
		return "", ErrNotManual
	}
	return id, nil
}

func (r *Repository) framework(ctx context.Context, key string) (string, error) {
	var id string
	err := r.db.QueryRow(ctx, `SELECT id FROM frameworks WHERE key = $1`, key).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrFrameworkNotFound
	}
	return id, err
}

// GetAttestation returns a project's attestation of a manual control.
func (r *Repository) GetAttestation(ctx context.Context, projectID, frameworkKey, code string) (Attestation, error) {
	cid, err := r.manualControl(ctx, frameworkKey, code)
	if err != nil {
		return Attestation{}, err
	}
	return r.attestation(ctx, projectID, cid)
}

func (r *Repository) attestation(ctx context.Context, projectID, controlID string) (Attestation, error) {
	var a Attestation
	err := r.db.QueryRow(ctx, `
		SELECT note, evidence_url, attested_by_email, attested_at, expires_at,
		       expires_at IS NOT NULL AND expires_at <= now()
		FROM control_attestations WHERE project_id = $1 AND control_id = $2`, projectID, controlID).
		Scan(&a.Note, &a.EvidenceURL, &a.AttestedBy, &a.AttestedAt, &a.ExpiresAt, &a.Expired)
	if errors.Is(err, pgx.ErrNoRows) {
		return Attestation{}, ErrNoAttestation
	}
	if err != nil {
		return Attestation{}, fmt.Errorf("get attestation: %w", err)
	}
	return a, nil
}

// Attest records (or replaces) how a project meets a manual control, by whom
// and when. Only manual controls take an attestation: a measured control's
// status comes from the evidence alone.
func (r *Repository) Attest(ctx context.Context, projectID, frameworkKey, code, userID string, in AttestationInput) (Attestation, error) {
	cid, err := r.manualControl(ctx, frameworkKey, code)
	if err != nil {
		return Attestation{}, err
	}
	if _, err := r.db.Exec(ctx, `
		INSERT INTO control_attestations (project_id, control_id, note, evidence_url, attested_by, attested_by_email, expires_at)
		VALUES ($1, $2, $3, $4, $5, COALESCE((SELECT email FROM users WHERE id = $5), ''), $6)
		ON CONFLICT (project_id, control_id) DO UPDATE SET
			note = EXCLUDED.note, evidence_url = EXCLUDED.evidence_url, attested_by = EXCLUDED.attested_by,
			attested_by_email = EXCLUDED.attested_by_email, attested_at = now(), expires_at = EXCLUDED.expires_at`,
		projectID, cid, in.Note, in.EvidenceURL, nullUUID(userID), in.ExpiresAt); err != nil {
		return Attestation{}, fmt.Errorf("attest control: %w", err)
	}
	return r.attestation(ctx, projectID, cid)
}

// RemoveAttestation withdraws a project's attestation of a manual control,
// returning the control to "to attest".
func (r *Repository) RemoveAttestation(ctx context.Context, projectID, frameworkKey, code string) error {
	cid, err := r.manualControl(ctx, frameworkKey, code)
	if err != nil {
		return err
	}
	tag, err := r.db.Exec(ctx, `DELETE FROM control_attestations WHERE project_id = $1 AND control_id = $2`, projectID, cid)
	if err != nil {
		return fmt.Errorf("remove attestation: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNoAttestation
	}
	return nil
}

func nullUUID(id string) *string {
	if id == "" {
		return nil
	}
	return &id
}

// ControlFinding is an open finding counted against a control.
type ControlFinding struct {
	ID       string  `json:"id"`
	Title    string  `json:"title"`
	Severity string  `json:"severity"`
	Scanner  string  `json:"scanner"`
	RuleID   string  `json:"rule_id"`
	CWE      *int    `json:"cwe"`
	FilePath string  `json:"file_path"`
	Priority float64 `json:"priority"`
}

// ControlFindings lists, per control code, the open findings that fail it —
// the same findings Evaluate counts — highest priority first, at most limit
// per control.
func (r *Repository) ControlFindings(ctx context.Context, projectID, frameworkKey string, limit int) (map[string][]ControlFinding, error) {
	q := `
		SELECT code, id, title, severity, scanner, rule_id, cwe, file_path, priority FROM (
			SELECT x.*, row_number() OVER (PARTITION BY x.code ORDER BY x.priority DESC, x.title, x.id) AS rn FROM (
				SELECT DISTINCT c.code, f.id, f.title, f.severity, f.scanner, f.rule_id, f.cwe, f.file_path, f.priority::float8 AS priority
				FROM frameworks fw
				JOIN controls c ON c.framework_id = fw.id AND c.assessment = 'automatic'
				JOIN ` + FindingMatchesSQL("f.project_id = $1") + ` x ON x.control_id = c.id
				JOIN findings f ON f.id = x.finding_id
				WHERE fw.key = $2
			) x
		) y WHERE rn <= $3 ORDER BY code, rn`
	rows, err := r.db.Query(ctx, q, projectID, frameworkKey, limit)
	if err != nil {
		return nil, fmt.Errorf("control findings: %w", err)
	}
	defer rows.Close()
	out := map[string][]ControlFinding{}
	for rows.Next() {
		var code string
		var f ControlFinding
		if err := rows.Scan(&code, &f.ID, &f.Title, &f.Severity, &f.Scanner, &f.RuleID, &f.CWE, &f.FilePath, &f.Priority); err != nil {
			return nil, fmt.Errorf("scan control finding: %w", err)
		}
		out[code] = append(out[code], f)
	}
	return out, rows.Err()
}
