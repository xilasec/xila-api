package membership

import (
	"context"
	"fmt"
)

// ProjectApprovalSetting returns a project's assessment-approval override
// ("inherit", "required" or "off"; M13 13.9) — inherit follows the
// instance-wide ASSESSMENT_REQUIRES_APPROVAL default (domain.ApprovalSetting
// resolves it).
func (r *Repository) ProjectApprovalSetting(ctx context.Context, projectID string) (string, error) {
	var s string
	if err := r.db.QueryRow(ctx, `SELECT assessment_approval FROM projects WHERE id = $1`, projectID).Scan(&s); err != nil {
		return "", fmt.Errorf("project approval setting: %w", err)
	}
	return s, nil
}

// AssessmentApprovers returns a project's designated approver user ids
// (groups expanded to their current members, deduplicated); empty means none
// are designated, so any project owner may decide (the original rule).
func (r *Repository) AssessmentApprovers(ctx context.Context, projectID string) ([]string, error) {
	const q = `
		SELECT DISTINCT COALESCE(a.user_id, m.user_id) AS user_id
		  FROM project_assessment_approvers a
		  LEFT JOIN user_group_members m ON m.group_id = a.group_id
		 WHERE a.project_id = $1 AND COALESCE(a.user_id, m.user_id) IS NOT NULL`
	return r.scanIDs(ctx, q, projectID)
}

// ApproverProjectIDs returns the ids of projects on which userID is a
// designated assessment approver, directly or through a group.
func (r *Repository) ApproverProjectIDs(ctx context.Context, userID string) ([]string, error) {
	const q = `
		SELECT DISTINCT a.project_id
		  FROM project_assessment_approvers a
		  LEFT JOIN user_group_members m ON m.group_id = a.group_id
		 WHERE a.user_id = $1 OR m.user_id = $1`
	return r.scanIDs(ctx, q, userID)
}

// ApproverGrant is one designated approver of a project (a user or a group,
// as stored — not expanded), for the project settings UI.
type ApproverGrant struct {
	UserID    *string `json:"user_id,omitempty"`
	Email     string  `json:"email,omitempty"`
	GroupID   *string `json:"group_id,omitempty"`
	GroupName string  `json:"group_name,omitempty"`
}

// ListAssessmentApproverGrants returns a project's designated approvers as
// stored, by email / group name.
func (r *Repository) ListAssessmentApproverGrants(ctx context.Context, projectID string) ([]ApproverGrant, error) {
	rows, err := r.db.Query(ctx, `
		SELECT a.user_id, COALESCE(u.email, ''), a.group_id, COALESCE(g.name, '')
		  FROM project_assessment_approvers a
		  LEFT JOIN users u ON u.id = a.user_id
		  LEFT JOIN user_groups g ON g.id = a.group_id
		 WHERE a.project_id = $1
		 ORDER BY u.email NULLS LAST, g.name NULLS LAST`, projectID)
	if err != nil {
		return nil, fmt.Errorf("list assessment approvers: %w", err)
	}
	defer rows.Close()
	out := []ApproverGrant{}
	for rows.Next() {
		var g ApproverGrant
		if err := rows.Scan(&g.UserID, &g.Email, &g.GroupID, &g.GroupName); err != nil {
			return nil, fmt.Errorf("scan assessment approver: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// SetAssessmentApproverGrants replaces a project's designated approvers with
// exactly userIDs and groupIDs (duplicates within either are ignored). Both
// empty restores "any project owner may decide".
func (r *Repository) SetAssessmentApproverGrants(ctx context.Context, projectID string, userIDs, groupIDs []string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after commit
	if _, err := tx.Exec(ctx, `DELETE FROM project_assessment_approvers WHERE project_id = $1`, projectID); err != nil {
		return fmt.Errorf("clear assessment approvers: %w", err)
	}
	if len(userIDs) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO project_assessment_approvers (project_id, user_id)
			SELECT DISTINCT $1::uuid, u FROM unnest($2::uuid[]) AS u`, projectID, userIDs); err != nil {
			return fmt.Errorf("set assessment approver users: %w", err)
		}
	}
	if len(groupIDs) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO project_assessment_approvers (project_id, group_id)
			SELECT DISTINCT $1::uuid, g FROM unnest($2::uuid[]) AS g`, projectID, groupIDs); err != nil {
			return fmt.Errorf("set assessment approver groups: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}
