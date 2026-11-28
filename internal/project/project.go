// Package project implements CRUD for projects (repositories/applications).
package project

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/archive"
	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/projecttree"
)

// Domain errors.
var (
	ErrNotFound  = errors.New("project not found")
	ErrDuplicate = errors.New("project slug already exists in team")
	ErrNoTeam    = errors.New("team does not exist")
	ErrNoParent  = errors.New("parent project does not exist")
	// ErrParentOrg: a parent must be in the child's organization.
	ErrParentOrg = errors.New("a parent project must be in the same organization")
	// ErrCycle: a project cannot be moved under itself or a descendant.
	ErrCycle = errors.New("a project cannot be its own ancestor")
	// ErrTooDeep: the tree would exceed projecttree.MaxDepth levels.
	ErrTooDeep = fmt.Errorf("a project tree is at most %d levels deep", projecttree.MaxDepth)
	// ErrNotEmpty: a project with scans or SBOMs cannot become a collection.
	ErrNotEmpty = errors.New("a project with scans or SBOMs cannot become a collection")
)

// Project is a repository or application being tracked — or, with
// IsCollection, a parent that holds no scans or SBOMs of its own and rolls up
// its descendants.
type Project struct {
	ID                  string             `json:"id"`
	TeamID              string             `json:"team_id"`
	ParentID            *string            `json:"parent_id"`
	IsCollection        bool               `json:"is_collection"`
	Slug                string             `json:"slug"`
	Name                string             `json:"name"`
	Description         string             `json:"description"`
	RepoURL             string             `json:"repo_url"`
	BusinessCriticality domain.Criticality `json:"business_criticality"`
	Tags                []string           `json:"tags"`
	// AITriageOptOut keeps the project's findings away from the AI triage
	// model (AI_TRIAGE_ENABLED): nothing of it is ever sent.
	AITriageOptOut bool `json:"ai_triage_opt_out"`
	// AssessmentApproval overrides the instance-wide ASSESSMENT_REQUIRES_APPROVAL
	// default for this project's manual assessments (inherit/required/off;
	// M13 13.9). Its designated approvers are managed separately
	// (GET/PUT /projects/{id}/assessment-approvers, internal/finding).
	AssessmentApproval domain.ApprovalSetting `json:"assessment_approval"`
	// Custom holds the project's custom-field values (internal/customfield).
	Custom    map[string]any `json:"custom"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	// ArchivedAt / ArchivedBy: set while the project is archived (internal/archive).
	ArchivedAt *time.Time `json:"archived_at"`
	ArchivedBy *string    `json:"archived_by"`
}

// Repository provides access to the projects table.
type Repository struct {
	db *pgxpool.Pool
}

// NewRepository constructs a Repository.
func NewRepository(db *pgxpool.Pool) *Repository {
	return &Repository{db: db}
}

const projectColumns = `id, team_id, parent_id, is_collection, slug, name, description, repo_url,
	business_criticality, tags, ai_triage_opt_out, assessment_approval, custom, created_at, updated_at, archived_at, archived_by`

func scanProject(row pgx.Row) (Project, error) {
	var p Project
	err := row.Scan(&p.ID, &p.TeamID, &p.ParentID, &p.IsCollection, &p.Slug, &p.Name, &p.Description, &p.RepoURL,
		&p.BusinessCriticality, &p.Tags, &p.AITriageOptOut, &p.AssessmentApproval, &p.Custom, &p.CreatedAt, &p.UpdatedAt, &p.ArchivedAt, &p.ArchivedBy)
	return p, err
}

// writeError maps the constraints a project write can break (including the
// projects_hierarchy trigger's) to domain errors.
func writeError(err error) error {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	if !ok {
		return nil
	}
	switch pgErr.ConstraintName {
	case "projects_parent_id_fkey":
		return ErrNoParent
	case "projects_team_id_fkey":
		return ErrNoTeam
	case "projects_parent_same_org":
		return ErrParentOrg
	case "projects_hierarchy_cycle", "projects_parent_not_self":
		return ErrCycle
	case "projects_hierarchy_depth":
		return ErrTooDeep
	case "projects_collection_empty":
		return ErrNotEmpty
	}
	if pgErr.Code == "23505" { // unique_violation
		return ErrDuplicate
	}
	return nil
}

// Create inserts a new project under a team (and, with ParentID, under a
// parent project of the same organization).
func (r *Repository) Create(ctx context.Context, p Project) (Project, error) {
	const q = `
		INSERT INTO projects (team_id, parent_id, is_collection, slug, name, description, repo_url, business_criticality, tags)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING ` + projectColumns
	out, err := scanProject(r.db.QueryRow(ctx, q,
		p.TeamID, p.ParentID, p.IsCollection, p.Slug, p.Name, p.Description, p.RepoURL, p.BusinessCriticality, p.Tags))
	if mapped := writeError(err); mapped != nil {
		return Project{}, mapped
	}
	if err != nil {
		return Project{}, fmt.Errorf("insert project: %w", err)
	}
	return out, nil
}

// GetBySlug fetches a project by team and slug, returning ErrNotFound when
// absent. Used by idempotent seeders (e.g. internal/demo) that look a project
// up before creating it.
func (r *Repository) GetBySlug(ctx context.Context, teamID, slug string) (Project, error) {
	const q = `SELECT ` + projectColumns + ` FROM projects WHERE team_id = $1 AND slug = $2`
	p, err := scanProject(r.db.QueryRow(ctx, q, teamID, slug))
	if errors.Is(err, pgx.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, fmt.Errorf("get project by slug: %w", err)
	}
	return p, nil
}

// List returns projects, optionally filtered to one team. scopeProjectIDs is the
// RBAC scope — the ids the actor may see, which is *not* simply "projects in my
// teams": a user can be granted a role on a single project without joining its
// team, and a project you can open but cannot find in any list is a bug. nil means
// no restriction (admin). custom filters on custom fields (?cf.<key>=…);
// archived lists the archived projects instead of the live ones.
func (r *Repository) List(ctx context.Context, teamID string, scopeProjectIDs []string, custom []customfield.Cond, archived bool) ([]Project, error) {
	q := `SELECT ` + projectColumns + ` FROM projects WHERE` + archive.Only(archive.Project(""), archived)
	var args []any
	if teamID != "" {
		args = append(args, teamID)
		q += fmt.Sprintf(" AND team_id = $%d", len(args))
	}
	if scopeProjectIDs != nil {
		args = append(args, scopeProjectIDs)
		q += fmt.Sprintf(" AND id = ANY($%d)", len(args))
	}
	cond, args := customfield.AppendSQL(custom, "custom", args)
	q += cond + ` ORDER BY name`

	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list projects: %w", err)
	}
	defer rows.Close()

	projects := []Project{}
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, fmt.Errorf("scan project: %w", err)
		}
		projects = append(projects, p)
	}
	return projects, rows.Err()
}

// Get returns a project by id.
func (r *Repository) Get(ctx context.Context, id string) (Project, error) {
	const q = `SELECT ` + projectColumns + ` FROM projects WHERE id = $1`
	p, err := scanProject(r.db.QueryRow(ctx, q, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, fmt.Errorf("get project: %w", err)
	}
	return p, nil
}

// Exists reports whether a live project with the given id exists: uploads
// into an archived project are refused as if it were gone.
func (r *Repository) Exists(ctx context.Context, id string) (bool, error) {
	q := `SELECT EXISTS(SELECT 1 FROM projects WHERE id = $1 AND` + archive.Project("") + `)`
	var ok bool
	if err := r.db.QueryRow(ctx, q, id).Scan(&ok); err != nil {
		return false, fmt.Errorf("project exists: %w", err)
	}
	return ok, nil
}

// Update applies partial changes; nil fields are left untouched. SetParent
// moves the project under ParentID (nil: make it a root).
func (r *Repository) Update(ctx context.Context, id string, p UpdateFields) (Project, error) {
	const q = `
		UPDATE projects
		SET name                 = COALESCE($2, name),
		    description          = COALESCE($3, description),
		    repo_url             = COALESCE($4, repo_url),
		    business_criticality = COALESCE($5, business_criticality),
		    tags                 = COALESCE($6, tags),
		    parent_id            = CASE WHEN $7 THEN $8::uuid ELSE parent_id END,
		    is_collection        = COALESCE($9, is_collection),
		    ai_triage_opt_out    = COALESCE($10, ai_triage_opt_out),
		    assessment_approval  = COALESCE($11, assessment_approval),
		    updated_at           = now()
		WHERE id = $1
		RETURNING ` + projectColumns
	out, err := scanProject(r.db.QueryRow(ctx, q,
		id, p.Name, p.Description, p.RepoURL, p.BusinessCriticality, p.Tags, p.SetParent, p.ParentID, p.IsCollection, p.AITriageOptOut, p.AssessmentApproval))
	if errors.Is(err, pgx.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if mapped := writeError(err); mapped != nil {
		return Project{}, mapped
	}
	if err != nil {
		return Project{}, fmt.Errorf("update project: %w", err)
	}
	return out, nil
}

// UpdateFields carries the optional fields of an update.
type UpdateFields struct {
	Name                *string
	Description         *string
	RepoURL             *string
	BusinessCriticality *domain.Criticality
	Tags                []string
	AITriageOptOut      *bool
	// AssessmentApproval overrides ASSESSMENT_REQUIRES_APPROVAL for this
	// project (inherit/required/off; M13 13.9).
	AssessmentApproval *domain.ApprovalSetting
	// SetParent moves the project under ParentID; a nil ParentID makes it a root.
	SetParent    bool
	ParentID     *string
	IsCollection *bool
}

// Children returns a project's direct children, by name.
func (r *Repository) Children(ctx context.Context, id string) ([]Project, error) {
	rows, err := r.db.Query(ctx, `SELECT `+projectColumns+` FROM projects WHERE parent_id = $1 ORDER BY name`, id)
	if err != nil {
		return nil, fmt.Errorf("list children: %w", err)
	}
	defer rows.Close()
	out := []Project{}
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, fmt.Errorf("scan project: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PriorityWeights returns a project's priority weight override as stored
// (nil = the defaults).
func (r *Repository) PriorityWeights(ctx context.Context, id string) ([]byte, error) {
	var raw []byte
	err := r.db.QueryRow(ctx, `SELECT priority_weights FROM projects WHERE id = $1`, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get priority weights: %w", err)
	}
	return raw, nil
}

// SetPriorityWeights stores a project's override (nil clears it).
func (r *Repository) SetPriorityWeights(ctx context.Context, id string, raw []byte) error {
	tag, err := r.db.Exec(ctx, `UPDATE projects SET priority_weights = $2, updated_at = now() WHERE id = $1`, id, raw)
	if err != nil {
		return fmt.Errorf("set priority weights: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TriageCarrySettings returns a project's triage-carry configuration: whether
// a manual false_positive / wont_fix / reopen decision propagates to the
// project's other versions, and the branch-name regex scoping which versions
// receive and share decisions (empty = every version). See
// internal/triagecarry.
func (r *Repository) TriageCarrySettings(ctx context.Context, id string) (enabled bool, branchRegex string, err error) {
	err = r.db.QueryRow(ctx, `SELECT triage_carry_enabled, triage_carry_branch_regex FROM projects WHERE id = $1`, id).
		Scan(&enabled, &branchRegex)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "", ErrNotFound
	}
	if err != nil {
		return false, "", fmt.Errorf("get triage carry settings: %w", err)
	}
	return enabled, branchRegex, nil
}

// SetTriageCarrySettings stores a project's triage-carry configuration.
func (r *Repository) SetTriageCarrySettings(ctx context.Context, id string, enabled bool, branchRegex string) error {
	tag, err := r.db.Exec(ctx,
		`UPDATE projects SET triage_carry_enabled = $2, triage_carry_branch_regex = $3, updated_at = now() WHERE id = $1`,
		id, enabled, branchRegex)
	if err != nil {
		return fmt.Errorf("set triage carry settings: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
