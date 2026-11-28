package project

import (
	"context"
	"errors"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/team"
)

// Domain errors for name-based resolution (xila upload --project-name): CI
// uploads that know a project and team by name, not by id.
var (
	// ErrNameRequired is returned when project_name is blank.
	ErrNameRequired = errors.New("project_name is required")
	// ErrTeamRequired is returned when auto_create is set without a team: a
	// project can't be created without knowing which team owns it.
	ErrTeamRequired = errors.New("team is required to auto-create a project")
	// ErrTeamNotFound is returned for a team id/slug the caller can't see
	// (or that doesn't exist) — never distinguished from "doesn't exist",
	// like every other not-found in this API.
	ErrTeamNotFound = errors.New("team not found")
	// ErrAmbiguousTeam is returned when a team slug matches more than one
	// team the caller can see (teams in different orgs may share a slug).
	ErrAmbiguousTeam = errors.New("team is ambiguous: more than one visible team has this slug; give a team id")
	// ErrAmbiguousProject is returned when project_name matches more than one
	// visible project and no team was given to disambiguate.
	ErrAmbiguousProject = errors.New("project_name matches more than one visible project; give a team to disambiguate")
	// ErrCannotCreate is returned when auto_create is set but the caller
	// lacks editor on the target team (the same rule as
	// POST /teams/{teamID}/projects).
	ErrCannotCreate = errors.New("insufficient role to create a project in this team")
	// ErrArchivedProject is returned when auto_create names a project whose
	// slug an archived project of the team still holds.
	ErrArchivedProject = errors.New("an archived project of this team has this name: restore it or choose another name")
)

// membershipChecker answers the visibility/role questions Resolver needs.
// membership.Repository satisfies it.
type membershipChecker interface {
	AdminStatus(ctx context.Context, userID string) (isAdmin, isOwner bool, err error)
	RoleOnTeam(ctx context.Context, userID, teamID string) (domain.TeamRole, bool, error)
	TeamIDsForUser(ctx context.Context, userID string) ([]string, error)
	ProjectIDsForUser(ctx context.Context, userID string) ([]string, error)
}

// Resolver finds, or with autoCreate creates, a project by name for CI
// uploads that only know a project (and optionally team) name, not an id
// (xila upload --project-name / --team / --create; POST /scans and
// POST /sboms with project_name). It never authorizes the upload itself
// (RBAC on the resolved or created project is the caller's job) beyond the
// team-editor check auto-creating needs.
type Resolver struct {
	projects *Repository
	teams    *team.Repository
	access   membershipChecker
}

// NewResolver constructs a Resolver.
func NewResolver(projects *Repository, teams *team.Repository, access membershipChecker) *Resolver {
	return &Resolver{projects: projects, teams: teams, access: access}
}

// ByName resolves name (matched against a project's slug) to a Project,
// optionally scoped to one team (teamRef: a team id or slug) and, with
// autoCreate, creating it under that team when no project matches — the same
// rule POST /teams/{teamID}/projects uses: the caller needs team editor.
// Without a team, the search covers every project the caller can see; more
// than one match is ErrAmbiguousProject.
func (r *Resolver) ByName(ctx context.Context, userID, name, teamRef string, autoCreate bool) (Project, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Project{}, ErrNameRequired
	}
	isAdmin, _, err := r.access.AdminStatus(ctx, userID)
	if err != nil {
		return Project{}, err
	}

	if teamRef == "" {
		if autoCreate {
			return Project{}, ErrTeamRequired
		}
		var scope []string // nil = unrestricted (admin)
		if !isAdmin {
			if scope, err = r.access.ProjectIDsForUser(ctx, userID); err != nil {
				return Project{}, err
			}
		}
		matches, err := r.projects.FindBySlug(ctx, scope, "", name)
		if err != nil {
			return Project{}, err
		}
		switch len(matches) {
		case 0:
			return Project{}, ErrNotFound
		case 1:
			return matches[0], nil
		default:
			return Project{}, ErrAmbiguousProject
		}
	}

	t, err := r.resolveTeam(ctx, userID, isAdmin, teamRef)
	if err != nil {
		return Project{}, err
	}
	// Live projects only (FindBySlug excludes archived ones), matched
	// case-insensitively like the no-team search.
	found, err := r.projects.FindBySlug(ctx, nil, t.ID, name)
	if err != nil {
		return Project{}, err
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
	default:
		return Project{}, ErrAmbiguousProject
	}
	if !autoCreate {
		return Project{}, ErrNotFound
	}
	if !isAdmin {
		role, member, rerr := r.access.RoleOnTeam(ctx, userID, t.ID)
		if rerr != nil {
			return Project{}, rerr
		}
		if !member || !role.AtLeast(domain.TeamEditor) {
			return Project{}, ErrCannotCreate
		}
	}
	created, err := r.projects.Create(ctx, Project{
		TeamID: t.ID, Slug: name, Name: name,
		BusinessCriticality: domain.CriticalityMedium, Tags: []string{},
	})
	if !errors.Is(err, ErrDuplicate) {
		return created, err
	}
	// Two CI jobs (a build matrix) auto-creating the same project race on the
	// unique slug: the loser uses the winner's. A slug still taken with no
	// live project to show for it belongs to an archived one.
	if found, err = r.projects.FindBySlug(ctx, nil, t.ID, name); err != nil {
		return Project{}, err
	}
	if len(found) == 1 {
		return found[0], nil
	}
	return Project{}, ErrArchivedProject
}

// resolveTeam resolves ref (a team id or slug) to a team the caller can see.
// A slug is matched among the caller's visible teams (every team for an
// admin) case-insensitively; more than one match is ErrAmbiguousTeam.
func (r *Resolver) resolveTeam(ctx context.Context, userID string, isAdmin bool, ref string) (team.Team, error) {
	if uuid.Validate(ref) == nil {
		t, err := r.teams.Get(ctx, ref)
		if errors.Is(err, team.ErrNotFound) {
			return team.Team{}, ErrTeamNotFound
		}
		if err != nil {
			return team.Team{}, err
		}
		if isAdmin {
			return t, nil
		}
		if _, member, merr := r.access.RoleOnTeam(ctx, userID, t.ID); merr != nil {
			return team.Team{}, merr
		} else if !member {
			return team.Team{}, ErrTeamNotFound
		}
		return t, nil
	}

	var candidates []team.Team
	var err error
	if isAdmin {
		candidates, err = r.teams.List(ctx)
	} else {
		var ids []string
		if ids, err = r.access.TeamIDsForUser(ctx, userID); err == nil {
			candidates, err = r.teams.ListByIDs(ctx, ids)
		}
	}
	if err != nil {
		return team.Team{}, err
	}
	var match *team.Team
	for i := range candidates {
		if strings.EqualFold(candidates[i].Slug, ref) {
			if match != nil {
				return team.Team{}, ErrAmbiguousTeam
			}
			match = &candidates[i]
		}
	}
	if match == nil {
		return team.Team{}, ErrTeamNotFound
	}
	return *match, nil
}

// ResolveError maps a Resolver.ByName error to an HTTP response: scan and
// sbom handlers share it so POST /scans and POST /sboms (project by name)
// answer identically.
func ResolveError(err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	case errors.Is(err, ErrNameRequired), errors.Is(err, ErrTeamRequired),
		errors.Is(err, ErrTeamNotFound), errors.Is(err, ErrAmbiguousTeam),
		errors.Is(err, ErrAmbiguousProject):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, ErrCannotCreate):
		return fiber.NewError(fiber.StatusForbidden, err.Error())
	case errors.Is(err, ErrArchivedProject):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	default:
		return err
	}
}
