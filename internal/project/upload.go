package project

import (
	"context"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/domain"
)

// UploadAccess answers the per-project questions an upload by project name
// must settle itself. membership.Repository satisfies it.
type UploadAccess interface {
	AdminStatus(ctx context.Context, userID string) (isAdmin, isOwner bool, err error)
	RoleOnProject(ctx context.Context, userID, projectID string) (domain.TeamRole, bool, error)
	ProjectCapabilityAllowed(ctx context.Context, userID, projectID string, minRole domain.TeamRole, capability domain.Capability) (bool, error)
}

// ResolveUpload resolves the project an upload by name targets (the
// project_name, team and auto_create query parameters of POST /scans and
// POST /sboms) and authorizes the upload to it.
//
// No project id is in those paths, so authz.Middleware can't check them; this
// does what it would for POST /projects/{id}/scans|sboms: the uploader role
// (or higher) on the project, a custom role not denying uploads, and a
// project-scoped token confined to that project. The confinement is checked
// before anything is resolved, so such a token can never auto-create a
// project, not even one it would then be refused.
func ResolveUpload(c *fiber.Ctx, r *Resolver, access UploadAccess) (Project, error) {
	ctx := c.UserContext()
	actor := auth.CurrentActor(c)
	autoCreate := c.QueryBool("auto_create", false)
	if actor.ProjectID != "" && autoCreate {
		return Project{}, fiber.NewError(fiber.StatusForbidden, "a project-scoped token can't create projects")
	}
	p, err := r.ByName(ctx, actor.UserID, c.Query("project_name"), c.Query("team"), autoCreate)
	if err != nil {
		return Project{}, ResolveError(err)
	}
	if actor.ProjectID != "" && actor.ProjectID != p.ID {
		return Project{}, fiber.NewError(fiber.StatusForbidden, "token not authorized for this project")
	}
	isAdmin, _, err := access.AdminStatus(ctx, actor.UserID)
	if err != nil || isAdmin {
		return p, err
	}
	role, member, err := access.RoleOnProject(ctx, actor.UserID, p.ID)
	if err != nil {
		return Project{}, err
	}
	if !member || !role.AtLeast(domain.TeamUploader) {
		return Project{}, fiber.NewError(fiber.StatusForbidden, "insufficient role for this action")
	}
	allowed, err := access.ProjectCapabilityAllowed(ctx, actor.UserID, p.ID, domain.TeamUploader, domain.CapUpload)
	if err != nil {
		return Project{}, err
	}
	if !allowed {
		return Project{}, fiber.NewError(fiber.StatusForbidden, "this role cannot perform this action")
	}
	return p, nil
}
