// Package authz enforces team-scoped RBAC. A single middleware resolves each
// request to the team that owns the target resource and checks the actor's role
// (deny-by-default); for portfolio-wide list endpoints it stashes the set of
// projects/teams the actor may see, which handlers use to scope results.
package authz

import (
	"context"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/domain"
)

const scopeKey = "authzScope"

// resolver answers the membership questions the middleware needs.
type resolver interface {
	AdminStatus(ctx context.Context, userID string) (isAdmin, isOwner bool, err error)
	RoleOnTeam(ctx context.Context, userID, teamID string) (domain.TeamRole, bool, error)
	RoleOnProject(ctx context.Context, userID, projectID string) (domain.TeamRole, bool, error)
	RoleOnOrg(ctx context.Context, userID, orgID string) (domain.OrgRole, bool, error)
	ProjectOfResource(ctx context.Context, resource, id string) (string, bool, error)
	TeamIDsForUser(ctx context.Context, userID string) ([]string, error)
	OrgIDsForUser(ctx context.Context, userID string) ([]string, error)
	ProjectIDsForUser(ctx context.Context, userID string) ([]string, error)
	OwnedProjectIDs(ctx context.Context, userID string) ([]string, error)
	// TeamCapabilityAllowed and ProjectCapabilityAllowed check a custom
	// role's deny-list on top of the minimum role: a capability denied by one
	// grant is still allowed if another grant meeting min doesn't deny it
	// (roles only add access — see membership.anyGrantAllows).
	TeamCapabilityAllowed(ctx context.Context, userID, teamID string, min domain.TeamRole, cap domain.Capability) (bool, error)
	ProjectCapabilityAllowed(ctx context.Context, userID, projectID string, min domain.TeamRole, cap domain.Capability) (bool, error)
	// ProjectIDsAllowing narrows ids to the projects where some grant of
	// userID doesn't deny cap.
	ProjectIDsAllowing(ctx context.Context, userID string, ids []string, cap domain.Capability) ([]string, error)
}

// Scope is the set of resources an actor may see, stashed for list handlers.
// AllAccess (admin) means no filtering.
type Scope struct {
	AllAccess  bool
	OrgIDs     []string
	TeamIDs    []string
	ProjectIDs []string
}

// Middleware enforces RBAC. It must run after auth.Middleware.
func Middleware(m resolver) fiber.Handler {
	return func(c *fiber.Ctx) error {
		actor := auth.CurrentActor(c)
		s := parseScope(c.Path(), c.Method())
		// Archive (internal/archive): purging is irreversible, so it is an
		// instance-admin act; seeing archived records is owner-level, like
		// restoring them — on a portfolio-wide list the scope narrows to the
		// projects the caller owns.
		if c.Method() == fiber.MethodDelete && c.QueryBool("purge") {
			s.adminOnly = true
		}
		archivedList := c.Method() == fiber.MethodGet && c.QueryBool("archived")
		if archivedList {
			s.minRole = domain.TeamOwner
		}

		// Admin status comes from the database, never from the token's claim: a
		// demoted admin's JWT still says "admin" until it expires, so trusting it
		// would mean a revocation doesn't take effect for up to a token lifetime.
		isAdmin, _, err := m.AdminStatus(c.UserContext(), actor.UserID)
		if err != nil {
			return err
		}
		if isAdmin {
			c.Locals(scopeKey, Scope{AllAccess: true})
			return c.Next()
		}
		if s.adminOnly {
			return fiber.NewError(fiber.StatusForbidden, "requires an admin")
		}
		if s.globalList {
			ctx := c.UserContext()
			pids, err := m.ProjectIDsForUser(ctx, actor.UserID)
			if archivedList {
				pids, err = m.OwnedProjectIDs(ctx, actor.UserID)
			}
			if err != nil {
				return err
			}
			if s.capability != "" {
				// A cross-project read a custom role can deny (exports): only
				// the projects where some grant allows it.
				if pids, err = m.ProjectIDsAllowing(ctx, actor.UserID, pids, s.capability); err != nil {
					return err
				}
			}
			tids, err := m.TeamIDsForUser(ctx, actor.UserID)
			if err != nil {
				return err
			}
			oids, err := m.OrgIDsForUser(ctx, actor.UserID)
			if err != nil {
				return err
			}
			c.Locals(scopeKey, Scope{ProjectIDs: pids, TeamIDs: tids, OrgIDs: oids})
			return c.Next()
		}

		// Org-scoped routes: check the actor's org role directly.
		if s.orgID != "" {
			role, member, err := m.RoleOnOrg(c.UserContext(), actor.UserID, s.orgID)
			if err != nil {
				return err
			}
			if !member {
				return fiber.NewError(fiber.StatusForbidden, "not a member of this organization")
			}
			if s.minOrgRole == domain.OrgAdmin && role != domain.OrgAdmin {
				return fiber.NewError(fiber.StatusForbidden, "requires an organization admin")
			}
			return c.Next()
		}

		// Team-scoped routes (/teams/{id}/…) check the team role.
		if s.teamID != "" {
			role, member, err := m.RoleOnTeam(c.UserContext(), actor.UserID, s.teamID)
			if err != nil {
				return err
			}
			if !member {
				return fiber.NewError(fiber.StatusForbidden, "not a member of this team")
			}
			if !role.AtLeast(s.minRole) {
				return fiber.NewError(fiber.StatusForbidden, "insufficient role for this action")
			}
			if s.capability != "" {
				allowed, err := m.TeamCapabilityAllowed(c.UserContext(), actor.UserID, s.teamID, s.minRole, s.capability)
				if err != nil {
					return err
				}
				if !allowed {
					return fiber.NewError(fiber.StatusForbidden, "this role cannot perform this action")
				}
			}
			return c.Next()
		}

		// Everything else project-scoped resolves to a project and checks the
		// *effective* project role — the highest of a direct project grant, the
		// owning team's role, and org admin.
		projectID, err := s.resolveProject(c.UserContext(), m)
		if err != nil {
			return err
		}
		if projectID == "" {
			// Not a project-scoped path (e.g. /me, /tokens, /frameworks) or the
			// resource doesn't exist — let the handler run (it enforces or 404s).
			return c.Next()
		}

		role, member, err := m.RoleOnProject(c.UserContext(), actor.UserID, projectID)
		if err != nil {
			return err
		}
		if !member {
			return fiber.NewError(fiber.StatusForbidden, "no access to this project")
		}
		// capMin is the role threshold that actually granted access — the
		// uploader carve-out passes at TeamUploader, not minRole, so the
		// capability check (upload, for those routes) is asked about the
		// grant that really authorized the request.
		capMin := s.minRole
		if !role.AtLeast(s.minRole) {
			// uploader is viewer plus uploads: it never reaches editor on its
			// own, so only the specific upload/gate routes that opt in
			// (allowUploader) accept it in place of the editor they'd
			// otherwise require.
			if !(s.allowUploader && role.AtLeast(domain.TeamUploader)) {
				return fiber.NewError(fiber.StatusForbidden, "insufficient role for this action")
			}
			capMin = domain.TeamUploader
		}
		if s.capability != "" {
			allowed, err := m.ProjectCapabilityAllowed(c.UserContext(), actor.UserID, projectID, capMin, s.capability)
			if err != nil {
				return err
			}
			if !allowed {
				return fiber.NewError(fiber.StatusForbidden, "this role cannot perform this action")
			}
		}
		return c.Next()
	}
}

// VisibleScope returns the actor's list scope (set on global-list routes).
func VisibleScope(c *fiber.Ctx) Scope {
	s, _ := c.Locals(scopeKey).(Scope)
	return s
}

type routeScope struct {
	adminOnly  bool
	globalList bool
	teamID     string
	orgID      string
	minOrgRole domain.OrgRole
	projectID  string
	resource   string
	resourceID string
	minRole    domain.TeamRole
	// allowUploader lets an uploader-only project grant satisfy this route
	// even though it fails minRole: the specific scan/SBOM/VEX upload, the
	// gate run, and reading the scan it just pushed.
	allowUploader bool
	// capability, when set, additionally requires some grant meeting minRole
	// (capMin for the uploader carve-out) not to deny it — a custom role's
	// deny-list on top of the role ladder (internal/domain.Capability).
	capability domain.Capability
}

// resolveProject finds the project a request targets: named in the path, or the
// project that owns the finding/scan/sbom/asset/vex it names.
func (s routeScope) resolveProject(ctx context.Context, m resolver) (string, error) {
	if s.projectID != "" {
		return s.projectID, nil
	}
	if s.resource != "" {
		p, ok, err := m.ProjectOfResource(ctx, s.resource, s.resourceID)
		if err != nil || !ok {
			return "", err
		}
		return p, nil
	}
	return "", nil
}

// parseScope derives the authorization scope from the request path + method.
// Params aren't bound in group middleware, so we parse the path string.
func parseScope(path, method string) routeScope {
	s := baseScope(path, method)
	s.capability = capabilityFor(path, method)
	return s
}

// capabilityFor is the custom-role capability a route needs on top of its
// minimum role ("" = none): the route classes a custom role can deny
// (domain.Capability). Keep it in step with the routes it names; the
// capability table test walks them.
func capabilityFor(path, method string) domain.Capability {
	segs := apiSegments(path)
	if len(segs) < 2 {
		return ""
	}
	get := method == fiber.MethodGet
	last := segs[len(segs)-1]
	if get {
		if last == "export" {
			return domain.CapExport // findings, components, VEX exports
		}
		return ""
	}
	switch segs[0] {
	case "findings":
		if len(segs) == 2 && segs[1] == "bulk" {
			return domain.CapTriage // the handler checks it per project too
		}
		if len(segs) < 3 {
			return domain.CapTriage // PATCH /findings/{id}: status / severity
		}
		switch segs[2] {
		case "fields", "assignee":
			return domain.CapTriage
		case "ai-proposals":
			if last == "accept" {
				return domain.CapTriage
			}
		case "comments", "attachments":
			return domain.CapComment
		}
	case "assessments":
		return domain.CapTriage // approving a status / severity change
	case "teams":
		if len(segs) >= 3 && (segs[2] == "members" || segs[2] == "groups") {
			return domain.CapManageMembers
		}
	case "projects":
		if len(segs) < 3 {
			return ""
		}
		switch segs[2] {
		case "scans", "sboms", "vex":
			if len(segs) == 3 {
				return domain.CapUpload
			}
		case "gate":
			if len(segs) == 3 {
				return domain.CapUpload // running the gate is part of a CI upload
			}
			return domain.CapProjectSettings // gate policy
		case "members", "groups":
			return domain.CapManageMembers
		case "connectors":
			if last == "pull" {
				return domain.CapUpload
			}
			return domain.CapProjectSettings
		case "sla", "issue-tracker", "versions", "badge-token":
			return domain.CapProjectSettings
		case "risk-acceptances":
			if last == "approve" || last == "reject" || last == "revoke" {
				return domain.CapRiskAcceptanceApprove
			}
		}
	}
	return ""
}

// apiSegments is the path after /api/v1, split on "/".
func apiSegments(path string) []string {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	for i, s := range segs {
		if s == "v1" {
			return segs[i+1:]
		}
	}
	return nil
}

func baseScope(path, method string) routeScope {
	segs := strings.Split(strings.Trim(path, "/"), "/")
	i := 0
	for i < len(segs) && segs[i] != "v1" {
		i++
	}
	if i >= len(segs) {
		return routeScope{}
	}
	segs = segs[i+1:]
	if len(segs) == 0 {
		return routeScope{}
	}

	get := method == fiber.MethodGet
	mut := func() domain.TeamRole {
		if get {
			return domain.TeamViewer
		}
		return domain.TeamEditor
	}

	// Restoring an archived record (internal/archive) is owner-level.
	if len(segs) == 3 && segs[2] == "restore" && method == fiber.MethodPost {
		switch segs[0] {
		case "projects":
			return routeScope{projectID: segs[1], minRole: domain.TeamOwner}
		case "engagements", "scans", "findings":
			return routeScope{resource: segs[0], resourceID: segs[1], minRole: domain.TeamOwner}
		}
	}

	switch segs[0] {
	case "orgs":
		if len(segs) == 1 {
			return routeScope{globalList: true} // list (self-scoped) / create (any user)
		}
		// An org's metric trend is list-scoped: membership alone doesn't grant
		// every project in the org, so the handler checks membership against
		// Scope.OrgIDs and sums only the visible projects.
		if len(segs) == 4 && segs[2] == "metrics" && segs[3] == "trends" && get {
			return routeScope{globalList: true}
		}
		s := routeScope{orgID: segs[1], minOrgRole: domain.OrgMember}
		// Managing members, creating teams, or mutating the org needs org admin.
		if (len(segs) >= 3 && (segs[2] == "members" || segs[2] == "teams")) || !get {
			s.minOrgRole = domain.OrgAdmin
		}
		return s
	case "teams":
		if len(segs) == 1 {
			return routeScope{globalList: true} // list (self-scoped)
		}
		s := routeScope{teamID: segs[1]}
		switch {
		case len(segs) >= 3 && segs[2] == "members":
			s.minRole = domain.TeamOwner
		case len(segs) >= 3 && segs[2] == "projects":
			s.minRole = domain.TeamEditor // create a project under the team
		case get:
			s.minRole = domain.TeamViewer
		default:
			s.minRole = domain.TeamOwner // rename / delete the team
		}
		return s
	case "projects":
		if len(segs) == 1 {
			return routeScope{globalList: true}
		}
		s := routeScope{projectID: segs[1], minRole: mut()}
		// uploader is viewer plus uploads: it already reads everything under
		// /projects/{id} via minRole viewer, but a push/gate POST still
		// defaults to editor, so opt those specific routes into the
		// allowUploader carve-out.
		if len(segs) == 3 && method == fiber.MethodPost &&
			(segs[2] == "scans" || segs[2] == "sboms" || segs[2] == "vex" || segs[2] == "gate") {
			s.allowUploader = true
		}
		// Archiving a project takes it (and its findings) out of every view
		// for everyone; restoring it is owner-level like every restore.
		if len(segs) == 2 && method == fiber.MethodDelete {
			s.minRole = domain.TeamOwner
		}
		// Granting access to a project is itself an owner-level act: an editor who
		// could add members could grant themselves nothing new, but could hand the
		// project to anyone.
		if len(segs) >= 3 && (segs[2] == "members" || segs[2] == "groups" || segs[2] == "access") {
			s.minRole = domain.TeamOwner // who can reach the project and why: owner-level, like managing it
		}
		// Watching is a personal subscription: anyone who can see the project.
		if len(segs) == 3 && segs[2] == "watch" {
			s.minRole = domain.TeamViewer
		}
		// An SLA is a commitment the project is held to: the team working the
		// backlog shouldn't be able to relax its own deadlines. Likewise which
		// version is the default decides what metrics and gates report, and
		// deleting a version deletes its findings.
		if len(segs) >= 3 && (segs[2] == "sla" || segs[2] == "versions") && !get {
			s.minRole = domain.TeamOwner
		}
		// The issue tracker holds a credential for another system and decides
		// what gets filed there: configuring (or testing) it is owner-level.
		if len(segs) >= 3 && segs[2] == "issue-tracker" && !get {
			s.minRole = domain.TeamOwner
		}
		// Deciding a risk acceptance (approve / reject / revoke) is owner-level;
		// the handler also enforces four-eyes on approve / reject.
		if len(segs) >= 5 && segs[2] == "risk-acceptances" && !get &&
			(segs[4] == "approve" || segs[4] == "reject" || segs[4] == "revoke") {
			s.minRole = domain.TeamOwner
		}
		// A badge token publishes the project's numbers to anyone holding it.
		if len(segs) >= 3 && segs[2] == "badge-token" && !get {
			s.minRole = domain.TeamOwner
		}
		// Declaring a product in CRA scope (or out of it) decides which
		// legal reporting obligations the project carries: owner-level.
		if len(segs) == 3 && segs[2] == "cra" && !get {
			s.minRole = domain.TeamOwner
		}
		// A connector holds a credential for another system too: configuring or
		// testing it is owner-level. Pulling is just a scan (editor).
		if len(segs) >= 3 && segs[2] == "connectors" && !get && !(len(segs) == 5 && segs[4] == "pull") {
			s.minRole = domain.TeamOwner
		}
		return s
	case "scans":
		if len(segs) >= 2 {
			return routeScope{resource: "scans", resourceID: segs[1], minRole: mut()}
		}
	case "assets":
		if len(segs) == 1 {
			return routeScope{globalList: true}
		}
		return routeScope{resource: "assets", resourceID: segs[1], minRole: mut()}
	case "sboms":
		if len(segs) >= 2 {
			return routeScope{resource: "sboms", resourceID: segs[1], minRole: mut()}
		}
	case "vex":
		if len(segs) >= 2 {
			return routeScope{resource: "vex", resourceID: segs[1], minRole: mut()}
		}
	case "engagements":
		if len(segs) >= 2 {
			return routeScope{resource: "engagements", resourceID: segs[1], minRole: mut()}
		}
	case "cra":
		// CRA Article 14 reporting cases: the list is scoped by the handler,
		// a case is authorized via its project, and dismissing one (choosing
		// not to report) is owner-level. The sweep is instance maintenance.
		switch {
		case len(segs) == 2 && segs[1] == "cases":
			return routeScope{globalList: true}
		case len(segs) >= 3 && segs[1] == "cases":
			s := routeScope{resource: "cra-cases", resourceID: segs[2], minRole: mut()}
			if len(segs) == 4 && segs[3] == "dismiss" {
				s.minRole = domain.TeamOwner
			}
			return s
		case len(segs) == 2 && segs[1] == "sweep":
			return routeScope{adminOnly: true}
		}
	case "remediation":
		switch {
		case len(segs) == 1:
			return routeScope{globalList: true} // portfolio list, scoped by the handler
		case segs[1] == "sweep":
			return routeScope{adminOnly: true} // portfolio-wide maintenance
		}
		return routeScope{resource: "remediation", resourceID: segs[1], minRole: mut()}
	case "root-causes":
		// Cross-project root causes: the list, the detail (one change's affected
		// projects) and creating the missing remediation actions all work on
		// the caller's visible projects, which globalList stashes for the
		// handler. "kind"/"key" aren't resource ids, so there is no path
		// resource to check; creating checks editor on each project in the
		// handler, like POST /findings/bulk.
		return routeScope{globalList: true}
	case "findings":
		if len(segs) == 1 {
			return routeScope{globalList: true}
		}
		switch segs[1] {
		case "expiring", "export", "tags":
			// Cross-project reads: the handler filters by the visible scope.
			return routeScope{globalList: true}
		case "expire-exceptions":
			return routeScope{adminOnly: true} // portfolio-wide maintenance
		case "bulk":
			// Spans projects: the handler authorizes every finding on its own
			// project (editor+). Never a resource lookup — "bulk" isn't an id.
			return routeScope{}
		default:
			return routeScope{resource: "findings", resourceID: segs[1], minRole: mut()}
		}
	case "risk-acceptances":
		// The approval queue across projects, scoped by the handler.
		return routeScope{globalList: true}
	case "ai-proposals":
		// Open AI triage proposals across projects, scoped by the handler.
		// Deciding one goes through /findings/{id}/ai-proposals/…, which
		// authorizes the finding's project.
		return routeScope{globalList: true}
	case "assessments":
		if len(segs) == 1 {
			return routeScope{globalList: true} // the review queue, scoped by the handler
		}
		// Approving / rejecting a manual assessment is owner-level; the handler
		// also refuses the requester (four-eyes).
		s := routeScope{resource: "assessments", resourceID: segs[1], minRole: domain.TeamViewer}
		if !get {
			s.minRole = domain.TeamOwner
		}
		return s
	case "components", "portfolio", "vulnerabilities", "ingestion-health", "fix-plan":
		return routeScope{globalList: true}
	case "license-groups":
		// License groups are portfolio-wide policy inputs: anyone signed in may
		// read them, only an instance admin may change them. (The /licenses
		// catalog is reference data — the default below.)
		if !get {
			return routeScope{adminOnly: true}
		}
		return routeScope{}
	case "custom-fields":
		// Custom-field definitions: anyone signed in may read them (every
		// editor needs them; ?project_id= is checked against the visible
		// scope by the handler); only an instance admin may change them.
		// Values are written under /projects, /assets and /findings (editor).
		if get {
			return routeScope{globalList: true}
		}
		return routeScope{adminOnly: true}
	case "finding-templates", "report-templates":
		// Templates are shared write-ups and report layouts: anyone signed in
		// may use them; only an instance admin may change them.
		if !get {
			return routeScope{adminOnly: true}
		}
		return routeScope{}
	case "features":
		// Runtime feature switches: anyone signed in reads them (the UI hides
		// what is off); only an instance admin flips one (the owner, for
		// owner-only features — the handler checks that).
		if !get {
			return routeScope{adminOnly: true}
		}
		return routeScope{}
	case "advisories":
		// The private advisory database describes internal packages, not a
		// tenant's data: anyone signed in may read it; only an instance admin
		// may publish, edit, withdraw or import advisories.
		if !get {
			return routeScope{adminOnly: true}
		}
		return routeScope{}
	case "policies":
		// Component policies are instance-wide: anyone signed in may read them
		// and dry-run a draft (handlers narrow both to the caller's projects);
		// only an instance admin may change or force-evaluate them.
		if get || (len(segs) == 2 && segs[1] == "preview") {
			return routeScope{globalList: true}
		}
		return routeScope{adminOnly: true}
	case "pkgmeta":
		// Cached registry metadata is public package data any signed-in user
		// may read; a sweep hits every registry for the whole portfolio, so
		// starting one is an instance-admin action.
		if !get {
			return routeScope{adminOnly: true}
		}
		return routeScope{}
	case "metrics":
		// Trends are list-scoped by the handler; snapshotting is maintenance.
		if len(segs) >= 2 && segs[1] == "trends" && get {
			return routeScope{globalList: true}
		}
		return routeScope{adminOnly: true}
	case "users", "permissions", "service-accounts", "scim-tokens", "federation", "enrich", "vulnmatch", "feed-rules", "psirt", "notifications", "triage-rules", "gate", "ingest", "sla", "issue-trackers", "sso", "retention", "audit-log", "exploit-intel":
		// User admin, service accounts + workload identity federation, SSO
		// providers + group → role mappings, portfolio-wide
		// enrichment, advisory feed rules, PSIRT advisory publishing, notification-channel management,
		// triage-rule policy, the global gate and SLA defaults, and the
		// portfolio-wide issue sync are instance-admin actions. (Per-project/org
		// gate, SLA and tracker routes live under /projects and /orgs and are
		// role-gated there.)
		return routeScope{adminOnly: true}
	}
	// frameworks, tokens, me — reference data or the actor's own resources;
	// mcp — every tool call is a sub-request authorized on its own route.
	return routeScope{}
}
