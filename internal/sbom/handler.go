package sbom

import (
	"bytes"
	"cmp"
	"errors"
	"slices"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/projecttree"
	"github.com/xilasec/xila-api/internal/vex"
)

// Handler exposes SBOM upload, history and component search over HTTP.
type Handler struct {
	repo     *Repository
	ingest   *Service
	resolver *project.Resolver    // optional: enables POST /sboms (project by name)
	access   project.UploadAccess // required alongside resolver
}

// NewHandler constructs an SBOM Handler.
func NewHandler(repo *Repository, ingest *Service) *Handler {
	return &Handler{repo: repo, ingest: ingest}
}

// WithProjectByName enables POST /sboms (CI uploads that know a project —
// and optionally a team — by name, not by id; see project.Resolver).
func (h *Handler) WithProjectByName(resolver *project.Resolver, access project.UploadAccess) *Handler {
	h.resolver, h.access = resolver, access
	return h
}

// Register mounts SBOM routes.
func (h *Handler) Register(r fiber.Router) {
	r.Post("/projects/:projectID/sboms", h.Upload)
	r.Post("/sboms", h.UploadByName)
	r.Get("/projects/:projectID/sboms", h.ListByProject)
	r.Get("/projects/:projectID/components", h.ProjectComponents)
	r.Get("/projects/:projectID/components/export", h.ExportProjectComponents)
	r.Get("/projects/:projectID/services", h.ProjectServices)
	r.Get("/sboms/:sbomID", h.Get)
	r.Get("/sboms/:sbomID/status", h.Status)
	r.Get("/sboms/:sbomID/components", h.SbomComponents)
	r.Get("/sboms/:sbomID/components/export", h.ExportSbomComponents)
	r.Get("/sboms/:sbomID/vulnerabilities", h.Vulnerabilities)
	r.Get("/sboms/:sbomID/services", h.SbomServices)
	r.Get("/sboms/:sbomID/export", h.Export)
	r.Get("/sboms/:sbomID/diff", h.Diff)
	r.Get("/sboms/:sbomID/graph", h.Graph)
	r.Get("/sboms/:sbomID/graph/paths", h.GraphPaths)
	r.Get("/components", h.SearchComponents)
	r.Get("/components/export", h.ExportComponents)
	r.Get("/vulnerabilities/:vulnID/sboms", h.VulnerabilityTimeline)
}

// Upload handles POST /projects/{id}/sboms with a CycloneDX (JSON or XML) or
// SPDX JSON body. The format is auto-detected from the content.
//
//	POST /projects/{id}/sboms?artifact=myapp&version=1.4.0
//	<raw cyclonedx or spdx document>
func (h *Handler) Upload(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	return h.uploadProject(c, projectID)
}

// UploadByName handles POST /sboms: an alternative to
// POST /projects/{id}/sboms for CI that knows a project (and team) by name,
// not by id (project_name, team, auto_create — see project.Resolver). Every
// other parameter is the same query-string metadata Upload reads. No
// project id is in the path, so the route-level authz middleware can't
// authorize this route (see authz.parseScope's routeScope{} for "sboms"):
// this handler re-checks the resolved project itself (project.ResolveUpload).
func (h *Handler) UploadByName(c *fiber.Ctx) error {
	if h.resolver == nil {
		return fiber.NewError(fiber.StatusNotImplemented, "project-by-name upload is not configured")
	}
	p, err := project.ResolveUpload(c, h.resolver, h.access)
	if err != nil {
		return err
	}
	return h.uploadProject(c, p.ID)
}

func (h *Handler) uploadProject(c *fiber.Ctx, projectID string) error {
	if len(c.Body()) == 0 {
		return fiber.NewError(fiber.StatusBadRequest, "request body (CycloneDX JSON) is required")
	}
	if c.Query("branch") != "" && c.Query("release") != "" {
		return fiber.NewError(fiber.StatusBadRequest, "give branch or release, not both")
	}
	req := IngestRequest{
		ProjectID: projectID,
		Artifact:  c.Query("artifact"),
		Version:   c.Query("version"),
		Branch:    strings.TrimSpace(c.Query("branch")),
		Release:   strings.TrimSpace(c.Query("release")),
		Strict:    c.QueryBool("strict", false),
	}
	s, err := h.ingest.Ingest(c.UserContext(), req, bytes.NewReader(c.Body()))
	var strictErr *StrictValidationError
	switch {
	case errors.Is(err, ErrProjectNotFound):
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	case errors.Is(err, ErrCollection):
		return fiber.NewError(fiber.StatusConflict, err.Error())
	case errors.Is(err, ErrStrictXMLUnsupported):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.As(err, &strictErr):
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error":  strictErr.Error(),
			"fields": strictErr.Fields,
		})
	case err != nil:
		return fiber.NewError(fiber.StatusUnprocessableEntity, err.Error())
	}
	return c.Status(fiber.StatusCreated).JSON(s)
}

// Status handles GET /sboms/{id}/status: the upload's background-processing
// state (vulnmatch match, pkgmeta fetch, policy evaluation, reachability —
// M13 13.3), so CI can wait for it before gating instead of racing a
// just-uploaded snapshot's still-running post-ingest steps.
func (h *Handler) Status(c *fiber.Ctx) error {
	s, err := h.snapshot(c, "sbomID")
	if err != nil {
		return err
	}
	p, err := h.repo.GetProcessing(c.UserContext(), s.ID)
	if errors.Is(err, ErrNoProcessing) {
		return fiber.NewError(fiber.StatusNotFound, "no processing record for this sbom")
	}
	if err != nil {
		return err
	}
	return c.JSON(p)
}

// ListByProject handles GET /projects/{id}/sboms (SBOM history).
func (h *Handler) ListByProject(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	sboms, err := h.repo.ListByProject(c.UserContext(), projectID, c.Query("artifact"))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"sboms": sboms})
}

// Get handles GET /sboms/{id}.
func (h *Handler) Get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "sbomID")
	if err != nil {
		return err
	}
	s, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "sbom not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(s)
}

// SbomComponents handles GET /sboms/{id}/components (one snapshot's inventory).
func (h *Handler) SbomComponents(c *fiber.Ctx) error {
	filter, err := sbomComponentFilter(c)
	if err != nil {
		return err
	}
	return h.listComponents(c, filter)
}

// ProjectComponents handles GET /projects/{id}/components. Pass ?latest=true for
// current inventory (newest snapshot per artifact) instead of all history.
func (h *Handler) ProjectComponents(c *fiber.Ctx) error {
	filter, err := h.projectComponentFilter(c)
	if err != nil {
		return err
	}
	return h.listComponents(c, filter)
}

// SearchComponents handles GET /components: global "which projects use package
// X" search across every snapshot (or the latest ones with ?latest=true).
func (h *Handler) SearchComponents(c *fiber.Ctx) error {
	filter, err := searchComponentFilter(c)
	if err != nil {
		return err
	}
	return h.listComponents(c, filter)
}

// sbomComponentFilter is the filter of GET /sboms/{id}/components (and export).
func sbomComponentFilter(c *fiber.Ctx) (ComponentFilter, error) {
	id, err := httpx.ID(c, "sbomID")
	if err != nil {
		return ComponentFilter{}, err
	}
	f, err := componentFilter(c)
	f.SbomID = id
	return f, err
}

// projectComponentFilter is the filter of GET /projects/{id}/components (and
// export): the project's components — or, with children included (see
// projecttree.Rollup), its and its descendants'.
func (h *Handler) projectComponentFilter(c *fiber.Ctx) (ComponentFilter, error) {
	id, err := httpx.ID(c, "projectID")
	if err != nil {
		return ComponentFilter{}, err
	}
	f, err := componentFilter(c)
	if err != nil {
		return f, err
	}
	ids, err := projecttree.Rollup(c, h.repo.db, id)
	if err != nil {
		return f, err
	}
	if len(ids) > 1 {
		f.ProjectIDs = ids
	} else {
		f.ProjectID = id
	}
	return f, nil
}

// searchComponentFilter is the filter of GET /components (and export),
// restricted to the actor's visible projects.
func searchComponentFilter(c *fiber.Ctx) (ComponentFilter, error) {
	f, err := componentFilter(c)
	if s := authz.VisibleScope(c); !s.AllAccess {
		f.ProjectIDs = s.ProjectIDs // RBAC: restrict to the actor's projects
	}
	return f, err
}

func (h *Handler) listComponents(c *fiber.Ctx, filter ComponentFilter) error {
	page := httpx.ParsePage(c)
	filter.Limit = page.Limit + 1 // fetch one extra to detect a next page
	filter.Offset = page.Offset

	hits, err := h.repo.ListComponents(c.UserContext(), filter)
	if err != nil {
		return err
	}
	hasMore := len(hits) > page.Limit
	if hasMore {
		hits = hits[:page.Limit]
	}
	return c.JSON(fiber.Map{"components": hits, "pagination": httpx.Meta(page, len(hits), hasMore)})
}

// componentFilter reads the shared component query parameters.
func componentFilter(c *fiber.Ctx) (ComponentFilter, error) {
	f := ComponentFilter{
		Name:       c.Query("name"),
		Purl:       c.Query("purl"),
		Version:    c.Query("version"),
		Type:       c.Query("type"),
		Kind:       c.Query("kind"),
		Search:     c.Query("search"),
		LatestOnly: c.QueryBool("latest"),
		// license=<id> / license_category=<ScanCode category>, case-insensitive.
		License:         strings.TrimSpace(c.Query("license")),
		LicenseCategory: strings.TrimSpace(c.Query("license_category")),
	}
	switch c.Query("vulnerable") {
	case "":
	case "true":
		f.Vulnerable = new(true)
	case "false":
		f.Vulnerable = new(false)
	default:
		return ComponentFilter{}, fiber.NewError(fiber.StatusBadRequest, "vulnerable must be true or false")
	}
	switch c.Query("outdated") {
	case "":
	case "true":
		f.Outdated = new(true)
	case "false":
		f.Outdated = new(false)
	default:
		return ComponentFilter{}, fiber.NewError(fiber.StatusBadRequest, "outdated must be true or false")
	}
	switch c.Query("internal") {
	case "":
	case "true":
		f.Internal = new(true)
	case "false":
		f.Internal = new(false)
	default:
		return ComponentFilter{}, fiber.NewError(fiber.StatusBadRequest, "internal must be true or false")
	}
	if f.Kind != "" && f.Kind != KindAI && !slices.Contains(Kinds, f.Kind) {
		return ComponentFilter{}, fiber.NewError(fiber.StatusBadRequest, "kind must be ai, software, model, dataset or ai-service")
	}
	switch f.Integrity = c.Query("integrity"); f.Integrity {
	case "", "verified", "mismatch", "unknown":
	default:
		return ComponentFilter{}, fiber.NewError(fiber.StatusBadRequest, "integrity must be verified, mismatch or unknown")
	}
	return f, nil
}

// snapshot loads the SBOM named in the path, mapping a miss to 404.
func (h *Handler) snapshot(c *fiber.Ctx, param string) (Sbom, error) {
	id, err := httpx.ID(c, param)
	if err != nil {
		return Sbom{}, err
	}
	s, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return Sbom{}, fiber.NewError(fiber.StatusNotFound, "sbom not found")
	}
	return s, err
}

// Vulnerabilities handles GET /sboms/{id}/vulnerabilities: every vulnerability
// this snapshot ships, with the components it hits.
func (h *Handler) Vulnerabilities(c *fiber.Ctx) error {
	s, err := h.snapshot(c, "sbomID")
	if err != nil {
		return err
	}
	vulns, err := h.repo.SnapshotVulnerabilities(c.UserContext(), s.ID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"sbom": s, "vulnerabilities": vulns})
}

// SbomServices handles GET /sboms/{id}/services: the services the snapshot
// declares, with their data flows and warning flags.
func (h *Handler) SbomServices(c *fiber.Ctx) error {
	s, err := h.snapshot(c, "sbomID")
	if err != nil {
		return err
	}
	svcs, err := h.repo.SnapshotServices(c.UserContext(), s.ID)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"sbom": s, "services": svcs, "summary": SummarizeServices(svcs)})
}

// ProjectServices handles GET /projects/{id}/services?branch=|release=: the
// services of the version's current snapshots (newest per artifact); the
// default version unless one is named.
func (h *Handler) ProjectServices(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	branch, release := strings.TrimSpace(c.Query("branch")), strings.TrimSpace(c.Query("release"))
	if branch != "" && release != "" {
		return fiber.NewError(fiber.StatusBadRequest, "give branch or release, not both")
	}
	svcs, err := h.repo.ProjectServices(c.UserContext(), projectID, cmp.Or(branch, release))
	if errors.Is(err, ErrVersionNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "version not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"services": svcs, "summary": SummarizeServices(svcs)})
}

// Export handles GET /sboms/{id}/export?format=cyclonedx&vulnerabilities=true:
// the snapshot as a CycloneDX 1.6 JSON BOM — components, services, dependency
// graph and (unless vulnerabilities=false) its vulnerabilities with the
// project's analysis.
func (h *Handler) Export(c *fiber.Ctx) error {
	if f := strings.ToLower(c.Query("format", "cyclonedx")); f != "cyclonedx" {
		return fiber.NewError(fiber.StatusBadRequest, "format must be cyclonedx")
	}
	spec, err := vex.ParseCDXSpec(c.Query("spec"))
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	withVulns := true
	switch c.Query("vulnerabilities") {
	case "", "true":
	case "false":
		withVulns = false
	default:
		return fiber.NewError(fiber.StatusBadRequest, "vulnerabilities must be true or false")
	}
	ctx := c.UserContext()
	s, err := h.snapshot(c, "sbomID")
	if err != nil {
		return err
	}
	comps, err := h.repo.SnapshotComponents(ctx, s.ID)
	if err != nil {
		return err
	}
	edges, err := h.repo.Edges(ctx, s.ID)
	if err != nil {
		return err
	}
	svcs, err := h.repo.SnapshotServices(ctx, s.ID)
	if err != nil {
		return err
	}
	var vulns []Vulnerability
	var facts []TriageFact
	if withVulns {
		if vulns, err = h.repo.SnapshotVulnerabilities(ctx, s.ID); err != nil {
			return err
		}
		if facts, err = h.repo.SnapshotTriage(ctx, s.ID); err != nil {
			return err
		}
	}
	name := cmp.Or(s.Artifact, "sbom") + "-" + cmp.Or(s.Version, s.ID)
	name = strings.Map(func(r rune) rune {
		if r == '/' || r == '\\' || r == '"' || r < 0x20 {
			return '_'
		}
		return r
	}, name)
	c.Set(fiber.HeaderContentDisposition, `attachment; filename="`+name+`.cdx.json"`)
	if err := c.JSON(ExportCycloneDX(s, comps, svcs, edges, vulns, facts, spec)); err != nil {
		return err
	}
	c.Set(fiber.HeaderContentType, "application/vnd.cyclonedx+json")
	return nil
}

// Diff handles GET /sboms/{id}/diff?base={id}: what changed since base, which
// defaults to the previous snapshot of the same artifact. The base must belong
// to the same project — authorization covered the head's project, not another.
func (h *Handler) Diff(c *fiber.Ctx) error {
	ctx := c.UserContext()
	head, err := h.snapshot(c, "sbomID")
	if err != nil {
		return err
	}
	var base *Sbom
	if baseID := c.Query("base"); baseID != "" {
		if uuid.Validate(baseID) != nil {
			return fiber.NewError(fiber.StatusBadRequest, "base must be an sbom id")
		}
		b, err := h.repo.Get(ctx, baseID)
		if errors.Is(err, ErrNotFound) || (err == nil && b.ProjectID != head.ProjectID) {
			return fiber.NewError(fiber.StatusNotFound, "base sbom not found in this project")
		}
		if err != nil {
			return err
		}
		base = &b
	} else if prev, ok, err := h.repo.Previous(ctx, head); err != nil {
		return err
	} else if ok {
		base = &prev
	}

	headComps, err := h.repo.SnapshotComponents(ctx, head.ID)
	if err != nil {
		return err
	}
	headSvcs, err := h.repo.SnapshotServices(ctx, head.ID)
	if err != nil {
		return err
	}
	var baseComps []ComponentHit
	var baseSvcs []BomService
	if base != nil {
		if baseComps, err = h.repo.SnapshotComponents(ctx, base.ID); err != nil {
			return err
		}
		if baseSvcs, err = h.repo.SnapshotServices(ctx, base.ID); err != nil {
			return err
		}
	}
	changes, unchanged, summary := DiffComponents(baseComps, headComps)
	services := DiffServices(baseSvcs, headSvcs)
	summary.countServices(services)
	return c.JSON(Diff{Base: base, Head: head, Changes: changes, Unchanged: unchanged, Services: services, Summary: summary})
}

// graph loads a snapshot's full graph.
func (h *Handler) graph(c *fiber.Ctx) (Graph, error) {
	s, err := h.snapshot(c, "sbomID")
	if err != nil {
		return Graph{}, err
	}
	comps, err := h.repo.SnapshotComponents(c.UserContext(), s.ID)
	if err != nil {
		return Graph{}, err
	}
	svcs, err := h.repo.SnapshotServices(c.UserContext(), s.ID)
	if err != nil {
		return Graph{}, err
	}
	edges, err := h.repo.Edges(c.UserContext(), s.ID)
	if err != nil {
		return Graph{}, err
	}
	return BuildGraph(s, comps, svcs, edges), nil
}

// Graph handles GET /sboms/{id}/graph: nodes (with vulnerability state) + edges.
func (h *Handler) Graph(c *fiber.Ctx) error {
	g, err := h.graph(c)
	if err != nil {
		return err
	}
	return c.JSON(g)
}

// GraphPaths handles GET /sboms/{id}/graph/paths?ref=… (or ?component_id=…):
// the shortest routes from the root down to that package — "why is this here,
// and which direct dependency pulls it in?".
func (h *Handler) GraphPaths(c *fiber.Ctx) error {
	g, err := h.graph(c)
	if err != nil {
		return err
	}
	target := c.Query("ref")
	if cid := c.Query("component_id"); cid != "" {
		for _, n := range g.Nodes {
			if n.ComponentID != nil && *n.ComponentID == cid {
				target = n.Ref
			}
		}
		if target == "" {
			return fiber.NewError(fiber.StatusNotFound, "component not in this sbom")
		}
	}
	if target == "" {
		return fiber.NewError(fiber.StatusBadRequest, "ref or component_id is required")
	}
	byRef := make(map[string]Node, len(g.Nodes))
	for _, n := range g.Nodes {
		byRef[n.Ref] = n
	}
	if _, ok := byRef[target]; !ok {
		return fiber.NewError(fiber.StatusNotFound, "ref not in this sbom's graph")
	}
	paths := [][]Node{}
	for _, p := range g.Paths(target, MaxPaths) {
		nodes := make([]Node, len(p))
		for i, ref := range p {
			nodes[i] = byRef[ref]
		}
		paths = append(paths, nodes)
	}
	return c.JSON(fiber.Map{"target": byRef[target], "paths": paths})
}

// VulnerabilityTimeline handles GET /vulnerabilities/{id}/sboms: every artifact
// that ever shipped this CVE / advisory, snapshot by snapshot, with the release
// that introduced it and the one that fixed it. Scoped to visible projects.
func (h *Handler) VulnerabilityTimeline(c *fiber.Ctx) error {
	id := strings.TrimSpace(c.Params("vulnID"))
	if id == "" {
		return fiber.NewError(fiber.StatusBadRequest, "vulnerability id is required")
	}
	var pids []string
	if s := authz.VisibleScope(c); !s.AllAccess {
		pids = s.ProjectIDs
	}
	timeline, err := h.repo.VulnerabilityTimeline(c.UserContext(), id, pids)
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"vulnerability": id, "artifacts": timeline})
}
