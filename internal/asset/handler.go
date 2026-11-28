package asset

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/httpx"
)

// accessChecker answers the cross-project visibility questions relation and
// blast-radius routes need: the other end of an edge can sit in a project the
// route's middleware never looked at. membership.Repository satisfies it.
type accessChecker interface {
	AdminStatus(ctx context.Context, userID string) (isAdmin, isOwner bool, err error)
	ProjectIDsForUser(ctx context.Context, userID string) ([]string, error)
}

// Handler exposes asset CRUD, exposure and relationships over HTTP.
type Handler struct {
	repo   *Repository
	svc    *Service
	access accessChecker
}

// NewHandler constructs an asset Handler.
func NewHandler(repo *Repository, svc *Service, access accessChecker) *Handler {
	return &Handler{repo: repo, svc: svc, access: access}
}

// Register mounts asset routes.
func (h *Handler) Register(r fiber.Router) {
	r.Post("/projects/:projectID/assets", h.Create)
	r.Get("/projects/:projectID/assets", h.ListByProject)
	r.Get("/assets", h.List)
	r.Get("/assets/:assetID", h.Get)
	r.Patch("/assets/:assetID", h.Update)
	r.Delete("/assets/:assetID", h.Delete)
	r.Put("/assets/:assetID/exposure", h.SetExposure)
	r.Get("/assets/:assetID/relations", h.ListRelations)
	r.Post("/assets/:assetID/relations", h.CreateRelation)
	r.Get("/assets/:assetID/relations/suggestions", h.Suggestions)
	r.Delete("/assets/:assetID/relations/:relationID", h.DeleteRelation)
	r.Get("/assets/:assetID/blast-radius", h.BlastRadius)
}

type createRequest struct {
	Type       domain.AssetType `json:"type"`
	Name       string           `json:"name"`
	Identifier string           `json:"identifier"`
	Metadata   map[string]any   `json:"metadata"`
}

func (h *Handler) Create(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var body createRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	body.Name = strings.TrimSpace(body.Name)
	if body.Name == "" {
		return fiber.NewError(fiber.StatusBadRequest, "name is required")
	}
	if !body.Type.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "invalid asset type")
	}

	a, err := h.repo.Create(c.UserContext(), Asset{
		ProjectID:  projectID,
		Type:       body.Type,
		Name:       body.Name,
		Identifier: body.Identifier,
		Metadata:   body.Metadata,
	})
	switch {
	case errors.Is(err, ErrDuplicate):
		return fiber.NewError(fiber.StatusConflict, "asset already exists for this project")
	case errors.Is(err, ErrNoProject):
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	case err != nil:
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(a)
}

func (h *Handler) ListByProject(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	return h.list(c, Filter{ProjectID: projectID, Type: domain.AssetType(c.Query("type"))})
}

// List handles GET /assets (portfolio, optional ?type= and ?project_id=).
func (h *Handler) List(c *fiber.Ctx) error {
	f := Filter{ProjectID: c.Query("project_id"), Type: domain.AssetType(c.Query("type"))}
	if s := authz.VisibleScope(c); !s.AllAccess {
		f.ProjectIDs = s.ProjectIDs // RBAC: restrict to the actor's projects
	}
	return h.list(c, f)
}

func (h *Handler) list(c *fiber.Ctx, filter Filter) error {
	if filter.Type != "" && !filter.Type.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "invalid asset type filter")
	}
	custom, err := customfield.ParseFilters(c.Queries())
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	filter.Custom = custom
	assets, err := h.repo.List(c.UserContext(), filter)
	if err != nil {
		return err
	}
	assets, err = h.repo.AttachRisk(c.UserContext(), assets)
	if err != nil {
		return err
	}
	if c.Query("sort") == "risk" {
		sort.SliceStable(assets, func(i, j int) bool { return assets[i].RiskScore > assets[j].RiskScore })
	}
	return c.JSON(fiber.Map{"assets": assets})
}

func (h *Handler) Get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "assetID")
	if err != nil {
		return err
	}
	a, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "asset not found")
	}
	if err != nil {
		return err
	}
	withRisk, err := h.repo.AttachRisk(c.UserContext(), []Asset{a})
	if err != nil {
		return err
	}
	return c.JSON(withRisk[0])
}

type updateRequest struct {
	Name       *string `json:"name"`
	Identifier *string `json:"identifier"`
}

func (h *Handler) Update(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "assetID")
	if err != nil {
		return err
	}
	var body updateRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	a, err := h.repo.Update(c.UserContext(), id, body.Name, body.Identifier)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "asset not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(a)
}

func (h *Handler) Delete(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "assetID")
	if err != nil {
		return err
	}
	if err := h.repo.Delete(c.UserContext(), id); errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "asset not found")
	} else if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

type exposureRequest struct {
	Exposure domain.Exposure `json:"exposure"`
	Reason   string          `json:"reason"`
}

// SetExposure handles PUT /assets/{id}/exposure: a manual assessment ("" clears
// it back to unknown). The asset's findings are re-ranked immediately.
func (h *Handler) SetExposure(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "assetID")
	if err != nil {
		return err
	}
	var body exposureRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	if !body.Exposure.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "exposure must be internet, internal, isolated or empty (unknown)")
	}
	body.Reason = strings.TrimSpace(body.Reason)
	if len(body.Reason) > 1000 {
		return fiber.NewError(fiber.StatusBadRequest, "reason is too long (max 1000 characters)")
	}
	a, err := h.svc.SetExposure(c.UserContext(), id, body.Exposure, body.Reason)
	if errors.Is(err, ErrNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "asset not found")
	}
	if err != nil {
		return err
	}
	return c.JSON(a)
}

// visibility is the set of projects the caller may see; all for instance admins.
type visibility struct {
	all      bool
	projects map[string]bool
}

func (v visibility) can(projectID string) bool { return v.all || v.projects[projectID] }

func (v visibility) list() []string {
	out := make([]string, 0, len(v.projects))
	for p := range v.projects {
		out = append(out, p)
	}
	return out
}

func (h *Handler) visible(c *fiber.Ctx) (visibility, error) {
	actor := auth.CurrentActor(c)
	if actor.ProjectID != "" { // a project-scoped API token sees its project only
		return visibility{projects: map[string]bool{actor.ProjectID: true}}, nil
	}
	isAdmin, _, err := h.access.AdminStatus(c.UserContext(), actor.UserID)
	if err != nil || isAdmin {
		return visibility{all: isAdmin}, err
	}
	pids, err := h.access.ProjectIDsForUser(c.UserContext(), actor.UserID)
	if err != nil {
		return visibility{}, err
	}
	v := visibility{projects: make(map[string]bool, len(pids))}
	for _, p := range pids {
		v.projects[p] = true
	}
	return v, nil
}

// ListRelations handles GET /assets/{id}/relations: every edge touching the
// asset whose other end the caller can see.
func (h *Handler) ListRelations(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "assetID")
	if err != nil {
		return err
	}
	if _, err := h.get(c, id); err != nil {
		return err
	}
	v, err := h.visible(c)
	if err != nil {
		return err
	}
	rels, err := h.repo.ListRelations(c.UserContext(), id)
	if err != nil {
		return err
	}
	out := make([]Relation, 0, len(rels))
	for _, r := range rels {
		other := r.To
		if r.ToAssetID == id {
			other = r.From
		}
		if v.can(other.ProjectID) {
			out = append(out, r)
		}
	}
	return c.JSON(fiber.Map{"relations": out})
}

type relationRequest struct {
	FromAssetID string       `json:"from_asset_id"`
	ToAssetID   string       `json:"to_asset_id"`
	Kind        RelationKind `json:"kind"`
}

// CreateRelation handles POST /assets/{id}/relations. One end must be the path
// asset (the middleware required editor on its project); the caller must be
// able to see the other end.
func (h *Handler) CreateRelation(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "assetID")
	if err != nil {
		return err
	}
	var body relationRequest
	if err := httpx.Parse(c, &body); err != nil {
		return err
	}
	if !body.Kind.Valid() {
		return fiber.NewError(fiber.StatusBadRequest, "kind must be built_from, deployed_as or depends_on")
	}
	other := body.ToAssetID
	switch id {
	case body.FromAssetID:
	case body.ToAssetID:
		other = body.FromAssetID
	default:
		return fiber.NewError(fiber.StatusBadRequest, "from_asset_id or to_asset_id must be this asset")
	}
	if body.FromAssetID == body.ToAssetID {
		return fiber.NewError(fiber.StatusBadRequest, "an asset cannot relate to itself")
	}
	if uuid.Validate(other) != nil {
		return fiber.NewError(fiber.StatusBadRequest, "the related asset id must be a uuid")
	}
	if _, err := h.get(c, id); err != nil {
		return err
	}
	if err := h.mustSee(c, other); err != nil {
		return err
	}
	by := auth.CurrentActor(c).UserID
	rel, err := h.repo.CreateRelation(c.UserContext(), Relation{
		FromAssetID: body.FromAssetID, ToAssetID: body.ToAssetID, Kind: body.Kind, CreatedBy: &by,
	})
	switch {
	case errors.Is(err, ErrRelationDuplicate):
		return fiber.NewError(fiber.StatusConflict, "relation already exists")
	case errors.Is(err, ErrNotFound):
		return fiber.NewError(fiber.StatusNotFound, "asset not found")
	case err != nil:
		return err
	}
	return c.Status(fiber.StatusCreated).JSON(rel)
}

// DeleteRelation handles DELETE /assets/{id}/relations/{relationID}: either end
// may remove an edge.
func (h *Handler) DeleteRelation(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "assetID")
	if err != nil {
		return err
	}
	relID, err := httpx.ID(c, "relationID")
	if err != nil {
		return err
	}
	if err := h.repo.DeleteRelation(c.UserContext(), id, relID); errors.Is(err, ErrRelationNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "relation not found")
	} else if err != nil {
		return err
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// suggestion is a proposed built_from edge, ready to POST back.
type suggestion struct {
	FromAssetID      string       `json:"from_asset_id"`
	ToAssetID        string       `json:"to_asset_id"`
	Kind             RelationKind `json:"kind"`
	Other            Ref          `json:"other"`
	SharedOSPackages int          `json:"shared_os_packages"`
	Reason           string       `json:"reason"`
}

// Suggestions handles GET /assets/{id}/relations/suggestions: built_from edges
// inferred from container images' SBOM OS package sets (ProposeBuiltFrom),
// among images the caller can see, minus edges that already exist. Nothing is
// stored until a suggestion is POSTed to /relations.
func (h *Handler) Suggestions(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "assetID")
	if err != nil {
		return err
	}
	a, err := h.get(c, id)
	if err != nil {
		return err
	}
	out := []suggestion{}
	if a.Type != domain.AssetContainerImage {
		return c.JSON(fiber.Map{"suggestions": out, "os_packages": 0})
	}
	v, err := h.visible(c)
	if err != nil {
		return err
	}
	ctx := c.UserContext()
	mine, overlaps, err := h.repo.OSPackageOverlap(ctx, id, v.all, v.list())
	if err != nil {
		return err
	}
	existing, err := h.repo.ListRelations(ctx, id)
	if err != nil {
		return err
	}
	for _, p := range ProposeBuiltFrom(mine, overlaps) {
		s := suggestion{FromAssetID: p.Other.AssetID, ToAssetID: id, Kind: BuiltFrom,
			SharedOSPackages: p.Other.Shared, Reason: p.Reason}
		if p.Base {
			s.FromAssetID, s.ToAssetID = id, p.Other.AssetID
		}
		if slices.ContainsFunc(existing, func(r Relation) bool {
			return r.Kind == BuiltFrom && r.FromAssetID == s.FromAssetID && r.ToAssetID == s.ToAssetID
		}) {
			continue
		}
		o, err := h.repo.Get(ctx, p.Other.AssetID)
		if err != nil {
			return err
		}
		s.Other = Ref{ID: o.ID, ProjectID: o.ProjectID, Type: o.Type, Name: o.Name, Exposure: o.Exposure}
		out = append(out, s)
	}
	return c.JSON(fiber.Map{"suggestions": out, "os_packages": mine})
}

// blastEntry is one downstream asset with the open findings it shares with the root.
type blastEntry struct {
	Downstream
	SharedFindings []SharedFinding `json:"shared_findings"`
	SharedCount    int             `json:"shared_count"`
}

// maxSharedPerAsset caps the findings listed per downstream asset (the count is exact).
const maxSharedPerAsset = 50

// BlastRadius handles GET /assets/{id}/blast-radius: every asset transitively
// built from this one or deployed as it (or as what was built from it), that
// the caller can see, each with its open findings sharing a CVE or package
// with this asset's open findings.
func (h *Handler) BlastRadius(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "assetID")
	if err != nil {
		return err
	}
	root, err := h.get(c, id)
	if err != nil {
		return err
	}
	v, err := h.visible(c)
	if err != nil {
		return err
	}
	ctx := c.UserContext()
	down, err := h.repo.Downstream(ctx, id)
	if err != nil {
		return err
	}
	entries := []blastEntry{}
	ids := []string{}
	for _, d := range down {
		if v.can(d.Asset.ProjectID) {
			entries = append(entries, blastEntry{Downstream: d, SharedFindings: []SharedFinding{}})
			ids = append(ids, d.Asset.ID)
		}
	}
	shared, err := h.repo.SharedFindings(ctx, id, ids)
	if err != nil {
		return err
	}
	index := make(map[string]int, len(entries))
	for i, e := range entries {
		index[e.Asset.ID] = i
	}
	total := 0
	for _, f := range shared {
		e := &entries[index[f.AssetID]]
		e.SharedCount++
		total++
		if len(e.SharedFindings) < maxSharedPerAsset {
			e.SharedFindings = append(e.SharedFindings, f)
		}
	}
	return c.JSON(fiber.Map{"asset": root, "affected": entries, "shared_findings": total})
}

// get loads the path asset, mapping not-found to 404.
func (h *Handler) get(c *fiber.Ctx, id string) (Asset, error) {
	a, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrNotFound) {
		return Asset{}, fiber.NewError(fiber.StatusNotFound, "asset not found")
	}
	return a, err
}

// mustSee 404s an asset the caller can't see — indistinguishable from a
// missing one, so ids in other tenants can't be probed.
func (h *Handler) mustSee(c *fiber.Ctx, id string) error {
	a, err := h.get(c, id)
	if err != nil {
		return err
	}
	v, err := h.visible(c)
	if err != nil {
		return err
	}
	if !v.can(a.ProjectID) {
		return fiber.NewError(fiber.StatusNotFound, "asset not found")
	}
	return nil
}
