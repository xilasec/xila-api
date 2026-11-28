package vulnmatch

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/httpx"
)

// Handler exposes the matcher's admin endpoints: an on-demand re-evaluation,
// the configured sources and the local OSV mirror (import, sync, stats).
// Admin-gated by the authz middleware (/vulnmatch is portfolio-wide).
type Handler struct {
	svc     *Service
	sources []string
	mirror  *OSVRepository // nil: no local mirror wired
	sync    *Mirror        // nil: no scheduled download configured
	jvn     *JVNMirror     // nil: the jvn source isn't configured
}

// NewHandler constructs the Handler. sources lists the configured source
// names; repo and mirror may be nil.
func NewHandler(svc *Service, sources []string, repo *OSVRepository, mirror *Mirror) *Handler {
	if sources == nil {
		sources = []string{}
	}
	return &Handler{svc: svc, sources: sources, mirror: repo, sync: mirror}
}

// WithJVN exposes the JVN iPedia mirror (stats and an on-demand sync).
func (h *Handler) WithJVN(m *JVNMirror) *Handler {
	h.jvn = m
	return h
}

// Register mounts the routes.
func (h *Handler) Register(r fiber.Router) {
	r.Post("/vulnmatch", h.Run)
	r.Get("/vulnmatch/sources", h.Sources)
	r.Post("/vulnmatch/osv-import", h.Import)
	r.Post("/vulnmatch/osv-mirror/sync", h.Sync)
	r.Post("/vulnmatch/jvn/sync", h.SyncJVN)
}

// Run re-evaluates every SBOM snapshot against the advisory sources now.
func (h *Handler) Run(c *fiber.Ctx) error {
	n, err := h.svc.Match(c.UserContext())
	if partial, ok := errors.AsType[*PartialError](err); ok {
		return c.JSON(fiber.Map{"findings": n, "partial": true, "failed_sources": partial.FailedSources()})
	}
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"findings": n, "partial": false, "failed_sources": []string{}})
}

// Sources reports the configured advisory sources and the local mirror's state.
func (h *Handler) Sources(c *fiber.Ctx) error {
	out := fiber.Map{"sources": h.sources, "mirror": nil, "jvn": nil}
	if h.mirror != nil {
		st, err := h.mirror.Stats(c.UserContext())
		if err != nil {
			return err
		}
		out["mirror"] = st
	}
	if h.jvn != nil {
		st, err := h.jvn.repo.Stats(c.UserContext())
		if err != nil {
			return err
		}
		out["jvn"] = st
	}
	return c.JSON(out)
}

// SyncJVN downloads JVN iPedia's feeds into the mirror now.
func (h *Handler) SyncJVN(c *fiber.Ctx) error {
	if h.jvn == nil {
		return fiber.NewError(fiber.StatusConflict, "the jvn source is not configured (VULNMATCH_SOURCES)")
	}
	res, err := h.jvn.Sync(c.UserContext())
	if err != nil {
		slog.WarnContext(c.UserContext(), "jvn sync failed", "error", err)
		return fiber.NewError(fiber.StatusBadGateway, "JVN iPedia sync failed (partially or completely); see the server log")
	}
	return c.JSON(res)
}

// Import loads an OSV ecosystem export (multipart field "file": the all.zip
// from osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip) into the
// local mirror. Idempotent: re-importing changes only advisories whose
// `modified` is newer.
func (h *Handler) Import(c *fiber.Ctx) error {
	if h.mirror == nil {
		return fiber.NewError(fiber.StatusServiceUnavailable, "local OSV mirror not available")
	}
	fh, err := c.FormFile("file")
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "upload the OSV export zip as multipart field \"file\"")
	}
	f, err := fh.Open()
	if err != nil {
		return err
	}
	defer f.Close()
	res, err := h.mirror.ImportZip(c.UserContext(), f, fh.Size)
	if errors.Is(err, ErrInvalidExport) {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if err != nil {
		return err
	}
	return c.JSON(res)
}

// Sync downloads and imports the configured ecosystems now.
func (h *Handler) Sync(c *fiber.Ctx) error {
	if h.sync == nil || len(h.sync.ecosystems) == 0 {
		return fiber.NewError(fiber.StatusConflict, "no mirror ecosystems configured (VULNMATCH_OSV_ECOSYSTEMS)")
	}
	res, err := h.sync.Sync(c.UserContext())
	if err != nil {
		return fiber.NewError(fiber.StatusBadGateway, err.Error())
	}
	return c.JSON(res)
}

// AdvisoryHandler serves the private advisory database. Reads are open to any
// signed-in user (advisories describe internal packages, not a tenant's data);
// mutations are instance-admin (authz).
type AdvisoryHandler struct {
	repo     *AdvisoryRepository
	onChange func() // re-match after an edit; nil = wait for the schedule
}

// NewAdvisoryHandler constructs the handler. onChange (optional) runs after
// every mutation — main wires it to a background re-match, so a new advisory
// shows up as findings (and a withdrawn one closes them) without waiting.
func NewAdvisoryHandler(repo *AdvisoryRepository, onChange func()) *AdvisoryHandler {
	return &AdvisoryHandler{repo: repo, onChange: onChange}
}

// Register mounts the routes.
func (h *AdvisoryHandler) Register(r fiber.Router) {
	r.Get("/advisories", h.List)
	r.Post("/advisories", h.Create)
	r.Post("/advisories/import", h.Import)
	r.Get("/advisories/:advisoryID", h.Get)
	r.Put("/advisories/:advisoryID", h.Update)
	r.Delete("/advisories/:advisoryID", h.Delete)
}

func (h *AdvisoryHandler) changed() {
	if h.onChange != nil {
		h.onChange()
	}
}

// List returns advisories (?q= search, ?withdrawn=true to include withdrawn).
func (h *AdvisoryHandler) List(c *fiber.Ctx) error {
	page := httpx.ParsePage(c)
	list, err := h.repo.List(c.UserContext(), AdvisoryFilter{
		Query: c.Query("q"), IncludeWithdrawn: c.QueryBool("withdrawn"),
		Limit: page.Limit + 1, Offset: page.Offset,
	})
	if err != nil {
		return err
	}
	hasMore := len(list) > page.Limit
	if hasMore {
		list = list[:page.Limit]
	}
	return c.JSON(fiber.Map{"advisories": list, "pagination": httpx.Meta(page, len(list), hasMore)})
}

// Get returns one advisory.
func (h *AdvisoryHandler) Get(c *fiber.Ctx) error {
	a, err := h.repo.Get(c.UserContext(), c.Params("advisoryID"))
	if errors.Is(err, ErrAdvisoryNotFound) {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	if err != nil {
		return err
	}
	return c.JSON(a)
}

// Create stores a new advisory (id optional: XILA-<year>-<NNNN> is assigned).
func (h *AdvisoryHandler) Create(c *fiber.Ctx) error {
	var a Advisory
	if err := c.BodyParser(&a); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if err := a.Validate(); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	out, err := h.repo.Create(c.UserContext(), a, actorID(c))
	if errors.Is(err, ErrAdvisoryDuplicate) {
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	if err != nil {
		return err
	}
	h.changed()
	return c.Status(fiber.StatusCreated).JSON(out)
}

// Update replaces an advisory. Set "withdrawn" to retract it.
func (h *AdvisoryHandler) Update(c *fiber.Ctx) error {
	var a Advisory
	if err := c.BodyParser(&a); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	a.ID = c.Params("advisoryID")
	if err := a.Validate(); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	out, err := h.repo.Update(c.UserContext(), a)
	if errors.Is(err, ErrAdvisoryNotFound) {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	if err != nil {
		return err
	}
	h.changed()
	return c.JSON(out)
}

// Delete removes an advisory.
func (h *AdvisoryHandler) Delete(c *fiber.Ctx) error {
	err := h.repo.Delete(c.UserContext(), c.Params("advisoryID"))
	if errors.Is(err, ErrAdvisoryNotFound) {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	if err != nil {
		return err
	}
	h.changed()
	return c.SendStatus(fiber.StatusNoContent)
}

// Import creates or replaces advisories from OSV JSON: one document, or an
// array of documents. All are validated before any is stored.
func (h *AdvisoryHandler) Import(c *fiber.Ctx) error {
	body := strings.TrimSpace(string(c.Body()))
	var docs []json.RawMessage
	if strings.HasPrefix(body, "[") {
		if err := json.Unmarshal([]byte(body), &docs); err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "invalid JSON array")
		}
	} else {
		docs = []json.RawMessage{json.RawMessage(body)}
	}
	advisories := make([]Advisory, 0, len(docs))
	for i, d := range docs {
		a, err := AdvisoryFromOSV(d)
		if err == nil {
			err = a.Validate()
		}
		if err != nil {
			return fiber.NewError(fiber.StatusBadRequest, "document "+strconv.Itoa(i)+": "+err.Error())
		}
		if a.ID == "" {
			return fiber.NewError(fiber.StatusBadRequest, "document "+strconv.Itoa(i)+": id is required")
		}
		advisories = append(advisories, a)
	}
	created, updated := 0, 0
	for _, a := range advisories {
		isNew, err := h.repo.Upsert(c.UserContext(), a, actorID(c))
		if err != nil {
			return err
		}
		if isNew {
			created++
		} else {
			updated++
		}
	}
	if len(advisories) > 0 {
		h.changed()
	}
	return c.JSON(fiber.Map{"created": created, "updated": updated})
}

// FeedRuleHandler manages feed rules (instance-admin; authz).
type FeedRuleHandler struct {
	repo     *FeedRuleRepository
	onChange func() // re-match after an edit; nil = wait for the schedule
}

// NewFeedRuleHandler constructs the handler. onChange (optional) runs after
// every mutation, so a mute closes its findings without waiting.
func NewFeedRuleHandler(repo *FeedRuleRepository, onChange func()) *FeedRuleHandler {
	return &FeedRuleHandler{repo: repo, onChange: onChange}
}

// Register mounts the routes.
func (h *FeedRuleHandler) Register(r fiber.Router) {
	r.Get("/feed-rules", h.List)
	r.Post("/feed-rules", h.Create)
	r.Get("/feed-rules/:ruleID", h.Get)
	r.Put("/feed-rules/:ruleID", h.Update)
	r.Delete("/feed-rules/:ruleID", h.Delete)
}

func (h *FeedRuleHandler) changed() {
	if h.onChange != nil {
		h.onChange()
	}
}

// List returns every rule in evaluation order.
func (h *FeedRuleHandler) List(c *fiber.Ctx) error {
	rules, err := h.repo.List(c.UserContext())
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"feed_rules": rules})
}

// Get returns one rule.
func (h *FeedRuleHandler) Get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "ruleID")
	if err != nil {
		return err
	}
	rule, err := h.repo.Get(c.UserContext(), id)
	if errors.Is(err, ErrFeedRuleNotFound) {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	if err != nil {
		return err
	}
	return c.JSON(rule)
}

// Create stores a rule.
func (h *FeedRuleHandler) Create(c *fiber.Ctx) error {
	var rule FeedRule
	if err := c.BodyParser(&rule); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	if err := rule.Validate(); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	out, err := h.repo.Create(c.UserContext(), rule, actorID(c))
	if err != nil {
		return err
	}
	h.changed()
	return c.Status(fiber.StatusCreated).JSON(out)
}

// Update replaces a rule.
func (h *FeedRuleHandler) Update(c *fiber.Ctx) error {
	var rule FeedRule
	if err := c.BodyParser(&rule); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid JSON body")
	}
	id, err := httpx.ID(c, "ruleID")
	if err != nil {
		return err
	}
	rule.ID = id
	if err := rule.Validate(); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	out, err := h.repo.Update(c.UserContext(), rule)
	if errors.Is(err, ErrFeedRuleNotFound) {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	if err != nil {
		return err
	}
	h.changed()
	return c.JSON(out)
}

// Delete removes a rule.
func (h *FeedRuleHandler) Delete(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "ruleID")
	if err != nil {
		return err
	}
	err = h.repo.Delete(c.UserContext(), id)
	if errors.Is(err, ErrFeedRuleNotFound) {
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	if err != nil {
		return err
	}
	h.changed()
	return c.SendStatus(fiber.StatusNoContent)
}

func actorID(c *fiber.Ctx) *string {
	if a := auth.CurrentActor(c); a.UserID != "" {
		return &a.UserID
	}
	return nil
}

// Kick runs a full match in the background — after a private advisory changed.
// Kicks while a run is in flight coalesce into one follow-up run, so a burst of
// edits costs at most two matches. Errors are logged.
func (s *Service) Kick(ctx context.Context) {
	s.kickMu.Lock()
	if s.kickRunning {
		s.kickPending = true
		s.kickMu.Unlock()
		return
	}
	s.kickRunning = true
	s.kickMu.Unlock()
	go func() {
		for {
			if n, err := s.Match(ctx); err != nil {
				slog.WarnContext(ctx, "vulnmatch: re-match after advisory change", "error", err, "findings", n)
			}
			s.kickMu.Lock()
			if !s.kickPending || ctx.Err() != nil {
				s.kickRunning = false
				s.kickMu.Unlock()
				return
			}
			s.kickPending = false
			s.kickMu.Unlock()
		}
	}()
}
