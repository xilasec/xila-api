package engagement

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/auth"
	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/findingtemplate"
	"github.com/xilasec/xila-api/internal/httpx"
	"github.com/xilasec/xila-api/internal/scan"
)

// findingAdder records findings through the ingest pipeline (scan.Service).
type findingAdder interface {
	AddFindingsTo(ctx context.Context, t scan.Target, scanner string, category domain.Category, fs []finding.Finding) (scan.Scan, error)
}

// findingStore reads back and tags the finding just added (finding.Repository).
type findingStore interface {
	List(ctx context.Context, f finding.Filter) ([]finding.Finding, error)
	Apply(ctx context.Context, ids []string, c finding.Change, actor string) ([]finding.Finding, error)
	Get(ctx context.Context, id string) (finding.Finding, error)
}

// templateStore resolves a finding template (findingtemplate.Repository).
type templateStore interface {
	Get(ctx context.Context, id string) (findingtemplate.Template, error)
}

// Handler serves engagements and manual findings.
type Handler struct {
	repo      *Repository
	adder     findingAdder
	findings  findingStore
	templates templateStore
}

// NewHandler constructs the handler.
func NewHandler(repo *Repository, adder findingAdder, findings findingStore, templates templateStore) *Handler {
	return &Handler{repo: repo, adder: adder, findings: findings, templates: templates}
}

// Register mounts the routes. authz: project routes by the project's role
// (GET viewer, writes editor); /engagements/{id} by its project.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/projects/:projectID/engagements", h.list)
	r.Post("/projects/:projectID/engagements", h.create)
	r.Get("/engagements/:engagementID", h.get)
	r.Patch("/engagements/:engagementID", h.update)
	r.Post("/projects/:projectID/findings", h.createManual)
}

func mapErr(err error) error {
	switch {
	case errors.Is(err, ErrValidation):
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrNoProject):
		return fiber.NewError(fiber.StatusNotFound, err.Error())
	}
	return err
}

func (h *Handler) list(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	list, err := h.repo.List(c.UserContext(), pid, c.QueryBool("archived"))
	if err != nil {
		return err
	}
	return c.JSON(fiber.Map{"engagements": list})
}

func (h *Handler) create(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var e Engagement
	if err := httpx.Parse(c, &e); err != nil {
		return err
	}
	e.ProjectID = pid
	if err := e.Validate(); err != nil {
		return mapErr(err)
	}
	out, err := h.repo.Create(c.UserContext(), e, auth.UserID(c))
	if err != nil {
		return mapErr(err)
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}

func (h *Handler) get(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "engagementID")
	if err != nil {
		return err
	}
	e, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		return mapErr(err)
	}
	return c.JSON(e)
}

func (h *Handler) update(c *fiber.Ctx) error {
	id, err := httpx.ID(c, "engagementID")
	if err != nil {
		return err
	}
	cur, err := h.repo.Get(c.UserContext(), id)
	if err != nil {
		return mapErr(err)
	}
	// Absent fields keep their value: decode over the current engagement.
	if err := httpx.Parse(c, &cur); err != nil {
		return err
	}
	cur.ID = id
	if err := cur.Validate(); err != nil {
		return mapErr(err)
	}
	out, err := h.repo.Update(c.UserContext(), cur)
	if err != nil {
		return mapErr(err)
	}
	return c.JSON(out)
}

// ManualFinding is what a person reports by hand.
type ManualFinding struct {
	Title            string          `json:"title"`
	Severity         domain.Severity `json:"severity"`
	Category         domain.Category `json:"category"`
	Description      string          `json:"description"`
	Mitigation       string          `json:"mitigation"`
	Impact           string          `json:"impact"`
	StepsToReproduce string          `json:"steps_to_reproduce"`
	References       []string        `json:"references"`
	CWE              *int            `json:"cwe"`
	CVE              []string        `json:"cve"`
	URL              string          `json:"url"`
	FilePath         string          `json:"file_path"`
	Line             *int            `json:"line"`
	Package          string          `json:"package"`
	PackageVersion   string          `json:"package_version"`
	FixedVersion     string          `json:"fixed_version"`
	Tags             []string        `json:"tags"`
	EngagementID     string          `json:"engagement_id"`
	VersionID        string          `json:"version_id"`
	TemplateID       string          `json:"template_id"`
}

// fill takes every field left empty from the template.
func (m *ManualFinding) fill(t findingtemplate.Template) {
	if m.Title == "" {
		m.Title = t.Title
	}
	if m.Severity == "" {
		m.Severity = t.Severity
	}
	if m.Category == "" {
		m.Category = t.Category
	}
	if m.CWE == nil {
		m.CWE = t.CWE
	}
	if len(m.CVE) == 0 {
		m.CVE = t.CVE
	}
	for _, f := range []struct {
		dst *string
		src string
	}{
		{&m.Description, t.Description}, {&m.Mitigation, t.Mitigation}, {&m.Impact, t.Impact},
	} {
		if *f.dst == "" {
			*f.dst = f.src
		}
	}
	if len(m.References) == 0 {
		m.References = t.References
	}
	if len(m.Tags) == 0 {
		m.Tags = t.Tags
	}
}

// createManual handles POST /projects/{id}/findings: a finding a person found.
// It is recorded as scanner "manual" (in the engagement, when given) and added
// without auto-close — a new manual finding never closes the earlier ones —
// so it otherwise runs the scanner pipeline: triage rules, dedup, priority,
// SLA, alerts, history.
func (h *Handler) createManual(c *fiber.Ctx) error {
	pid, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	var m ManualFinding
	if err := httpx.Parse(c, &m); err != nil {
		return err
	}
	if m.TemplateID != "" {
		t, err := h.templates.Get(c.UserContext(), m.TemplateID)
		if errors.Is(err, findingtemplate.ErrNotFound) {
			return fiber.NewError(fiber.StatusBadRequest, "template_id: no such template")
		}
		if err != nil {
			return err
		}
		m.fill(t)
	}
	m.Title = strings.TrimSpace(m.Title)
	if m.Category == "" {
		m.Category = domain.CategoryDAST
	}
	switch {
	case m.Title == "":
		return fiber.NewError(fiber.StatusBadRequest, "title is required")
	case !m.Severity.Valid():
		return fiber.NewError(fiber.StatusBadRequest, "severity must be critical, high, medium, low or info")
	case !m.Category.Valid():
		return fiber.NewError(fiber.StatusBadRequest, "invalid category")
	}
	tags, err := finding.NormalizeTags(m.Tags)
	if err != nil {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if m.EngagementID != "" {
		e, err := h.repo.Get(c.UserContext(), m.EngagementID)
		if err != nil || e.ProjectID != pid {
			return fiber.NewError(fiber.StatusBadRequest, "engagement_id: not an engagement of this project")
		}
	}

	meta := map[string]any{"author": auth.UserID(c)}
	for k, v := range map[string]string{"mitigation": m.Mitigation, "impact": m.Impact, "steps_to_reproduce": m.StepsToReproduce} {
		if v != "" {
			meta[k] = v
		}
	}
	if len(m.References) > 0 {
		meta["references"] = strings.Join(m.References, "\n")
	}
	if m.TemplateID != "" {
		meta["template_id"] = m.TemplateID
	}
	cves := slices.Clone(m.CVE)
	ruleID := ""
	if len(cves) > 0 {
		ruleID = cves[0]
	}
	f := finding.Finding{
		Fingerprint: "manual:" + uuid.NewString(), // every report is its own finding
		Category:    m.Category, RuleID: ruleID, Title: m.Title, Description: m.Description,
		Severity: m.Severity, CWE: m.CWE, CVE: cves, URL: m.URL, FilePath: m.FilePath, Line: m.Line,
		PackageName: m.Package, PackageVersion: m.PackageVersion, FixedVersion: m.FixedVersion,
		Metadata: meta,
	}
	sc, err := h.adder.AddFindingsTo(c.UserContext(), scan.Target{ProjectID: pid, VersionID: m.VersionID, EngagementID: m.EngagementID, Actor: auth.UserID(c)},
		finding.ManualScanner, m.Category, []finding.Finding{f})
	if errors.Is(err, scan.ErrProjectNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	}
	if errors.Is(err, scan.ErrCollection) {
		return fiber.NewError(fiber.StatusConflict, err.Error())
	}
	if err != nil {
		return err
	}
	got, err := h.findings.List(c.UserContext(), finding.Filter{ProjectID: pid, ScanID: sc.ID, IncludeDuplicates: true, Limit: 1})
	if err != nil || len(got) != 1 {
		return errors.Join(errors.New("manual finding not recorded"), err)
	}
	out := got[0]
	if len(tags) > 0 {
		updated, err := h.findings.Apply(c.UserContext(), []string{out.ID}, finding.Change{SetTags: true, Tags: tags}, auth.UserID(c))
		if err != nil {
			return err
		}
		out = updated[0]
	}
	return c.Status(fiber.StatusCreated).JSON(out)
}
