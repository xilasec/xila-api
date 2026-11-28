package report

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/xilasec/xila-api/internal/authz"
	"github.com/xilasec/xila-api/internal/httpx"
)

//go:embed report.html
var reportHTML string

// page is the report template. html/template escapes every value for its
// context, so a finding titled `<script>…` prints as text.
var page = template.Must(template.New("report").Funcs(template.FuncMap{
	"date": func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
	"datep": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.UTC().Format(time.DateOnly)
	},
	"pct": func(f *float64) string {
		if f == nil {
			return "—"
		}
		return strconv.FormatFloat(*f*100, 'f', 1, 64) + "%"
	},
	"epss": func(f *float64) string {
		if f == nil {
			return ""
		}
		return strconv.FormatFloat(*f*100, 'f', 1, 64) + "%"
	},
	"score": func(f float64) string { return strconv.FormatFloat(f, 'f', 1, 64) },
	"bar":   func(f float64) string { return strconv.FormatFloat(f, 'f', 1, 64) },
	"days":  func(f float64) string { return strconv.FormatFloat(f, 'f', 1, 64) + "d" },
	"add":   func(a, b int) int { return a + b },
	"join":  strings.Join,
	// css admits only a #rrggbb colour into the <style> block (validated on
	// write too; this keeps a hand-edited row from injecting CSS).
	"css": func(s string) template.CSS {
		if !hexColor.MatchString(s) {
			return ""
		}
		//nolint:gosec // G203: only a validated #rrggbb reaches here
		return template.CSS(s) // nosemgrep: go.lang.security.audit.xss.template-html-does-not-escape.unsafe-template-type -- only a validated #rrggbb reaches here
	},
	// dataURI admits only an image data: URI as the logo's src; html/template
	// would otherwise rewrite every data: URL to #ZgotmplZ.
	"dataURI": func(s string) template.URL {
		for _, p := range logoPrefix {
			if strings.HasPrefix(s, p) {
				//nolint:gosec // G203: only an image data: URI reaches here
				return template.URL(s) // nosemgrep: go.lang.security.audit.xss.template-html-does-not-escape.unsafe-template-type -- only image data: URIs reach here
			}
		}
		return ""
	},
	// meta reads a write-up field (steps, impact, mitigation, references)
	// from a finding's metadata; non-strings read as empty.
	"meta": func(m map[string]any, key string) string {
		v, _ := m[key].(string)
		return strings.TrimSpace(v)
	},
}).Parse(reportHTML))

// Render writes a report as a self-contained HTML document.
func Render(w io.Writer, r Report) error {
	return page.Execute(w, r)
}

// reportService is what the handler needs from Service.
type reportService interface {
	Project(ctx context.Context, projectID string, opts Options) (Report, error)
	Portfolio(ctx context.Context, pids []string, opts Options) (Report, error)
}

// templateSource resolves ?template= (TemplateRepository).
type templateSource interface {
	Get(ctx context.Context, id string) (Template, error)
}

// Handler serves the HTML reports.
type Handler struct {
	svc       reportService
	templates templateSource
}

// NewHandler constructs a report Handler.
func NewHandler(svc *Service, templates templateSource) *Handler {
	return &Handler{svc: svc, templates: templates}
}

// options reads ?template= and ?engagement_id=.
func (h *Handler) options(c *fiber.Ctx) (Options, error) {
	var opts Options
	if id := c.Query("template"); id != "" {
		if uuid.Validate(id) != nil {
			return opts, fiber.NewError(fiber.StatusBadRequest, "invalid template")
		}
		t, err := h.templates.Get(c.UserContext(), id)
		if errors.Is(err, ErrTemplateNotFound) {
			return opts, fiber.NewError(fiber.StatusBadRequest, "template: no such report template")
		}
		if err != nil {
			return opts, err
		}
		opts.Template = t
	}
	if id := c.Query("engagement_id"); id != "" {
		if uuid.Validate(id) != nil {
			return opts, fiber.NewError(fiber.StatusBadRequest, ErrEngagementMismatch.Error())
		}
		opts.EngagementID = id
	}
	return opts, nil
}

// Register mounts the report routes. /projects/{id}/report is authorized as a
// project read; /portfolio/report is scoped to the actor's visible projects.
func (h *Handler) Register(r fiber.Router) {
	r.Get("/projects/:projectID/report", h.ProjectReport)
	r.Get("/portfolio/report", h.PortfolioReport)
}

// ProjectReport handles GET /projects/{id}/report.
func (h *Handler) ProjectReport(c *fiber.Ctx) error {
	projectID, err := httpx.ID(c, "projectID")
	if err != nil {
		return err
	}
	opts, err := h.options(c)
	if err != nil {
		return err
	}
	rep, err := h.svc.Project(c.UserContext(), projectID, opts)
	if errors.Is(err, ErrProjectNotFound) {
		return fiber.NewError(fiber.StatusNotFound, "project not found")
	}
	if errors.Is(err, ErrEngagementMismatch) {
		return fiber.NewError(fiber.StatusBadRequest, err.Error())
	}
	if err != nil {
		return err
	}
	return send(c, rep, "xila-report-"+rep.Project.Slug)
}

// PortfolioReport handles GET /portfolio/report.
func (h *Handler) PortfolioReport(c *fiber.Ctx) error {
	var pids []string // nil = admin: every project
	if s := authz.VisibleScope(c); !s.AllAccess {
		pids = s.ProjectIDs
	}
	opts, err := h.options(c)
	if err != nil {
		return err
	}
	rep, err := h.svc.Portfolio(c.UserContext(), pids, opts)
	if err != nil {
		return err
	}
	return send(c, rep, "xila-portfolio-report")
}

// send renders the report. The document is inert: the CSP forbids scripts and
// every external fetch (images only as inline data: — the template's logo, and
// an SVG in <img> can't run script), so even a template slip couldn't run code
// or leak data.
func send(c *fiber.Ctx, rep Report, name string) error {
	var buf bytes.Buffer
	if err := Render(&buf, rep); err != nil {
		return err
	}
	c.Set(fiber.HeaderContentType, fiber.MIMETextHTMLCharsetUTF8)
	c.Set(fiber.HeaderContentSecurityPolicy, "default-src 'none'; style-src 'unsafe-inline'; img-src data:")
	c.Set(fiber.HeaderXContentTypeOptions, "nosniff")
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Set(fiber.HeaderContentDisposition,
		fmt.Sprintf(`inline; filename="%s-%s.html"`, safeName(name), rep.GeneratedAt.Format(time.DateOnly)))
	return c.Send(buf.Bytes())
}

// safeName keeps a filename to [A-Za-z0-9._-] (slugs are free text; a quote
// would break out of the Content-Disposition parameter).
func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return r
		}
		return '_'
	}, s)
}
