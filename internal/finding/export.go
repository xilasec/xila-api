package finding

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/customfield"
	"github.com/xilasec/xila-api/internal/export"
)

// exportHeader is the column layout of a findings export.
var exportHeader = []string{
	"ID", "Project", "Branch / version", "Scanner", "Category", "Rule ID",
	"Severity", "Priority", "Status", "Title", "CVE", "CWE", "CVSS",
	"Package", "Version", "Fixed version", "Location", "URL",
	"First seen", "Last seen", "Resolved", "SLA due", "SLA status",
	"Assignee", "EPSS", "KEV", "Exception reason", "Exception expires", "Tags",
}

// ExportAll handles GET /findings/export — the inbox's current filter as CSV or
// XLSX, scoped to the actor's projects exactly like GET /findings.
func (h *Handler) ExportAll(c *fiber.Ctx) error {
	filter, err := portfolioFilter(c)
	if err != nil {
		return err
	}
	return h.export(c, filter)
}

// Export handles GET /projects/{id}/findings/export.
func (h *Handler) Export(c *fiber.Ctx) error {
	filter, err := h.projectFilter(c)
	if err != nil {
		return err
	}
	return h.export(c, filter)
}

func (h *Handler) export(c *fiber.Ctx, filter Filter) error {
	ctx := c.UserContext()
	var defs []customfield.Definition
	if h.customFields != nil {
		var err error
		if defs, err = h.customFields.List(ctx, customfield.EntityFinding); err != nil {
			return err
		}
	}
	header := slices.Clone(exportHeader)
	for _, d := range defs {
		header = append(header, d.Label)
	}
	emails := map[string]string{} // user field values print as emails
	return export.Respond(c, "xila-findings", "Findings", header, func(t export.Table) (bool, error) {
		rows := export.Rows{T: t}
		err := h.repo.Each(ctx, filter, export.MaxRows+1, func(f Labeled) error {
			row := exportRow(f)
			for _, d := range defs {
				v, err := h.customCell(ctx, d, f.Custom[d.Key], emails)
				if err != nil {
					return err
				}
				row = append(row, v)
			}
			return rows.Add(row...)
		})
		return rows.Truncated, err
	})
}

// customCell is one custom field's export cell: numbers stay numbers, a user
// field prints the user's email, anything unset is empty.
func (h *Handler) customCell(ctx context.Context, d customfield.Definition, v any, emails map[string]string) (any, error) {
	switch x := v.(type) {
	case nil:
		return "", nil
	case float64:
		return x, nil
	case string:
		if d.Type != customfield.TypeUser {
			return x, nil
		}
		if e, ok := emails[x]; ok {
			return e, nil
		}
		e, err := h.repo.UserEmail(ctx, x)
		if err != nil {
			return nil, err
		}
		emails[x] = e
		return e, nil
	}
	return fmt.Sprint(v), nil
}

// exportRow lays one finding out in exportHeader's order.
func exportRow(f Labeled) []any {
	var cwe, location, assignee string
	if f.CWE != nil {
		cwe = "CWE-" + strconv.Itoa(*f.CWE)
	}
	location = f.FilePath
	if f.FilePath != "" && f.Line != nil {
		location += ":" + strconv.Itoa(*f.Line)
	}
	if f.AssigneeEmail != nil {
		assignee = *f.AssigneeEmail
	}
	exceptionReason, _, exceptionExpires := f.Exception()
	return []any{
		f.ID, f.ProjectName, f.VersionName, f.Scanner, string(f.Category), f.RuleID,
		string(f.Severity), f.Priority, string(f.Status), f.Title, strings.Join(f.CVE, ", "), cwe, f.CVSS,
		f.PackageName, f.PackageVersion, f.FixedVersion, location, f.URL,
		f.FirstSeenAt, f.LastSeenAt, f.ResolvedAt, f.SLADueAt, string(f.SLAStatus),
		assignee, f.EPSS, f.KEV, exceptionReason, exceptionExpires, strings.Join(f.Tags, ", "),
	}
}

// UserEmail returns a user's email, or id itself when there is no such user
// (a deleted user named in a custom field).
func (r *Repository) UserEmail(ctx context.Context, id string) (string, error) {
	var email string
	err := r.db.QueryRow(ctx, `SELECT COALESCE((SELECT email FROM users WHERE id::text = $1), $1)`, id).Scan(&email)
	if err != nil {
		return "", fmt.Errorf("user email: %w", err)
	}
	return email, nil
}
