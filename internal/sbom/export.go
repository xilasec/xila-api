package sbom

import (
	"strings"

	"github.com/gofiber/fiber/v2"

	"github.com/xilasec/xila-api/internal/export"
)

// componentExportHeader is the column layout of a components export.
var componentExportHeader = []string{
	"Project", "Artifact", "SBOM version", "SBOM uploaded",
	"Type", "Kind", "Group", "Name", "Version", "Purl", "CPE", "License", "File path",
	"Direct", "Depth", "Scope",
	"License expression", "License categories", "License resolved",
	"Vulnerabilities", "Max severity", "KEV", "Vulnerability IDs",
	"Latest version", "Outdated", "Versions behind", "Version published", "Integrity",
	"Supplier", "Model task", "Datasets", "Copyright", "Homepage",
	"Component ID", "SBOM ID",
}

// ExportComponents handles GET /components/export — the cross-project search
// as CSV or XLSX, scoped to the actor's projects like GET /components.
func (h *Handler) ExportComponents(c *fiber.Ctx) error {
	return h.exportComponents(c, searchComponentFilter)
}

// ExportProjectComponents handles GET /projects/{id}/components/export.
func (h *Handler) ExportProjectComponents(c *fiber.Ctx) error {
	return h.exportComponents(c, h.projectComponentFilter)
}

// ExportSbomComponents handles GET /sboms/{id}/components/export.
func (h *Handler) ExportSbomComponents(c *fiber.Ctx) error {
	return h.exportComponents(c, sbomComponentFilter)
}

func (h *Handler) exportComponents(c *fiber.Ctx, filterOf func(*fiber.Ctx) (ComponentFilter, error)) error {
	filter, err := filterOf(c)
	if err != nil {
		return err
	}
	return export.Respond(c, "xila-components", "Components", componentExportHeader, func(t export.Table) (bool, error) {
		rows := export.Rows{T: t}
		err := h.repo.EachComponent(c.UserContext(), filter, export.MaxRows+1, func(hit ComponentHit) error {
			return rows.Add(componentExportRow(hit)...)
		})
		return rows.Truncated, err
	})
}

// componentExportRow lays one component out in componentExportHeader's order.
func componentExportRow(h ComponentHit) []any {
	var maxSev string
	if h.MaxSeverity != nil {
		maxSev = string(*h.MaxSeverity)
	}
	var task string
	if h.ML != nil {
		task = h.ML.Task
	}
	return []any{
		h.ProjectName, h.Artifact, h.SbomVersion, h.SbomCreatedAt,
		h.Type, h.Kind, h.Group, h.Name, h.Version, h.Purl, h.Cpe, h.License, h.FilePath,
		h.Direct, h.Depth, string(h.Scope),
		h.LicenseExpression, strings.Join(h.LicenseCategories, ", "), h.LicenseResolved,
		h.VulnCount, maxSev, h.KEV, strings.Join(h.Vulns, ", "),
		h.LatestVersion, h.Outdated, h.VersionsBehind, h.VersionPublishedAt, h.Integrity,
		strings.Join(h.ML.Organizations(), ", "), task, strings.Join(h.ML.DatasetNames(), ", "), h.Copyright, h.Homepage,
		h.ID, h.SbomID,
	}
}
