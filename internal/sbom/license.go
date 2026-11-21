package sbom

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// LicenseResolver turns a component's license statements (Component.LicenseTerms,
// all of which apply) into its normalized SPDX expression, license ids, their
// ScanCode categories, and whether every one is a known license.
// license.Resolve implements it; it's injected because package license sits on
// top of this one.
type LicenseResolver func(terms []string) (expr string, ids, categories []string, resolved bool)

// WithLicenses makes every upload resolve its components' licenses before they
// are stored (and before the post-ingest evaluator sees them).
func (s *Service) WithLicenses(resolve LicenseResolver) *Service {
	s.licenses = resolve
	return s
}

// resolveLicenses fills the license resolution fields of every component.
func resolveLicenses(resolve LicenseResolver, components []Component) {
	for i := range components {
		applyLicense(resolve, &components[i], components[i].LicenseTerms)
	}
}

func applyLicense(resolve LicenseResolver, c *Component, terms []string) {
	expr, ids, cats, ok := resolve(terms)
	c.LicenseExpression, c.LicenseIDs, c.LicenseCategories, c.LicenseResolved = expr, nonNil(ids), nonNil(cats), &ok
}

// legacyLicenseTerms recovers the license statements of a row stored before
// license resolution existed, from its raw license column: SPDX documents
// stored one expression, CycloneDX ones every license entry joined with ", ".
// The whole string is tried first (a name may contain a comma: "Apache
// License, Version 2.0"); the split wins when it resolves and the whole
// doesn't, or when neither resolves but the split recognizes more licenses
// (so the known ones stay filterable).
func legacyLicenseTerms(resolve LicenseResolver, raw string) []string {
	whole := []string{raw}
	if !strings.Contains(raw, ", ") {
		return whole
	}
	_, wholeIDs, _, ok := resolve(whole)
	if ok {
		return whole
	}
	split := strings.Split(raw, ", ")
	if _, splitIDs, _, ok := resolve(split); ok || len(splitIDs) > len(wholeIDs) {
		return split
	}
	return whole
}

// backfillBatch is how many distinct raw license strings one backfill round
// resolves.
const backfillBatch = 500

// BackfillLicenses resolves the licenses of every component stored before
// license resolution existed (license_resolved IS NULL). It works per distinct
// raw license string — an inventory repeats a handful of licenses thousands of
// times — and only ever touches unresolved rows, so it is idempotent and a
// re-run with nothing left to do is one index probe. Returns the rows updated.
func (r *Repository) BackfillLicenses(ctx context.Context, resolve LicenseResolver) (int, error) {
	total := 0
	for {
		rows, err := r.db.Query(ctx, `
			SELECT DISTINCT license FROM sbom_components
			WHERE license_resolved IS NULL LIMIT $1`, backfillBatch)
		if err != nil {
			return total, fmt.Errorf("list unresolved licenses: %w", err)
		}
		var raws []string
		for rows.Next() {
			var raw string
			if err := rows.Scan(&raw); err != nil {
				rows.Close()
				return total, fmt.Errorf("scan license: %w", err)
			}
			raws = append(raws, raw)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return total, fmt.Errorf("list unresolved licenses: %w", err)
		}
		if len(raws) == 0 {
			return total, nil
		}
		for _, raw := range raws {
			var c Component
			applyLicense(resolve, &c, legacyLicenseTerms(resolve, raw))
			tag, err := r.db.Exec(ctx, `
				UPDATE sbom_components
				SET license_expression = $2, license_ids = $3, license_categories = $4, license_resolved = $5
				WHERE license = $1 AND license_resolved IS NULL`,
				raw, c.LicenseExpression, c.LicenseIDs, c.LicenseCategories, *c.LicenseResolved)
			if err != nil {
				return total, fmt.Errorf("backfill license %q: %w", raw, err)
			}
			total += int(tag.RowsAffected())
		}
	}
}

// LicenseOverrideMatcher resolves one project's curated concluded license for
// a package, if one applies. license.Matcher.MatchLicense implements it;
// injected the same way LicenseResolver is, so this package never imports
// internal/license (which would import this one back, for version compares).
type LicenseOverrideMatcher interface {
	MatchLicense(projectID, purl, version string) (expr string, ids, categories []string, resolved bool, overrideID string, ok bool)
}

// applyLicenseOverrides replaces a matching component's resolved license with
// its project's curated concluded value, keeping the SBOM's own resolution in
// License Declared*. A component with no match is untouched (Declared* stay
// empty: the two pairs are then identical, nothing to show differently).
func applyLicenseOverrides(m LicenseOverrideMatcher, projectID string, components []Component) {
	for i := range components {
		c := &components[i]
		expr, ids, cats, resolved, overrideID, ok := m.MatchLicense(projectID, c.Purl, c.Version)
		if !ok {
			continue
		}
		c.LicenseDeclaredExpression = c.LicenseExpression
		c.LicenseDeclaredIDs = c.LicenseIDs
		c.LicenseDeclaredCategories = c.LicenseCategories
		c.LicenseDeclaredResolved = c.LicenseResolved
		r := resolved
		c.LicenseExpression, c.LicenseIDs, c.LicenseCategories, c.LicenseResolved = expr, nonNil(ids), nonNil(cats), &r
		id := overrideID
		c.LicenseOverrideID = &id
	}
}

// ReapplyLicenseOverrides recomputes license fields for every component of a
// project's current snapshots (every version, every artifact) against
// matcher, the project's current overrides. Call this when an override is
// created, updated or deleted, then policy.Service's project-wide
// re-evaluation, so component-license policies see the new verdict.
//
// The declared (SBOM-reported) value is re-derived from the component's
// stored raw license string with legacyLicenseTerms, the same recovery the
// startup backfill uses, so it never drifts from what the SBOM actually
// said regardless of how many times an override has since changed. Writes
// only components whose computed fields actually change.
func (r *Repository) ReapplyLicenseOverrides(ctx context.Context, projectID string, resolve LicenseResolver, matcher LicenseOverrideMatcher) (int, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id FROM (
			SELECT DISTINCT ON (version_id, artifact) id FROM sboms
			WHERE project_id = $1
			ORDER BY version_id, artifact, created_at DESC, id DESC
		) latest`, projectID)
	if err != nil {
		return 0, fmt.Errorf("current snapshots for project: %w", err)
	}
	sbomIDs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, fmt.Errorf("scan current snapshots: %w", err)
	}
	if len(sbomIDs) == 0 {
		return 0, nil
	}

	type row struct {
		id, purl, version, license string
	}
	crows, err := r.db.Query(ctx, `
		SELECT id, purl, version, license FROM sbom_components WHERE sbom_id = ANY($1)`, sbomIDs)
	if err != nil {
		return 0, fmt.Errorf("components for project: %w", err)
	}
	var components []row
	for crows.Next() {
		var c row
		if err := crows.Scan(&c.id, &c.purl, &c.version, &c.license); err != nil {
			crows.Close()
			return 0, fmt.Errorf("scan component: %w", err)
		}
		components = append(components, c)
	}
	crows.Close()
	if err := crows.Err(); err != nil {
		return 0, err
	}

	batch := &pgx.Batch{}
	n := 0
	for _, c := range components {
		declExpr, declIDs, declCats, declResolved := resolve(legacyLicenseTerms(resolve, c.license))
		expr, ids, cats, resolved, overrideID := declExpr, declIDs, declCats, declResolved, (*string)(nil)
		if mExpr, mIDs, mCats, mResolved, mID, ok := matcher.MatchLicense(projectID, c.purl, c.version); ok {
			expr, ids, cats, resolved, overrideID = mExpr, mIDs, mCats, mResolved, &mID
		}
		batch.Queue(`
			UPDATE sbom_components SET
				license_expression = $2, license_ids = $3, license_categories = $4, license_resolved = $5,
				license_declared_expression = $6, license_declared_ids = $7, license_declared_categories = $8, license_declared_resolved = $9,
				license_override_id = $10
			WHERE id = $1 AND (
				license_expression IS DISTINCT FROM $2 OR license_resolved IS DISTINCT FROM $5 OR
				license_declared_expression IS DISTINCT FROM $6 OR license_override_id IS DISTINCT FROM $10
			)`,
			c.id, expr, nonNil(ids), nonNil(cats), resolved,
			declExpr, nonNil(declIDs), nonNil(declCats), declResolved, overrideID)
		n++
	}
	br := r.db.SendBatch(ctx, batch)
	defer br.Close()
	changed := 0
	for range components {
		tag, err := br.Exec()
		if err != nil {
			return changed, fmt.Errorf("reapply license override: %w", err)
		}
		changed += int(tag.RowsAffected())
	}
	return changed, nil
}
