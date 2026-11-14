package sbom

import (
	"context"
	"fmt"
	"strings"
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
