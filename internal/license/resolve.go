package license

import (
	"errors"
	"strings"
)

// Resolve turns the license statements an SBOM gives for one component into
// its normalized expression. Each term is one statement — an SPDX expression,
// an id, or a license name — and together they all apply, so they're combined
// with AND (see sbom.Component.LicenseTerms for how the parsers pick them).
//
//   - expr is the normalized SPDX expression, "" when there is no license or a
//     term doesn't parse;
//   - ids are the license ids of every term that parsed (so a component with
//     one unparseable statement is still found by its known licenses);
//   - categories are the distinct ScanCode categories of those ids;
//   - resolved is true only when every term parsed and every id and exception
//     is known (SPDX list, ScanCode, or a LicenseRef-*). Empty, NONE and
//     NOASSERTION are unresolved.
//
// Its signature is sbom.LicenseResolver's.
func Resolve(terms []string) (expr string, ids, categories []string, resolved bool) {
	var parsed []Expr
	failed := false
	for _, t := range terms {
		if strings.TrimSpace(t) == "" {
			continue
		}
		e, err := ParseExpression(t)
		if err != nil {
			// NONE / NOASSERTION say nothing; anything else is a license we
			// couldn't read.
			failed = failed || !errors.Is(err, ErrNoAssertion)
			continue
		}
		parsed = append(parsed, e)
	}
	all := And(parsed...)
	ids = all.IDs()
	categories = []string{}
	seen := map[string]bool{}
	for _, id := range ids {
		if info, ok := Lookup(id); ok && info.Category != "" && !seen[info.Category] {
			seen[info.Category] = true
			categories = append(categories, info.Category)
		}
	}
	if failed {
		return "", ids, categories, false
	}
	return all.String(), ids, categories, all.Resolved()
}
