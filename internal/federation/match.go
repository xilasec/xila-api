package federation

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// identityClaims name the workload: a binding must pin at least one of them to
// a pattern that doesn't begin with a wildcard. A public issuer (GitHub
// Actions, GitLab.com) signs tokens for every repository on the platform, so a
// binding on `ref` or `environment` alone would admit anyone's pipeline.
var identityClaims = []string{
	"sub",
	"repository", "repository_id", "repository_owner", "repository_owner_id", // GitHub Actions
	"project_path", "project_id", "namespace_path", "namespace_id", // GitLab CI
}

// ErrInvalidConditions describes a binding's conditions that can't be stored.
var ErrInvalidConditions = errors.New("invalid conditions")

// validateConditions checks a binding's claim conditions: at least one, every
// claim name and pattern non-empty, and an identity claim pinned (see
// identityClaims).
func validateConditions(conds map[string]string) error {
	if len(conds) == 0 {
		return fmt.Errorf("%w: at least one claim condition is required", ErrInvalidConditions)
	}
	pinned := false
	for claim, pattern := range conds {
		if strings.TrimSpace(claim) == "" || strings.TrimSpace(pattern) == "" {
			return fmt.Errorf("%w: claim names and patterns must be non-empty", ErrInvalidConditions)
		}
		for _, id := range identityClaims {
			if claim == id && !strings.ContainsAny(pattern[:1], "*?") {
				pinned = true
			}
		}
	}
	if !pinned {
		return fmt.Errorf("%w: pin the workload with a condition on one of %s whose pattern doesn't start with a wildcard",
			ErrInvalidConditions, strings.Join(identityClaims, ", "))
	}
	return nil
}

// matches reports whether every condition holds for the token's claims. A
// condition is an exact value, or a glob: `*` matches within one `/`-separated
// segment, `**` across segments, `?` one character other than `/`. A missing
// claim, or one that isn't a string, number or boolean, never matches.
func matches(conds map[string]string, claims map[string]any) bool {
	for claim, pattern := range conds {
		v, ok := claimString(claims[claim])
		if !ok || !globMatch(pattern, v) {
			return false
		}
	}
	return true
}

func claimString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case bool:
		return strconv.FormatBool(x), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	}
	return "", false
}

func globMatch(pattern, value string) bool {
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == value
	}
	return globRegexp(pattern).MatchString(value)
}

func globRegexp(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString(`^`)
	for i := 0; i < len(pattern); i++ {
		switch {
		case strings.HasPrefix(pattern[i:], "**"):
			b.WriteString(`.*`)
			i++
		case pattern[i] == '*':
			b.WriteString(`[^/]*`)
		case pattern[i] == '?':
			b.WriteString(`[^/]`)
		default:
			// Byte-wise is safe: only ASCII bytes are special, and QuoteMeta of
			// a lone UTF-8 continuation byte is that byte.
			j := i
			for j < len(pattern) && pattern[j] != '*' && pattern[j] != '?' {
				j++
			}
			b.WriteString(regexp.QuoteMeta(pattern[i:j]))
			i = j - 1
		}
	}
	b.WriteString(`$`)
	return regexp.MustCompile(b.String())
}
