package component

import (
	"regexp"
	"strings"
)

// Matcher is a compiled set of Patterns, fast to test against every
// component an SBOM upload carries.
type Matcher struct {
	rules []compiledPattern
}

type compiledPattern struct {
	ecosystem   string // "" = any
	group, name *regexp.Regexp
}

// Compile builds a Matcher from patterns. Patterns are validated on save, so
// a compile failure here would be a stored row with a bad regex.
func Compile(patterns []Pattern) (*Matcher, error) {
	m := &Matcher{rules: make([]compiledPattern, 0, len(patterns))}
	for _, p := range patterns {
		group, err := compileOne(p.PatternType, p.GroupPattern)
		if err != nil {
			return nil, err
		}
		name, err := compileOne(p.PatternType, p.NamePattern)
		if err != nil {
			return nil, err
		}
		m.rules = append(m.rules, compiledPattern{ecosystem: p.Ecosystem, group: group, name: name})
	}
	return m, nil
}

// compileOne compiles one glob or regex pattern; "" matches everything (nil).
func compileOne(t PatternType, pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, nil
	}
	if t == PatternRegex {
		return regexp.Compile(`(?i)` + pattern)
	}
	q := regexp.QuoteMeta(pattern)
	q = strings.ReplaceAll(q, `\*`, `.*`)
	q = strings.ReplaceAll(q, `\?`, `.`)
	return regexp.Compile(`(?i)^` + q + `$`)
}

// Match reports whether any rule selects a component with this ecosystem
// (purl type), group (namespace) and name. A nil Matcher (none configured)
// never matches.
func (m *Matcher) Match(ecosystem, group, name string) bool {
	if m == nil {
		return false
	}
	eco := strings.ToLower(ecosystem)
	for _, r := range m.rules {
		if r.ecosystem != "" && r.ecosystem != eco {
			continue
		}
		if r.group != nil && !r.group.MatchString(group) {
			continue
		}
		if r.name != nil && !r.name.MatchString(name) {
			continue
		}
		return true
	}
	return false
}
