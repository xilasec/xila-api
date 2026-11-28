package mcp

import (
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// emailPattern finds email addresses in any string, free text included.
var emailPattern = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

// personKeys are the fields whose value names a person (an email or a
// display name), not only an opaque id.
var personKeys = map[string]bool{
	"author": true, "actor": true, "actor_name": true, "requester": true, "approver": true,
	"decider": true, "username": true, "full_name": true, "display_name": true, "exception_by": true,
}

// pseudonymizer replaces personal data in one MCP result (M13 13.16). Each
// distinct person becomes "person-N", the same N everywhere in that result,
// so the model can still tell "the same reviewer" apart without learning who
// they are. Opaque ids (uuids) are kept: they identify no one by themselves.
type pseudonymizer struct{ seen map[string]string }

func newPseudonymizer() *pseudonymizer { return &pseudonymizer{seen: map[string]string{}} }

// alias is the pseudonym of one person, keyed case-insensitively.
func (p *pseudonymizer) alias(person string) string {
	key := strings.ToLower(strings.TrimSpace(person))
	if a, ok := p.seen[key]; ok {
		return a
	}
	a := "person-" + strconv.Itoa(len(p.seen)+1)
	p.seen[key] = a
	return a
}

// text replaces every email address in s.
func (p *pseudonymizer) text(s string) string {
	return emailPattern.ReplaceAllStringFunc(s, p.alias)
}

// systemActor reports whether a person field holds an automated actor
// ("system", "triage-rule:<name>", "vuln-policy:<name>", "mcp:<tool>"...),
// which names no one.
func systemActor(s string) bool {
	return s == "" || s == "system" || (strings.Contains(s, ":") && !strings.Contains(s, "@"))
}

// value pseudonymizes v, a decoded JSON value, in place where it can.
func (p *pseudonymizer) value(v any) any {
	switch x := v.(type) {
	case map[string]any:
		// Sorted, so a result numbers its people the same way every time.
		for _, k := range slices.Sorted(maps.Keys(x)) {
			child := x[k]
			if s, ok := child.(string); ok && (personKeys[k] || strings.HasSuffix(k, "email")) && !systemActor(s) {
				x[k] = p.alias(s)
				continue
			}
			x[k] = p.value(child)
		}
		return x
	case []any:
		for i, child := range x {
			x[i] = p.value(child)
		}
		return x
	case string:
		return p.text(x)
	}
	return v
}
