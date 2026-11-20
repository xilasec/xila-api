package finding

import (
	"regexp"
	"strings"
)

// MentionCandidate is one person who could be @mentioned: their id and email.
type MentionCandidate struct {
	UserID string
	Email  string
}

// mentionPattern matches "@token": either a bare handle (the local part of
// someone's email, e.g. "@alice") or a full "@local@domain.tld" email, so a
// comment can mention either way.
var mentionPattern = regexp.MustCompile(`@([A-Za-z0-9][A-Za-z0-9._%+-]*(?:@[A-Za-z0-9.-]+\.[A-Za-z]{2,})?)`)

// ExtractMentions returns the distinct user ids of candidates mentioned by
// @email or @name (the local part of their email, case-insensitive) in body,
// in order of first mention. An unknown handle, or a bare @name shared by more
// than one candidate's local part, is ignored silently — no user enumeration;
// disambiguate with the full @local@domain form instead.
func ExtractMentions(body string, candidates []MentionCandidate) []string {
	byEmail := make(map[string]string, len(candidates))
	byLocal := make(map[string]string, len(candidates))
	ambiguous := map[string]bool{}
	for _, c := range candidates {
		email := strings.ToLower(c.Email)
		if email == "" {
			continue
		}
		byEmail[email] = c.UserID
		local, _, ok := strings.Cut(email, "@")
		if !ok || local == "" {
			continue
		}
		if _, dup := byLocal[local]; dup {
			ambiguous[local] = true
			continue
		}
		byLocal[local] = c.UserID
	}
	seen := map[string]bool{}
	var out []string
	for _, m := range mentionPattern.FindAllStringSubmatch(body, -1) {
		token := strings.ToLower(m[1])
		id, ok := byEmail[token]
		if !ok && !ambiguous[token] {
			id, ok = byLocal[token]
		}
		if !ok || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}
