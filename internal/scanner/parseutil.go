package scanner

import (
	"regexp"
	"strings"
)

var cveTextRe = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)

// cvesInText extracts the CVE ids mentioned in free text (advisory names,
// reference links, scanner messages), uppercased and deduplicated in order of
// first appearance. Several tools only name the CVE inside prose — an RHSA
// title, a Nikto message, a Burp issue detail — and the CVE is what dedup and
// EPSS/KEV enrichment key on, so it has to be lifted out.
func cvesInText(texts ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range texts {
		for _, m := range cveTextRe.FindAllString(t, -1) {
			id := strings.ToUpper(m)
			if !seen[id] {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

// mergeSameLocation folds findings that would share an identity (the ingest
// fingerprint is scanner + category + rule + location + package + line) into
// one, keeping the first and appending the others' descriptions, the highest
// severity and the union of CVEs. Tools with generic check ids (Nikto's
// "uncommon header" check, Wapiti's per-category results) report several
// distinct observations at one URL; without the merge all but the last would
// be silently overwritten on upsert.
func mergeSameLocation(fs []ParsedFinding) []ParsedFinding {
	type key struct {
		cat             string
		rule, path, pkg string
		line            int
	}
	idx := make(map[key]int, len(fs))
	out := fs[:0]
	for _, f := range fs {
		k := key{cat: string(f.Category), rule: f.RuleID, path: f.FilePath, pkg: f.Package}
		if f.Line != nil {
			k.line = *f.Line
		}
		i, dup := idx[k]
		if !dup {
			idx[k] = len(out)
			out = append(out, f)
			continue
		}
		m := &out[i]
		if f.Description != "" && !strings.Contains(m.Description, f.Description) {
			m.Description = strings.TrimSpace(m.Description + "\n" + f.Description)
		}
		if f.Severity.Weight() > m.Severity.Weight() {
			m.Severity = f.Severity
		}
		m.CVE = cvesInText(append(m.CVE, f.CVE...)...)
		if m.Metadata == nil {
			m.Metadata = map[string]any{}
		}
		n, _ := m.Metadata["occurrences"].(int)
		m.Metadata["occurrences"] = max(n, 1) + 1
	}
	return out
}
