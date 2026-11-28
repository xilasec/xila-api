package sbom

import (
	"net/url"
	"strings"
)

// maxCopyright bounds a stored copyright notice (some generators paste whole
// NOTICE files into the field).
const maxCopyright = 4000

// cleanCopyright normalizes a copyright statement: SPDX's NOASSERTION / NONE
// mean "not stated", and whitespace runs collapse.
func cleanCopyright(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	switch strings.ToUpper(s) {
	case "NOASSERTION", "NONE":
		return ""
	}
	if r := []rune(s); len(r) > maxCopyright {
		s = string(r[:maxCopyright])
	}
	return s
}

// cleanHomepage keeps a homepage only when it is an absolute http(s) URL: the
// UI renders it as a link, so anything else (javascript:, data:, SPDX's
// NOASSERTION) is dropped rather than shown.
func cleanHomepage(s string) string {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	return s
}

// websiteOf picks a component's homepage from its external references.
func websiteOf(refs []ExternalRef) string {
	for _, r := range refs {
		if strings.EqualFold(r.Type, "website") {
			if u := cleanHomepage(r.URL); u != "" {
				return u
			}
		}
	}
	return ""
}
