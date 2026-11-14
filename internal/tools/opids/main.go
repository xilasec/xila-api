// Command opids gives every operation in internal/apidoc/openapi.yaml an
// operationId derived from its method and path, so generated clients get
// stable, readable method names (listProjectFindings, getFinding,
// createProjectScan, approveRiskAcceptance, …). Existing ids are kept, so a
// hand-picked name is never overwritten. It edits the file in place, inserting
// one line under each operation that lacks an id:
//
//	go run ./internal/tools/opids            # add missing ids
//	go run ./internal/tools/opids -check     # exit 1 if any are missing
//
// TestEveryOperationHasUniqueID (internal/apidoc) enforces the result.
package main

import (
	"flag"
	"fmt"
	"os"
	"regexp"
	"strings"
	"unicode"
)

const specPath = "internal/apidoc/openapi.yaml"

func main() {
	check := flag.Bool("check", false, "report missing ids instead of writing them")
	flag.Parse()
	src, err := os.ReadFile(specPath)
	if err != nil {
		fail(err)
	}
	out, added, err := addIDs(string(src))
	if err != nil {
		fail(err)
	}
	if *check {
		if added > 0 {
			fail(fmt.Errorf("%d operation(s) lack an operationId: run `go run ./internal/tools/opids`", added))
		}
		return
	}
	if added == 0 {
		return
	}
	if err := os.WriteFile(specPath, []byte(out), 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("added %d operationId(s)\n", added)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "opids:", err)
	os.Exit(1)
}

var (
	pathLine   = regexp.MustCompile(`^  (/[^:]*):\s*$`)
	methodLine = regexp.MustCompile(`^    (get|post|put|patch|delete):\s*$`)
	idLine     = regexp.MustCompile(`^      operationId:\s*(\S+)`)
)

// addIDs walks the spec line by line: `  /path:` opens a path item and
// `    get:` an operation. The spec is hand-formatted with fixed indentation
// (TestSpecIsWellFormed parses it), which is what makes the line scan safe.
func addIDs(src string) (string, int, error) {
	lines := strings.Split(src, "\n")
	inPaths := false
	path := ""
	seen := map[string]string{}
	type op struct {
		at     int // index of the method line
		method string
		path   string
		hasID  bool
	}
	var ops []op
	for i, l := range lines {
		switch {
		case l == "paths:":
			inPaths = true
			continue
		case inPaths && len(l) > 0 && l[0] != ' ' && l[0] != '#':
			inPaths = false
		}
		if !inPaths {
			continue
		}
		if m := pathLine.FindStringSubmatch(l); m != nil {
			path = m[1]
			continue
		}
		if m := methodLine.FindStringSubmatch(l); m != nil {
			ops = append(ops, op{at: i, method: m[1], path: path})
			continue
		}
		if m := idLine.FindStringSubmatch(l); m != nil && len(ops) > 0 {
			ops[len(ops)-1].hasID = true
			if prev, dup := seen[m[1]]; dup {
				return "", 0, fmt.Errorf("operationId %s used by %s and %s %s", m[1], prev, ops[len(ops)-1].method, ops[len(ops)-1].path)
			}
			seen[m[1]] = ops[len(ops)-1].method + " " + ops[len(ops)-1].path
		}
	}
	added := 0
	// Insert from the bottom so earlier indexes stay valid.
	for k := len(ops) - 1; k >= 0; k-- {
		o := ops[k]
		if o.hasID {
			continue
		}
		id := deriveID(o.method, o.path)
		if prev, dup := seen[id]; dup {
			return "", 0, fmt.Errorf("derived operationId %s for %s %s collides with %s; give one of them an explicit operationId", id, o.method, o.path, prev)
		}
		seen[id] = o.method + " " + o.path
		lines = append(lines[:o.at+1], append([]string{"      operationId: " + id}, lines[o.at+1:]...)...)
		added++
	}
	return strings.Join(lines, "\n"), added, nil
}

// actions are trailing path words that name a verb, not a resource:
// POST /risk-acceptances/{id}/approve → approveRiskAcceptance.
var actions = map[string]bool{
	"accept": true, "apply": true, "approve": true, "archive": true, "assign": true,
	"attest": true, "close": true, "decide": true, "disable": true, "dismiss": true,
	"enable": true, "evaluate": true, "exchange": true, "export": true, "import": true,
	"merge": true, "preview": true, "publish": true, "refresh": true, "reject": true,
	"reopen": true, "reprioritize": true, "reset": true, "restore": true, "resume": true,
	"retry": true, "revise": true, "revoke": true, "rotate": true, "setup": true,
	"submit": true, "suspend": true, "sync": true, "test": true, "transfer": true,
	"validate": true,
}

// uncountable path words that end in "s" but are not plural collections.
var notPlural = map[string]bool{
	"access": true, "alias": true, "analysis": true, "children": true, "mfa": true,
	"metrics": true, "news": true, "series": true, "settings": true, "status": true,
	"stats": true, "trends": true, "vex": true, "versions-diff": true,
}

var irregular = map[string]string{
	"policies": "policy", "advisories": "advisory", "vulnerabilities": "vulnerability",
	"dependencies": "dependency", "statuses": "status", "aliases": "alias",
	"summaries": "summary", "entries": "entry", "proxies": "proxy", "children": "child",
}

func singular(w string) string {
	if s, ok := irregular[w]; ok {
		return s
	}
	if notPlural[w] {
		return w
	}
	switch {
	case strings.HasSuffix(w, "ies"):
		return w[:len(w)-3] + "y"
	case strings.HasSuffix(w, "sses"), strings.HasSuffix(w, "xes"):
		return w[:len(w)-2]
	case strings.HasSuffix(w, "s") && !strings.HasSuffix(w, "ss"):
		return w[:len(w)-1]
	}
	return w
}

func plural(w string) bool { return !notPlural[w] && singular(w) != w }

func pascal(words ...string) string {
	var b strings.Builder
	for _, w := range words {
		for _, part := range strings.FieldsFunc(w, func(r rune) bool { return r == '-' || r == '_' || r == '.' }) {
			r := []rune(part)
			r[0] = unicode.ToUpper(r[0])
			b.WriteString(string(r))
		}
	}
	return b.String()
}

// deriveID names an operation from its method and path:
//
//	GET    /projects                      → listProjects
//	GET    /projects/{projectID}          → getProject
//	GET    /projects/{projectID}/findings → listProjectFindings
//	POST   /projects/{projectID}/scans    → createProjectScan
//	PATCH  /findings/{findingID}          → updateFinding
//	POST   /findings/{findingID}/restore  → restoreFinding
//	GET    /auth/oidc/{slug}/login        → getAuthOidcLoginByProvider
func deriveID(method, path string) string {
	segs := strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
	var nouns []string
	bySlug := false
	for i, s := range segs {
		if strings.HasPrefix(s, "{") {
			if s == "{slug}" {
				bySlug = true
			}
			continue
		}
		// A collection followed by its id names one item: findings/{id} → Finding.
		if i+1 < len(segs) && strings.HasPrefix(segs[i+1], "{") && segs[i+1] != "{slug}" {
			s = singular(s)
		}
		nouns = append(nouns, s)
	}
	last := segs[len(segs)-1]
	endsInID := strings.HasPrefix(last, "{") && last != "{slug}"
	// A trailing parameter on a non-collection word names its own item:
	// compliance/{framework} → ProjectComplianceFramework, remediation/{actionID}
	// → RemediationAction (the collection form takes the plain noun).
	if endsInID && len(segs) >= 2 && !plural(segs[len(segs)-2]) {
		p := strings.Trim(last, "{}")
		p = strings.TrimSuffix(strings.TrimSuffix(p, "ID"), "Id")
		if p != "" {
			nouns = append(nouns, p)
		}
	}
	suffix := ""
	if bySlug {
		suffix = "ByProvider"
	}
	if len(nouns) == 0 {
		return method + "Root"
	}
	word := nouns[len(nouns)-1]
	head := nouns[:len(nouns)-1]
	// Trailing action word: the verb leads, the owning resource follows.
	if actions[word] && !endsInID && len(head) > 0 {
		return word + pascal(head...) + suffix
	}
	// Toggles named by a noun-verb (watch): the method says which way.
	if word == "watch" {
		verb := map[string]string{"get": "get", "put": "watch", "delete": "unwatch"}[method]
		if verb == "get" {
			return "get" + pascal(head...) + "Watch" + suffix
		}
		return verb + pascal(head...) + suffix
	}
	base := pascal(nouns...)
	switch method {
	case "get":
		if !endsInID && plural(word) {
			return "list" + base + suffix
		}
		return "get" + base + suffix
	case "post":
		if !endsInID && plural(word) {
			return "create" + pascal(append(head, singular(word))...) + suffix
		}
		return "post" + base + suffix
	case "put":
		return "put" + base + suffix
	case "patch":
		return "update" + base + suffix
	case "delete":
		return "delete" + base + suffix
	}
	return method + base + suffix
}
