package license

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ErrInvalidExpression is returned (wrapped) for anything that isn't an SPDX
// license expression.
var ErrInvalidExpression = errors.New("invalid license expression")

// ErrNoAssertion is returned for SPDX's NONE / NOASSERTION: the document says
// no license is known, which is not a license.
var ErrNoAssertion = errors.New("no license asserted")

// Expr is a parsed SPDX license expression (SPDX spec Annex D). The zero value
// is the empty expression.
type Expr struct {
	root *node
}

// node is one license (op == "") or an n-ary AND / OR of its args.
type node struct {
	op   string
	args []*node

	id        string // canonical case when known, verbatim otherwise
	plus      bool   // "+": this version or any later one
	exception string // WITH exception, canonical case when known
	known     bool   // id is in the SPDX list / ScanCode, or a LicenseRef
	excKnown  bool   // exception is in the SPDX list, or an AdditionRef
}

const (
	opAnd = "AND"
	opOr  = "OR"
	// maxDepth bounds parenthesis nesting so hostile input can't blow the stack.
	maxDepth = 64
)

var (
	idstring   = `[A-Za-z0-9.\-]+`
	licenseRef = regexp.MustCompile(`^(?:DocumentRef-` + idstring + `:)?LicenseRef-` + idstring + `$`)
	additionRf = regexp.MustCompile(`^(?:DocumentRef-` + idstring + `:)?AdditionRef-` + idstring + `$`)
	plainID    = regexp.MustCompile(`^` + idstring + `$`)
)

// aliases maps spellings SBOM tools commonly emit instead of an SPDX id (keyed
// by aliasKey) to the id they unambiguously mean. Deliberately explicit and
// small: a guessed license is worse than an unresolved one. The full SPDX name
// of every license (e.g. "Apache License 2.0", "MIT License") is accepted too,
// from the catalog. Spellings that don't say "only" or "or later" map to the
// deprecated bare GPL-family ids, which carry exactly that ambiguity.
var aliases = map[string]string{
	"apache 2":                                 "Apache-2.0",
	"apache 2.0":                               "Apache-2.0",
	"apache-2":                                 "Apache-2.0",
	"apache license, version 2.0":              "Apache-2.0",
	"apache license version 2.0":               "Apache-2.0",
	"apache software license, version 2.0":     "Apache-2.0",
	"the apache software license, version 2.0": "Apache-2.0",
	"the apache license, version 2.0":          "Apache-2.0",
	"apache software license 2.0":              "Apache-2.0",
	"asl 2.0":                                  "Apache-2.0",
	"mit":                                      "MIT",
	"the mit license":                          "MIT",
	"mit license (mit)":                        "MIT",
	"expat":                                    "MIT",
	"bsd":                                      "BSD-3-Clause",
	"bsd license":                              "BSD-3-Clause",
	"new bsd license":                          "BSD-3-Clause",
	"modified bsd license":                     "BSD-3-Clause",
	"the bsd license":                          "BSD-3-Clause",
	"bsd 3-clause":                             "BSD-3-Clause",
	"bsd-3":                                    "BSD-3-Clause",
	"3-clause bsd license":                     "BSD-3-Clause",
	"bsd 3-clause license":                     "BSD-3-Clause",
	"bsd 2-clause":                             "BSD-2-Clause",
	"bsd-2":                                    "BSD-2-Clause",
	"2-clause bsd license":                     "BSD-2-Clause",
	"bsd 2-clause license":                     "BSD-2-Clause",
	"simplified bsd license":                   "BSD-2-Clause",
	"isc license":                              "ISC",
	"isc license (iscl)":                       "ISC",
	"mpl 2.0":                                  "MPL-2.0",
	"mpl-2":                                    "MPL-2.0",
	"mozilla public license 2.0 (mpl 2.0)":     "MPL-2.0",
	"eclipse public license - v 1.0":           "EPL-1.0",
	"eclipse public license - v 2.0":           "EPL-2.0",
	"epl 2.0":                                  "EPL-2.0",
	"gplv2":                                    "GPL-2.0",
	"gpl v2":                                   "GPL-2.0",
	"gnu general public license v2 (gplv2)":    "GPL-2.0",
	"gplv3":                                    "GPL-3.0",
	"gpl v3":                                   "GPL-3.0",
	"gnu general public license v3 (gplv3)":    "GPL-3.0",
	"lgplv2.1":                                 "LGPL-2.1",
	"lgplv3":                                   "LGPL-3.0",
	"gnu lesser general public license v3 (lgplv3)": "LGPL-3.0",
	"agplv3":                             "AGPL-3.0",
	"cc0":                                "CC0-1.0",
	"public domain (cc0)":                "CC0-1.0",
	"python software foundation license": "PSF-2.0",
	"the unlicense (unlicense)":          "Unlicense",
	"alv2":                               "Apache-2.0",
	"eclipse public license v2.0":        "EPL-2.0",
	"common development and distribution license (cddl) v1.0": "CDDL-1.0",
	// The Eclipse Distribution License 1.0 is the BSD 3-Clause license
	// (https://www.eclipse.org/org/documents/edl-v10.php); SPDX lists no
	// separate id for it.
	"eclipse distribution license - v 1.0": "BSD-3-Clause",
	"edl 1.0":                              "BSD-3-Clause",
}

// aliasKey normalizes a free-text license name for the alias / name lookup:
// lower case, whitespace collapsed. Nothing fuzzier.
func aliasKey(s string) string {
	return strings.Join(strings.Fields(strings.ToLower(s)), " ")
}

// ParseExpression parses an SPDX license expression: license ids (any case,
// normalized to canonical case; deprecated ids accepted), the "+" suffix,
// LicenseRef-* / DocumentRef-*:LicenseRef-*, WITH exceptions, AND / OR and
// parentheses with SPDX precedence (+ > WITH > AND > OR). Operators are matched
// case-insensitively. A string that is, as a whole, an SPDX license's full name
// or one of a few common tool spellings ("Apache 2.0", "MIT License") resolves
// to that license.
//
// Ids that are well-formed but not in the catalog still parse (verbatim) and
// are reported by Unknown(); a syntax error returns ErrInvalidExpression.
func ParseExpression(s string) (Expr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Expr{}, fmt.Errorf("%w: empty", ErrInvalidExpression)
	}
	if u := strings.ToUpper(s); u == "NONE" || u == "NOASSERTION" {
		return Expr{}, ErrNoAssertion
	}
	if id, ok := aliasID(s); ok {
		return Expr{root: leaf(id)}, nil
	}
	p := &parser{toks: tokenize(s)}
	root, err := p.or(0)
	if err != nil {
		return Expr{}, err
	}
	if p.pos < len(p.toks) {
		return Expr{}, fmt.Errorf("%w: unexpected %q", ErrInvalidExpression, p.toks[p.pos])
	}
	return Expr{root: root}, nil
}

// aliasID resolves a whole string naming one license by alias or full name.
func aliasID(s string) (string, bool) {
	key := aliasKey(s)
	if id, ok := aliases[key]; ok {
		return id, true
	}
	if id, ok := loadCatalog().byName[key]; ok {
		return id, true
	}
	return "", false
}

// tokenize splits on whitespace and parentheses.
func tokenize(s string) []string {
	var toks []string
	start := -1
	flush := func(i int) {
		if start >= 0 {
			toks = append(toks, s[start:i])
			start = -1
		}
	}
	for i, r := range s {
		switch {
		case r == '(' || r == ')':
			flush(i)
			toks = append(toks, string(r))
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			flush(i)
		default:
			if start < 0 {
				start = i
			}
		}
	}
	flush(len(s))
	return toks
}

type parser struct {
	toks []string
	pos  int
}

func (p *parser) peekOp(op string) bool {
	return p.pos < len(p.toks) && strings.EqualFold(p.toks[p.pos], op)
}

// or := and { OR and }
func (p *parser) or(depth int) (*node, error) {
	return p.nary(opOr, depth, p.and)
}

// and := with { AND with }
func (p *parser) and(depth int) (*node, error) {
	return p.nary(opAnd, depth, p.with)
}

func (p *parser) nary(op string, depth int, next func(int) (*node, error)) (*node, error) {
	first, err := next(depth)
	if err != nil {
		return nil, err
	}
	args := []*node{first}
	for p.peekOp(op) {
		p.pos++
		n, err := next(depth)
		if err != nil {
			return nil, err
		}
		args = append(args, n)
	}
	if len(args) == 1 {
		return first, nil
	}
	return combine(op, args), nil
}

// with := "(" or ")" | simple [ WITH exception ]
func (p *parser) with(depth int) (*node, error) {
	if p.pos >= len(p.toks) {
		return nil, fmt.Errorf("%w: unexpected end", ErrInvalidExpression)
	}
	tok := p.toks[p.pos]
	if tok == "(" {
		if depth >= maxDepth {
			return nil, fmt.Errorf("%w: nested too deeply", ErrInvalidExpression)
		}
		p.pos++
		n, err := p.or(depth + 1)
		if err != nil {
			return nil, err
		}
		if p.pos >= len(p.toks) || p.toks[p.pos] != ")" {
			return nil, fmt.Errorf("%w: missing )", ErrInvalidExpression)
		}
		p.pos++
		return n, nil
	}
	if tok == ")" || isOperator(tok) {
		return nil, fmt.Errorf("%w: expected a license, got %q", ErrInvalidExpression, tok)
	}
	p.pos++
	n, err := simple(tok)
	if err != nil {
		return nil, err
	}
	if p.peekOp("WITH") {
		p.pos++
		if p.pos >= len(p.toks) || p.toks[p.pos] == "(" || p.toks[p.pos] == ")" || isOperator(p.toks[p.pos]) {
			return nil, fmt.Errorf("%w: WITH needs an exception", ErrInvalidExpression)
		}
		exc := p.toks[p.pos]
		p.pos++
		switch {
		case additionRf.MatchString(exc):
			n.exception, n.excKnown = exc, true
		case plainID.MatchString(exc):
			if info, ok := LookupException(exc); ok {
				n.exception, n.excKnown = info.ID, true
			} else {
				n.exception = exc
			}
		default:
			return nil, fmt.Errorf("%w: bad exception %q", ErrInvalidExpression, exc)
		}
	}
	return n, nil
}

func isOperator(tok string) bool {
	return strings.EqualFold(tok, opAnd) || strings.EqualFold(tok, opOr) || strings.EqualFold(tok, "WITH")
}

// simple parses one license token: an id with an optional "+", or a reference.
func simple(tok string) (*node, error) {
	if licenseRef.MatchString(tok) {
		return &node{id: tok, known: true}, nil
	}
	// The SPDX list itself carries a few deprecated ids ending in "+"
	// ("GPL-2.0+"); they parse as the bare id with the "+" operator.
	base, plus := strings.CutSuffix(tok, "+")
	// "+" applies to a listed license's version, never to a LicenseRef.
	if !plainID.MatchString(base) || licenseRef.MatchString(base) {
		return nil, fmt.Errorf("%w: bad license id %q", ErrInvalidExpression, tok)
	}
	n := leaf(base)
	n.plus = plus
	return n, nil
}

// leaf builds a license node, canonicalizing a known id.
func leaf(id string) *node {
	if info, ok := Lookup(id); ok {
		return &node{id: info.ID, known: true}
	}
	if licenseRef.MatchString(id) {
		return &node{id: id, known: true}
	}
	return &node{id: id}
}

// combine builds an n-ary op node, flattening nested nodes of the same op
// ("(A AND B) AND C" is "A AND B AND C").
func combine(op string, args []*node) *node {
	n := &node{op: op}
	for _, a := range args {
		if a.op == op {
			n.args = append(n.args, a.args...)
		} else {
			n.args = append(n.args, a)
		}
	}
	return n
}

// And conjoins expressions (skipping empty ones): every one of them applies.
func And(exprs ...Expr) Expr {
	var args []*node
	for _, e := range exprs {
		if e.root != nil {
			args = append(args, e.root)
		}
	}
	switch len(args) {
	case 0:
		return Expr{}
	case 1:
		return Expr{root: args[0]}
	}
	return Expr{root: combine(opAnd, args)}
}

// IsZero reports whether e is the empty expression.
func (e Expr) IsZero() bool { return e.root == nil }

// String is the normalized expression: canonical-case ids, upper-case
// operators, single spaces, and parentheses only where precedence needs them.
func (e Expr) String() string {
	if e.root == nil {
		return ""
	}
	var b strings.Builder
	e.root.write(&b, "")
	return b.String()
}

func (n *node) write(b *strings.Builder, parent string) {
	if n.op == "" {
		b.WriteString(n.id)
		if n.plus {
			b.WriteByte('+')
		}
		if n.exception != "" {
			b.WriteString(" WITH ")
			b.WriteString(n.exception)
		}
		return
	}
	// AND binds tighter than OR: only an OR inside an AND needs parentheses.
	paren := parent == opAnd && n.op == opOr
	if paren {
		b.WriteByte('(')
	}
	for i, a := range n.args {
		if i > 0 {
			b.WriteString(" " + n.op + " ")
		}
		a.write(b, n.op)
	}
	if paren {
		b.WriteByte(')')
	}
}

// walk visits every license node.
func (n *node) walk(fn func(*node)) {
	if n == nil {
		return
	}
	if n.op == "" {
		fn(n)
		return
	}
	for _, a := range n.args {
		a.walk(fn)
	}
}

// IDs is every license id the expression mentions, in order of appearance,
// each once: canonical case for known ids, verbatim for LicenseRef-* and
// unknown ones. A "+" or WITH exception doesn't change the id; exceptions are
// reported by Exceptions.
func (e Expr) IDs() []string {
	return e.collect(func(n *node) string { return n.id })
}

// Exceptions is every WITH exception the expression mentions, each once.
func (e Expr) Exceptions() []string {
	return e.collect(func(n *node) string { return n.exception })
}

// Unknown lists the license ids and exceptions that are neither in the catalog
// nor a LicenseRef-* / AdditionRef-*: what keeps the expression from resolving.
func (e Expr) Unknown() []string {
	return e.collect(func(n *node) string {
		if !n.known {
			return n.id
		}
		if n.exception != "" && !n.excKnown {
			return n.exception
		}
		return ""
	})
}

// Resolved reports whether the expression is non-empty and every id and
// exception in it is known.
func (e Expr) Resolved() bool {
	return e.root != nil && len(e.Unknown()) == 0
}

func (e Expr) collect(pick func(*node) string) []string {
	out := []string{}
	seen := map[string]bool{}
	e.root.walk(func(n *node) {
		if v := pick(n); v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	})
	return out
}

// Satisfies reports whether the expression can be complied with using only
// licenses allowed accepts: an OR needs any one branch, an AND every branch, and
// a license (with or without "+" or a WITH exception) is judged by its id —
// exceptions only ever grant additional permissions. The empty expression
// satisfies nothing.
func (e Expr) Satisfies(allowed func(id string) bool) bool {
	if e.root == nil {
		return false
	}
	return e.root.satisfies(allowed)
}

func (n *node) satisfies(allowed func(string) bool) bool {
	switch n.op {
	case opOr:
		for _, a := range n.args {
			if a.satisfies(allowed) {
				return true
			}
		}
		return false
	case opAnd:
		for _, a := range n.args {
			if !a.satisfies(allowed) {
				return false
			}
		}
		return true
	}
	return allowed(n.id)
}
