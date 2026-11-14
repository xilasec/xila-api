// Package expr evaluates the CEL expressions policies and triage rules may use
// as a condition (https://cel.dev — the language Dependency-Track and
// Kubernetes use for the same job).
//
// An expression reads a plain document of facts — maps, lists, strings,
// numbers, booleans, and null for a fact nobody knows — the same document an
// external policy engine would be given. Two invariants:
//
//   - Unknown never matches. A missing fact is null, and anything that can't be
//     evaluated (null compared or used in arithmetic, a missing key) counts as
//     "no match", never as a violation or an auto-triage hit.
//   - Mistakes are rejected when the rule is saved: syntax and type errors, a
//     result that isn't a boolean, an expression too expensive to run per
//     component, and a field name that doesn't exist (the expression is
//     dry-run against a document with every fact present).
package expr

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/ext"
)

// Limits: an expression runs once per component (policies) or finding (triage
// rules) on every evaluation, so it must stay cheap.
const (
	maxSource = 4096
	costLimit = 100_000
)

// Schema is one kind of document: its top-level variable names and a sample
// with every fact present (to catch misspelled fields when saving).
type Schema struct {
	Vars   []string
	Sample map[string]any
}

// Program is a compiled, validated expression.
type Program struct {
	Source string
	prg    cel.Program
}

func env(s Schema) (*cel.Env, error) {
	opts := []cel.EnvOption{ext.Strings(), cel.ParserExpressionSizeLimit(maxSource)}
	for _, v := range s.Vars {
		opts = append(opts, cel.Variable(v, cel.DynType))
	}
	return cel.NewEnv(opts...)
}

// Compile validates src against the schema and returns the runnable program.
// Errors are user-facing (they explain what to fix).
func Compile(s Schema, src string) (*Program, error) {
	return compile(s, src, true)
}

// Load compiles an expression that was validated when it was saved, without
// the dry run: a fact that has since disappeared (a deleted custom field) must
// make the expression not match — Match treats the missing key as no match —
// rather than fail to load.
func Load(vars []string, src string) (*Program, error) {
	return compile(Schema{Vars: vars}, src, false)
}

func compile(s Schema, src string, dryRun bool) (*Program, error) {
	src = strings.TrimSpace(src)
	if src == "" {
		return nil, errors.New("expression is empty")
	}
	if len(src) > maxSource {
		return nil, fmt.Errorf("expression is longer than %d characters", maxSource)
	}
	e, err := env(s)
	if err != nil {
		return nil, err
	}
	ast, iss := e.Compile(src)
	if iss.Err() != nil {
		return nil, fmt.Errorf("expression: %s", iss.Err())
	}
	if t := ast.OutputType(); !t.IsAssignableType(cel.BoolType) && t != cel.DynType {
		return nil, fmt.Errorf("expression must be true or false, not %s", t)
	}
	prg, err := e.Program(ast, cel.CostLimit(costLimit), cel.InterruptCheckFrequency(100))
	if err != nil {
		return nil, fmt.Errorf("expression: %w", err)
	}
	p := &Program{Source: src, prg: prg}
	if !dryRun {
		return p, nil
	}
	// Dry run: every fact is present here, so an error means the expression
	// names something that doesn't exist or uses a fact the wrong way.
	out, _, err := prg.ContextEval(context.Background(), s.Sample)
	if err != nil {
		return nil, fmt.Errorf("expression: %s (available: %s)", err, strings.Join(fieldList(s.Sample, ""), ", "))
	}
	if out.Type() != types.BoolType {
		return nil, fmt.Errorf("expression must be true or false, not %s", out.Type().TypeName())
	}
	return p, nil
}

// Match evaluates the expression on doc. An error — an unknown (null) fact, a
// key the document lacks, the cost limit — is "no match".
func (p *Program) Match(ctx context.Context, doc map[string]any) bool {
	out, _, err := p.prg.ContextEval(ctx, doc)
	if err != nil {
		return false
	}
	b, ok := out.Value().(bool)
	return ok && b
}

// fieldList names every field of the sample, for error messages.
func fieldList(m map[string]any, prefix string) []string {
	var out []string
	for k, v := range m {
		name := prefix + k
		if sub, ok := v.(map[string]any); ok {
			out = append(out, fieldList(sub, name+".")...)
			continue
		}
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}
