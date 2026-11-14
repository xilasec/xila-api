package customfield

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Op is a filter comparison.
type Op string

// Filter operators: ?cf.<key>=v (equals), ?cf.<key>.gte=v (and gt, lte, lt —
// numbers and YYYY-MM-DD dates), ?cf.<key>.set=true|false.
const (
	OpEq  Op = "eq"
	OpGt  Op = "gt"
	OpGte Op = "gte"
	OpLt  Op = "lt"
	OpLte Op = "lte"
	OpSet Op = "set"
)

var sqlOps = map[Op]string{OpGt: ">", OpGte: ">=", OpLt: "<", OpLte: "<="}

// MaxFilters caps the ?cf. parameters one request may carry.
const MaxFilters = 10

// Cond is one ?cf.<key>[.op]=value filter.
type Cond struct {
	Key   string
	Op    Op
	Value string
	// Parsed forms of Value.
	num    *float64
	isDate bool
	set    bool
}

// ParseFilters reads every cf.<key>[.<op>] parameter from params. It needs no
// definitions: an equality matches the value as text or (when it parses as
// one) as a number; a range compares numbers numerically and dates as
// YYYY-MM-DD. A key no entity carries simply matches nothing.
func ParseFilters(params map[string]string) ([]Cond, error) {
	var out []Cond
	for name, value := range params {
		rest, ok := strings.CutPrefix(name, "cf.")
		if !ok {
			continue
		}
		key, opName, _ := strings.Cut(rest, ".")
		c := Cond{Key: key, Op: OpEq, Value: value}
		if opName != "" {
			c.Op = Op(opName)
		}
		if !ValidKey(key) {
			return nil, invalid("cf.%s: not a custom field key", rest)
		}
		switch c.Op {
		case OpEq:
			if value == "" {
				return nil, invalid("cf.%s needs a value", key)
			}
			if n, err := strconv.ParseFloat(value, 64); err == nil {
				c.num = &n
			}
		case OpGt, OpGte, OpLt, OpLte:
			if n, err := strconv.ParseFloat(value, 64); err == nil {
				c.num = &n
			} else if _, err := time.Parse(time.DateOnly, value); err == nil {
				c.isDate = true
			} else {
				return nil, invalid("cf.%s.%s must be a number or a date (YYYY-MM-DD)", key, c.Op)
			}
		case OpSet:
			b, err := strconv.ParseBool(value)
			if err != nil {
				return nil, invalid("cf.%s.set must be true or false", key)
			}
			c.set = b
		default:
			return nil, invalid("cf.%s: unknown operator %q (use gt, gte, lt, lte or set)", key, opName)
		}
		out = append(out, c)
	}
	if len(out) > MaxFilters {
		return nil, invalid("at most %d custom-field filters", MaxFilters)
	}
	// Map order is random: sort, so the same request builds the same SQL.
	slices.SortFunc(out, func(a, b Cond) int {
		return strings.Compare(a.Key+"."+string(a.Op), b.Key+"."+string(b.Op))
	})
	return out, nil
}

// AppendSQL ANDs conds onto a WHERE clause over the jsonb column col
// (e.g. "custom" or "p.custom"), appending its parameters to args.
func AppendSQL(conds []Cond, col string, args []any) (string, []any) {
	var b strings.Builder
	for _, c := range conds {
		args = append(args, c.Key)
		k := len(args)
		switch c.Op {
		case OpEq:
			args = append(args, c.Value)
			fmt.Fprintf(&b, " AND (%s @> jsonb_build_object($%d::text, $%d::text)", col, k, len(args))
			if c.num != nil {
				args = append(args, *c.num)
				fmt.Fprintf(&b, " OR %s @> jsonb_build_object($%d::text, $%d::numeric)", col, k, len(args))
			}
			b.WriteString(")")
		case OpSet:
			if c.set {
				fmt.Fprintf(&b, " AND %s ? $%d::text", col, k)
			} else {
				fmt.Fprintf(&b, " AND NOT (%s ? $%d::text)", col, k)
			}
		default:
			// CASE guards the cast: only a stored number is read as numeric,
			// only a stored date string as a date.
			if c.num != nil {
				args = append(args, *c.num)
				fmt.Fprintf(&b, " AND (CASE WHEN jsonb_typeof(%[1]s -> $%[2]d::text) = 'number' THEN (%[1]s ->> $%[2]d::text)::numeric END) %[3]s $%[4]d::numeric",
					col, k, sqlOps[c.Op], len(args))
			} else {
				args = append(args, c.Value)
				fmt.Fprintf(&b, " AND (CASE WHEN %[1]s ->> $%[2]d::text ~ '^\\d{4}-\\d{2}-\\d{2}$' THEN %[1]s ->> $%[2]d::text END) %[3]s $%[4]d::text",
					col, k, sqlOps[c.Op], len(args))
			}
		}
	}
	return b.String(), args
}
