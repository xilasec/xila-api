package scanner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Export formats written by hand or by many different tools (DefectDojo's
// generic import above all) are loose about JSON types: a line number arrives as
// 42, "42" or "N/A". These types accept every shape and keep only real values,
// so one sloppy field doesn't fail an otherwise valid import.

// flexInt is an optional integer that may be encoded as a number or a string.
type flexInt struct{ v *int }

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		f.v = &n
	} else if fl, err := strconv.ParseFloat(s, 64); err == nil && fl == float64(int(fl)) {
		n := int(fl)
		f.v = &n
	}
	return nil
}

// ptr returns the value, or nil when absent or not a number.
func (f flexInt) ptr() *int { return f.v }

// flexFloat is an optional float that may be encoded as a number or a string.
type flexFloat struct{ v *float64 }

func (f *flexFloat) UnmarshalJSON(b []byte) error {
	s := strings.Trim(strings.TrimSpace(string(b)), `"`)
	if n, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
		f.v = &n
	}
	return nil
}

func (f flexFloat) ptr() *float64 { return f.v }

// flexStrings is a list of identifiers that may be a single string, a list of
// strings, or a list mixing strings, numbers and {"x": "CVE-…"} objects. Every
// scalar found is kept as a string.
type flexStrings []string

func (f *flexStrings) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		return nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	var walk func(any)
	walk = func(x any) {
		switch t := x.(type) {
		case string:
			if t != "" {
				*f = append(*f, t)
			}
		case float64:
			*f = append(*f, strconv.FormatFloat(t, 'f', -1, 64))
		case []any:
			for _, e := range t {
				walk(e)
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		case nil, bool:
		default:
			*f = append(*f, fmt.Sprint(t))
		}
	}
	walk(v)
	return nil
}

// cweFirst returns the first CWE id found in values like "CWE-79",
// "CWE-696: Incorrect Behavior Order" or "79".
func cweFirst(vals ...string) *int {
	for _, v := range vals {
		if n := cweFrom(v); n != nil {
			return n
		}
		if m := cweRe.FindStringSubmatch(v); m != nil {
			if n, err := strconv.Atoi(m[1]); err == nil && n > 0 {
				return &n
			}
		}
	}
	return nil
}
