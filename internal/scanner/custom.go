package scanner

// No-code parsers (M12 12.4, DefectDojo Pro "Universal Parser" parity): an
// instance admin maps the fields of any CSV, JSON or XML report onto
// ParsedFinding from the UI, no Go code. internal/customparser owns
// persistence, admin HTTP and caching; this file is the pure compiler +
// mapping engine, so it can reuse the severity/CWE/CVE helpers every
// built-in parser shares instead of re-deriving them.
//
// A CustomDefinition has a record selector (where the repeated records live)
// and a CustomFieldMap per ParsedFinding field (a record path/column, a
// static value, or a "{path} in {path2}" template over other paths in the
// same record). NewCustomParser validates + compiles a definition into a
// Parser; Parse (and the detailed ParseDetailed, for a dry-run preview) walk
// the report's records and apply the mapping.

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/xilasec/xila-api/internal/domain"
)

// CustomFieldKey names a ParsedFinding attribute a no-code parser can map.
type CustomFieldKey string

// The mappable ParsedFinding fields. Title is the only required one.
const (
	CFTitle          CustomFieldKey = "title"
	CFSeverity       CustomFieldKey = "severity"
	CFRuleID         CustomFieldKey = "rule_id"
	CFDescription    CustomFieldKey = "description"
	CFCVE            CustomFieldKey = "cve"
	CFCWE            CustomFieldKey = "cwe"
	CFFilePath       CustomFieldKey = "file_path"
	CFLine           CustomFieldKey = "line"
	CFPackage        CustomFieldKey = "package"
	CFPackageVersion CustomFieldKey = "package_version"
	CFFixedVersion   CustomFieldKey = "fixed_version"
	CFURL            CustomFieldKey = "url"
	CFCVSS           CustomFieldKey = "cvss"
)

var customFieldKeys = []CustomFieldKey{
	CFTitle, CFSeverity, CFRuleID, CFDescription, CFCVE, CFCWE, CFFilePath,
	CFLine, CFPackage, CFPackageVersion, CFFixedVersion, CFURL, CFCVSS,
}

// Valid reports whether k is a mappable field.
func (k CustomFieldKey) Valid() bool { return slices.Contains(customFieldKeys, k) }

// CustomFieldKeys lists every mappable field, for the admin UI's mapping editor.
func CustomFieldKeys() []CustomFieldKey { return slices.Clone(customFieldKeys) }

// CustomFormat is the wire format a no-code parser reads.
type CustomFormat string

// Supported no-code formats.
const (
	CustomFormatCSV  CustomFormat = "csv"
	CustomFormatJSON CustomFormat = "json"
	CustomFormatXML  CustomFormat = "xml"
)

// Valid reports whether f is a supported format.
func (f CustomFormat) Valid() bool {
	return f == CustomFormatCSV || f == CustomFormatJSON || f == CustomFormatXML
}

// CustomFormats lists the supported formats, for the admin UI.
func CustomFormats() []CustomFormat {
	return []CustomFormat{CustomFormatCSV, CustomFormatJSON, CustomFormatXML}
}

// CustomFieldMap is one field's mapping: a record path/column, a static
// value, a "{path} in {path2}" template whose placeholders are other paths in
// the same record, or (severity only) a value map from the raw mapped text to
// our severity vocabulary (e.g. {"4": "critical", "Sev3": "medium"}).
// Resolution order is template, else path (falling back to Value if the path
// is absent or empty), else the static Value alone.
type CustomFieldMap struct {
	Path     string            `json:"path,omitempty"`
	Template string            `json:"template,omitempty"`
	Value    string            `json:"value,omitempty"`
	ValueMap map[string]string `json:"value_map,omitempty"`
}

func (m CustomFieldMap) empty() bool { return m.Path == "" && m.Template == "" && m.Value == "" }

// CustomDefinition is a no-code parser: a scanner name, the category its scan
// is recorded under, the wire format, where its repeated records live
// (RecordSelector), and a mapping per ParsedFinding field.
//
// RecordSelector:
//   - json: a dotted path to the array of records ("results",
//     "runs.0.results"), or "$" for a top-level array.
//   - xml: a "/"-separated element path from the document root to the
//     repeated record element ("report/item").
//   - csv: unused (empty) — the header row already defines each record's
//     fields.
type CustomDefinition struct {
	Name           string                            `json:"name"`
	Category       domain.Category                   `json:"category"`
	Format         CustomFormat                      `json:"format"`
	RecordSelector string                            `json:"record_selector"`
	Fields         map[CustomFieldKey]CustomFieldMap `json:"fields"`
}

// Limits on a no-code parser: a report can be arbitrarily sized up to the
// request body limit, but a malicious or mistaken mapping (e.g. a selector
// that matches everything) must not let one upload do unbounded work.
const (
	maxCustomRecords = 100_000
	maxCustomPathLen = 500
	maxCustomDepth   = 20
)

var customNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,63}$`)

// ValidateCustomDefinition checks a definition's shape: a lowercase slug
// name, a known category/format, a syntactically valid record selector (csv:
// none; json/xml: non-empty, within the path-depth cap), a required title
// mapping, only known field keys, value maps only on severity, and every
// path/template within the path-depth and length caps. It does not run the
// mapping against real data — collisionCheck (name vs. built-ins) and running
// a sample through DryRun catch the rest.
func ValidateCustomDefinition(def CustomDefinition) error {
	if !customNameRe.MatchString(def.Name) {
		return fmt.Errorf("name must be a lowercase slug (letters, digits, hyphens, 2-64 chars): %q", def.Name)
	}
	if !def.Category.Valid() {
		return fmt.Errorf("unknown category: %q", def.Category)
	}
	if !def.Format.Valid() {
		return fmt.Errorf("unknown format %q (must be csv, json or xml)", def.Format)
	}
	switch def.Format {
	case CustomFormatCSV:
		if strings.TrimSpace(def.RecordSelector) != "" {
			return errors.New("record_selector is not used for csv: the header row already defines each record's fields")
		}
	default:
		sel := strings.TrimSpace(def.RecordSelector)
		if sel == "" {
			return fmt.Errorf("record_selector is required for %s", def.Format)
		}
		if err := validatePathSyntax(sel); err != nil {
			return fmt.Errorf("record_selector: %w", err)
		}
	}
	title, ok := def.Fields[CFTitle]
	if !ok || title.empty() {
		return errors.New("a title mapping is required")
	}
	for key, fm := range def.Fields {
		if !key.Valid() {
			return fmt.Errorf("unknown field %q", key)
		}
		if len(fm.ValueMap) > 0 && key != CFSeverity {
			return fmt.Errorf("field %q: value_map is only valid for severity", key)
		}
		if err := validateFieldMapSyntax(fm); err != nil {
			return fmt.Errorf("field %q: %w", key, err)
		}
	}
	return nil
}

// splitPath breaks a dotted (JSON) or slashed (XML) path into segments. "."
// and "/" are accepted interchangeably so one navigator serves both formats.
func splitPath(p string) []string {
	if p == "" {
		return nil
	}
	return strings.FieldsFunc(p, func(r rune) bool { return r == '.' || r == '/' })
}

func validatePathSyntax(p string) error {
	if p == "$" {
		return nil
	}
	if len(p) > maxCustomPathLen {
		return fmt.Errorf("path too long (max %d): %q", maxCustomPathLen, p)
	}
	segs := splitPath(p)
	if len(segs) == 0 {
		return fmt.Errorf("path is empty: %q", p)
	}
	if len(segs) > maxCustomDepth {
		return fmt.Errorf("path exceeds max depth %d: %q", maxCustomDepth, p)
	}
	return nil
}

var templatePlaceholderRe = regexp.MustCompile(`\{([^{}]*)\}`)

func validateFieldMapSyntax(fm CustomFieldMap) error {
	if fm.Path != "" {
		if err := validatePathSyntax(fm.Path); err != nil {
			return err
		}
	}
	for _, m := range templatePlaceholderRe.FindAllStringSubmatch(fm.Template, -1) {
		if m[1] == "" {
			return fmt.Errorf("template has an empty {} placeholder: %q", fm.Template)
		}
		if err := validatePathSyntax(m[1]); err != nil {
			return fmt.Errorf("template placeholder {%s}: %w", m[1], err)
		}
	}
	return nil
}

// CustomParser is a no-code parser compiled from a validated CustomDefinition.
// It implements Parser like any built-in scanner, so the ingest pipeline
// (dedup, triage, priority, gates, alerts) works on its findings unchanged.
type CustomParser struct {
	def CustomDefinition
}

// NewCustomParser validates def and compiles it into a Parser.
func NewCustomParser(def CustomDefinition) (*CustomParser, error) {
	if err := ValidateCustomDefinition(def); err != nil {
		return nil, err
	}
	return &CustomParser{def: def}, nil
}

// Scanner implements Parser.
func (p *CustomParser) Scanner() string { return p.def.Name }

// PrimaryCategory implements Parser.
func (p *CustomParser) PrimaryCategory() domain.Category { return p.def.Category }

// RecordError is one record's mapping failure (e.g. a missing required
// title). Parse discards these (a malformed record is skipped, like every
// built-in parser tolerates one bad entry); ParseDetailed keeps them so the
// admin dry-run endpoint can show exactly what each record produced.
type RecordError struct {
	Index int    `json:"index"`
	Error string `json:"error"`
}

// Parse implements Parser.
func (p *CustomParser) Parse(r io.Reader) ([]ParsedFinding, error) {
	findings, _, err := p.ParseDetailed(r)
	return findings, err
}

// ParseDetailed parses the report and returns both the findings it would
// create and any per-record mapping errors. A structurally broken report (bad
// JSON/XML/CSV, or a record selector that matches nothing) is the only error
// Parse itself returns; everything else becomes a RecordError.
func (p *CustomParser) ParseDetailed(r io.Reader) ([]ParsedFinding, []RecordError, error) {
	recs, err := p.extractRecords(r)
	if err != nil {
		return nil, nil, err
	}
	if len(recs) > maxCustomRecords {
		recs = recs[:maxCustomRecords]
	}
	findings := make([]ParsedFinding, 0, len(recs))
	var recErrs []RecordError
	for i, rec := range recs {
		pf, err := p.mapRecord(rec)
		if err != nil {
			recErrs = append(recErrs, RecordError{Index: i, Error: err.Error()})
			continue
		}
		findings = append(findings, pf)
	}
	return mergeSameLocation(findings), recErrs, nil
}

// customRecord is a generic view over one parsed record (a JSON object, an
// XML element, or a CSV row), so the mapping engine resolves a field's path
// the same way regardless of the source format.
type customRecord interface {
	field(path string) (string, bool)
}

func (p *CustomParser) extractRecords(r io.Reader) ([]customRecord, error) {
	switch p.def.Format {
	case CustomFormatCSV:
		return csvRecords(r)
	case CustomFormatJSON:
		return jsonRecordsFrom(r, p.def.RecordSelector)
	case CustomFormatXML:
		return xmlRecordsFrom(r, p.def.RecordSelector)
	}
	return nil, fmt.Errorf("unsupported format: %q", p.def.Format)
}

// --- CSV --------------------------------------------------------------

type csvRecord map[string]string

func (r csvRecord) field(path string) (string, bool) {
	v, ok := r[path]
	return v, ok
}

func csvRecords(r io.Reader) ([]customRecord, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1 // tolerate ragged rows rather than failing the whole report
	header, err := cr.Read()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("csv report is empty")
		}
		return nil, fmt.Errorf("read csv header: %w", err)
	}
	for i := range header {
		header[i] = strings.TrimSpace(header[i])
	}
	var out []customRecord
	for len(out) < maxCustomRecords {
		row, err := cr.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read csv row: %w", err)
		}
		rec := make(csvRecord, len(header))
		for i, h := range header {
			if i < len(row) {
				rec[h] = row[i]
			}
		}
		out = append(out, rec)
	}
	return out, nil
}

// --- JSON ---------------------------------------------------------------

type jsonRecord struct{ v any }

func (r jsonRecord) field(path string) (string, bool) {
	node, ok := jsonNavigate(r.v, path)
	if !ok {
		return "", false
	}
	return jsonScalarString(node)
}

func jsonRecordsFrom(r io.Reader, selector string) ([]customRecord, error) {
	var doc any
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode json: %w", err)
	}
	arr, err := jsonSelectArray(doc, selector)
	if err != nil {
		return nil, err
	}
	if len(arr) > maxCustomRecords {
		arr = arr[:maxCustomRecords]
	}
	out := make([]customRecord, len(arr))
	for i, v := range arr {
		out[i] = jsonRecord{v: v}
	}
	return out, nil
}

func jsonSelectArray(doc any, selector string) ([]any, error) {
	selector = strings.TrimSpace(selector)
	if selector == "" || selector == "$" {
		arr, ok := doc.([]any)
		if !ok {
			return nil, errors.New(`record_selector "$": document root is not an array`)
		}
		return arr, nil
	}
	node, ok := jsonNavigate(doc, selector)
	if !ok {
		return nil, fmt.Errorf("record_selector %q: path not found", selector)
	}
	arr, ok := node.([]any)
	if !ok {
		return nil, fmt.Errorf("record_selector %q: value is not an array", selector)
	}
	return arr, nil
}

// jsonNavigate walks v by path's dotted segments: a map key, or a numeric
// index into an array.
func jsonNavigate(v any, path string) (any, bool) {
	cur := v
	for _, seg := range splitPath(path) {
		switch t := cur.(type) {
		case map[string]any:
			next, ok := t[seg]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(t) {
				return nil, false
			}
			cur = t[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

// jsonScalarString renders a decoded JSON value as text. An array of scalars
// is joined (useful for alias/CVE lists); an object can't be stringified
// directly — the mapping should navigate into it instead.
func jsonScalarString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case float64:
		if t == math.Trunc(t) && !math.IsInf(t, 0) {
			return strconv.FormatInt(int64(t), 10), true
		}
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(t), true
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := jsonScalarString(e); ok {
				parts = append(parts, s)
			}
		}
		if len(parts) == 0 {
			return "", false
		}
		return strings.Join(parts, ", "), true
	}
	return "", false
}

// --- XML ------------------------------------------------------------------

// xmlNode is a generic element tree, decoded with Go's encoding/xml, which
// never resolves external entities or a DTD at all (no billion-laughs, no
// XXE) — the same hardening every built-in XML parser in this repo gets for
// free by using xml.Decoder directly (see burp.go, nmap.go).
type xmlNode struct {
	Name     string
	Attrs    map[string]string
	Text     string
	Children []*xmlNode
}

func (n *xmlNode) field(path string) (string, bool) {
	segs := splitPath(path)
	if len(segs) == 0 {
		return "", false
	}
	cur := n
	for i, seg := range segs {
		last := i == len(segs)-1
		if attr, isAttr := strings.CutPrefix(seg, "@"); isAttr {
			if !last {
				return "", false
			}
			v, ok := cur.Attrs[attr]
			return v, ok
		}
		if last {
			for _, c := range cur.Children {
				if c.Name == seg {
					return strings.TrimSpace(c.Text), true
				}
			}
			return "", false
		}
		var next *xmlNode
		for _, c := range cur.Children {
			if c.Name == seg {
				next = c
				break
			}
		}
		if next == nil {
			return "", false
		}
		cur = next
	}
	return "", false
}

func xmlRecordsFrom(r io.Reader, selector string) ([]customRecord, error) {
	root, err := decodeXMLTree(r)
	if err != nil {
		return nil, err
	}
	nodes, err := xmlSelectRecords(root, selector)
	if err != nil {
		return nil, err
	}
	if len(nodes) > maxCustomRecords {
		nodes = nodes[:maxCustomRecords]
	}
	out := make([]customRecord, len(nodes))
	for i, n := range nodes {
		out[i] = n
	}
	return out, nil
}

// decodeXMLTree builds a generic element tree for an arbitrary schema. The
// element cap is a defense-in-depth guard independent of maxCustomRecords
// (a deeply-nested non-record structure could otherwise grow unbounded).
func decodeXMLTree(r io.Reader) (*xmlNode, error) {
	dec := xml.NewDecoder(r)
	var stack []*xmlNode
	var root *xmlNode
	nodes := 0
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("decode xml: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			nodes++
			if nodes > maxCustomRecords*50 {
				return nil, errors.New("xml document has too many elements")
			}
			n := &xmlNode{Name: t.Name.Local, Attrs: make(map[string]string, len(t.Attr))}
			for _, a := range t.Attr {
				n.Attrs[a.Name.Local] = a.Value
			}
			if len(stack) > 0 {
				parent := stack[len(stack)-1]
				parent.Children = append(parent.Children, n)
			} else if root == nil {
				root = n
			}
			stack = append(stack, n)
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].Text += string(t)
			}
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		}
	}
	if root == nil {
		return nil, errors.New("xml document has no root element")
	}
	return root, nil
}

// xmlSelectRecords navigates selector (root/child/.../record) from the real
// document root (segs[0] must name it) and returns every element matching the
// final segment — the repeated record elements.
func xmlSelectRecords(root *xmlNode, selector string) ([]*xmlNode, error) {
	segs := splitPath(selector)
	if len(segs) == 0 {
		return nil, errors.New("record_selector is empty")
	}
	if segs[0] != root.Name {
		return nil, fmt.Errorf("record_selector %q: document root element is %q", selector, root.Name)
	}
	cur := []*xmlNode{root}
	rest := segs[1:]
	for i, seg := range rest {
		last := i == len(rest)-1
		var next []*xmlNode
		for _, n := range cur {
			for _, c := range n.Children {
				if c.Name == seg {
					next = append(next, c)
				}
			}
		}
		if len(next) == 0 {
			return nil, fmt.Errorf("record_selector %q: no element %q found", selector, seg)
		}
		if last {
			cur = next
		} else {
			cur = []*xmlNode{next[0]}
		}
	}
	return cur, nil
}

// --- mapping --------------------------------------------------------------

// resolveFieldRaw resolves one field mapping against a record: a template
// (placeholders are other paths in the record), else a path (falling back to
// Value when absent or empty), else the static Value alone.
func resolveFieldRaw(fm CustomFieldMap, rec customRecord) (string, bool) {
	if fm.Template != "" {
		return expandTemplate(fm.Template, rec), true
	}
	if fm.Path != "" {
		if v, ok := rec.field(fm.Path); ok && v != "" {
			return v, true
		}
	}
	if fm.Value != "" {
		return fm.Value, true
	}
	return "", false
}

func expandTemplate(tmpl string, rec customRecord) string {
	return templatePlaceholderRe.ReplaceAllStringFunc(tmpl, func(m string) string {
		path := m[1 : len(m)-1]
		if v, ok := rec.field(path); ok {
			return v
		}
		return ""
	})
}

// mapRecord applies the definition's field mappings to one record.
func (p *CustomParser) mapRecord(rec customRecord) (ParsedFinding, error) {
	titleSpec, ok := p.def.Fields[CFTitle]
	if !ok {
		return ParsedFinding{}, errors.New("no title mapping configured")
	}
	title, ok := resolveFieldRaw(titleSpec, rec)
	title = strings.TrimSpace(title)
	if !ok || title == "" {
		return ParsedFinding{}, errors.New("missing required field: title")
	}

	pf := ParsedFinding{Category: p.def.Category, Title: title, Severity: domain.SeverityMedium}

	severitySet := false
	if spec, ok := p.def.Fields[CFSeverity]; ok {
		if raw, has := resolveFieldRaw(spec, rec); has {
			if mapped, exists := spec.ValueMap[raw]; exists {
				pf.Severity = normalizeSeverity(mapped)
			} else {
				pf.Severity = normalizeSeverity(raw)
			}
			severitySet = true
		}
	}
	// The ingest fingerprint keys on scanner+category+rule_id+file_path+
	// package+line, not title: a definition that maps only title would
	// otherwise collapse every distinct finding with no mapped location into
	// one. Falling back to the title keeps distinct records distinct by
	// default; an explicit rule_id mapping (even one that can be empty for
	// some records) is the admin's deliberate choice and is never overridden.
	if spec, ok := p.def.Fields[CFRuleID]; ok {
		if raw, has := resolveFieldRaw(spec, rec); has {
			pf.RuleID = raw
		}
	} else {
		pf.RuleID = title
	}
	if spec, ok := p.def.Fields[CFDescription]; ok {
		if raw, has := resolveFieldRaw(spec, rec); has {
			pf.Description = raw
		}
	}
	if spec, ok := p.def.Fields[CFCVE]; ok {
		if raw, has := resolveFieldRaw(spec, rec); has {
			pf.CVE = cvesInText(raw)
		}
	}
	if spec, ok := p.def.Fields[CFCWE]; ok {
		if raw, has := resolveFieldRaw(spec, rec); has {
			pf.CWE = cweFrom(raw)
		}
	}
	if spec, ok := p.def.Fields[CFFilePath]; ok {
		if raw, has := resolveFieldRaw(spec, rec); has {
			pf.FilePath = raw
		}
	}
	if spec, ok := p.def.Fields[CFLine]; ok {
		if raw, has := resolveFieldRaw(spec, rec); has {
			if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
				pf.Line = intPtr(n)
			}
		}
	}
	if spec, ok := p.def.Fields[CFPackage]; ok {
		if raw, has := resolveFieldRaw(spec, rec); has {
			pf.Package = raw
		}
	}
	if spec, ok := p.def.Fields[CFPackageVersion]; ok {
		if raw, has := resolveFieldRaw(spec, rec); has {
			pf.PackageVersion = raw
		}
	}
	if spec, ok := p.def.Fields[CFFixedVersion]; ok {
		if raw, has := resolveFieldRaw(spec, rec); has {
			pf.FixedVersion = raw
		}
	}
	if spec, ok := p.def.Fields[CFURL]; ok {
		if raw, has := resolveFieldRaw(spec, rec); has {
			pf.URL = raw
		}
	}
	if spec, ok := p.def.Fields[CFCVSS]; ok {
		if raw, has := resolveFieldRaw(spec, rec); has {
			if f, err := strconv.ParseFloat(strings.TrimSpace(raw), 64); err == nil {
				pf.CVSS = floatPtr(f)
				if !severitySet {
					pf.Severity = severityFromCVSS(f)
					severitySet = true
				}
			}
		}
	}
	return pf, nil
}
