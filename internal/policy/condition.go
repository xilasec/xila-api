package policy

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/expr"
	"github.com/xilasec/xila-api/internal/license"
	"github.com/xilasec/xila-api/internal/sbom"
)

// Subject is the component fact a condition tests.
type Subject string

// Security subjects judge the component's vulnerabilities (advisory matches and
// scanner findings, by the sbom.VulnState rule), license subjects its resolved
// SPDX expression, operational subjects its coordinates and package metadata.
const (
	SubjectSeverity          Subject = "severity"           // gte: worst vulnerability severity ≥ value
	SubjectVulnerabilityID   Subject = "vulnerability_id"   // is / matches: any advisory id or CVE
	SubjectKEV               Subject = "kev"                // is: a vulnerability is on a KEV catalog
	SubjectKEVSource         Subject = "kev_source"         // in: a vulnerability is on one of these KEV catalogs
	SubjectEPSS              Subject = "epss"               // gte: highest EPSS ≥ value (0–1)
	SubjectCWE               Subject = "cwe"                // in: a vulnerability's CWE is listed
	SubjectLicense           Subject = "license"            // is / is_not: SPDX id globs
	SubjectLicenseGroup      Subject = "license_group"      // in / not_in: license group refs
	SubjectLicenseUnresolved Subject = "license_unresolved" // is: license doesn't resolve to SPDX
	SubjectOutdated          Subject = "outdated"           // is: a newer release exists
	SubjectVersionsBehind    Subject = "versions_behind"    // gte: releases behind the latest
	SubjectAge               Subject = "age"                // gte: days since this version's release
	SubjectMissingHash       Subject = "missing_hash"       // is: "any" (no hash) / "strong" (no SHA-256+)
	SubjectIntegrity         Subject = "integrity"          // is: "mismatch" / "verified" against the registry's digests
	SubjectCoordinates       Subject = "coordinates"        // matches / no_match: group/name/version
	SubjectPurl              Subject = "purl"               // matches / no_match: purl globs
	SubjectPackageType       Subject = "package_type"       // in / not_in: purl types

	// AI inventory (ML-BOM) subjects. model.* judge models and AI services,
	// dataset.name datasets and the datasets a model card names; any other
	// component is unknown to them.
	SubjectComponentKind Subject = "component.kind" // in / not_in: software, model, dataset, ai-service
	SubjectModelSupplier Subject = "model.supplier" // in / not_in: supplier / manufacturer / publisher globs
	SubjectModelName     Subject = "model.name"     // matches / no_match: name or group/name globs
	SubjectModelLicense  Subject = "model.license"  // is / is_not: SPDX id globs, as license
	SubjectModelTask     Subject = "model.task"     // in / not_in: model card task globs
	SubjectDatasetName   Subject = "dataset.name"   // matches / no_match: dataset name globs
)

// Operator is how a condition compares the fact with its value.
type Operator string

// Operators.
const (
	OpIs      Operator = "is"
	OpIsNot   Operator = "is_not"
	OpMatches Operator = "matches"
	OpNoMatch Operator = "no_match"
	OpIn      Operator = "in"
	OpNotIn   Operator = "not_in"
	OpGTE     Operator = "gte"
)

// operators lists each subject's valid operators.
var operators = map[Subject][]Operator{
	SubjectSeverity:          {OpGTE},
	SubjectVulnerabilityID:   {OpIs, OpMatches},
	SubjectKEV:               {OpIs},
	SubjectKEVSource:         {OpIn},
	SubjectEPSS:              {OpGTE},
	SubjectCWE:               {OpIn},
	SubjectLicense:           {OpIs, OpIsNot},
	SubjectLicenseGroup:      {OpIn, OpNotIn},
	SubjectLicenseUnresolved: {OpIs},
	SubjectOutdated:          {OpIs},
	SubjectVersionsBehind:    {OpGTE},
	SubjectAge:               {OpGTE},
	SubjectMissingHash:       {OpIs},
	SubjectIntegrity:         {OpIs},
	SubjectCoordinates:       {OpMatches, OpNoMatch},
	SubjectPurl:              {OpMatches, OpNoMatch},
	SubjectPackageType:       {OpIn, OpNotIn},
	SubjectComponentKind:     {OpIn, OpNotIn},
	SubjectModelSupplier:     {OpIn, OpNotIn},
	SubjectModelName:         {OpMatches, OpNoMatch},
	SubjectModelLicense:      {OpIs, OpIsNot},
	SubjectModelTask:         {OpIn, OpNotIn},
	SubjectDatasetName:       {OpMatches, OpNoMatch},
}

// IsLicense reports whether s judges the component's license.
func (s Subject) IsLicense() bool {
	return s == SubjectLicense || s == SubjectLicenseGroup || s == SubjectLicenseUnresolved || s == SubjectModelLicense
}

// Condition is one test of a policy: subject, operator, value. Value's type
// depends on the subject (see the README's policy section); Validate normalizes
// it (a single string becomes a one-element list, for example).
type Condition struct {
	Subject  Subject         `json:"subject"`
	Operator Operator        `json:"operator"`
	Value    json.RawMessage `json:"value"`
}

// Coordinates is the value of a coordinates condition. Group and Name are
// globs; Version is a glob, or a range when it starts with a comparison
// (">=1.2.0, <2.0.0"), ordered by sbom.CompareVersions. Empty parts match
// anything; at least one must be set.
type Coordinates struct {
	Group   string `json:"group"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

// PackageInfo is what the package repositories say about a component version
// (pkgmeta). A component without it is unknown — never "up to date".
type PackageInfo struct {
	Latest         string
	Outdated       bool
	VersionsBehind *int
	Published      *time.Time
}

// Component is one inventory component with the facts conditions read: the
// parsed license (zero when there is none) and package metadata (nil when
// unknown).
type Component struct {
	sbom.InventoryComponent
	License license.Expr
	Meta    *PackageInfo
}

// Match is a condition that held for a component, and the fact that made it so.
type Match struct {
	Subject  Subject         `json:"subject"`
	Operator Operator        `json:"operator"`
	Value    json.RawMessage `json:"value"`
	Fact     string          `json:"fact"`
}

// ValidationError is a policy the API must reject (400).
type ValidationError struct{ msg string }

func (e *ValidationError) Error() string { return e.msg }

func invalid(format string, args ...any) error {
	return &ValidationError{msg: fmt.Sprintf(format, args...)}
}

// errGroupGone is what a group resolver returns for a group that no longer
// exists while evaluating: the condition then never matches (rather than
// failing the whole policy, which would close all of its violations).
var errGroupGone = errors.New("license group gone")

// groupResolver returns the license ids of a license group ref.
type groupResolver func(ref string) ([]string, error)

// matcher tests one component; fact describes what it saw.
type matcher func(c *Component, now time.Time) (ok bool, fact string)

// compiled is a validated condition ready to evaluate.
type compiled struct {
	Condition
	match matcher
}

// compile validates c, normalizes its value and builds its matcher. schema is
// the document an expression is checked against (ComponentSchemaFor the
// current project custom fields).
func compile(c Condition, groups groupResolver, schema expr.Schema) (compiled, error) {
	ops, ok := operators[c.Subject]
	if !ok {
		return compiled{}, invalid("unknown condition subject %q", c.Subject)
	}
	if !slices.Contains(ops, c.Operator) {
		return compiled{}, invalid("operator %q is not valid for %s (use %s)", c.Operator, c.Subject, joinOps(ops))
	}
	if len(c.Value) == 0 || string(c.Value) == "null" {
		return compiled{}, invalid("%s: value is required", c.Subject)
	}
	var (
		m     matcher
		value any
		err   error
	)
	switch c.Subject {
	case SubjectSeverity:
		m, value, err = compileSeverity(c)
	case SubjectVulnerabilityID:
		m, value, err = compileVulnID(c)
	case SubjectKEV:
		m, value, err = compileBool(c, func(x *Component) (bool, bool, string) {
			return x.KEV, true, fmt.Sprintf("kev %t", x.KEV)
		})
	case SubjectKEVSource:
		m, value, err = compileKEVSource(c)
	case SubjectEPSS:
		m, value, err = compileEPSS(c)
	case SubjectCWE:
		m, value, err = compileCWE(c)
	case SubjectLicense:
		m, value, err = compileLicense(c)
	case SubjectLicenseGroup:
		m, value, err = compileLicenseGroup(c, groups)
	case SubjectLicenseUnresolved:
		m, value, err = compileBool(c, func(x *Component) (bool, bool, string) {
			if x.LicenseResolved == nil {
				return false, false, ""
			}
			return !*x.LicenseResolved, true, licenseFact(x)
		})
	case SubjectOutdated:
		m, value, err = compileBool(c, func(x *Component) (bool, bool, string) {
			if x.Meta == nil {
				return false, false, ""
			}
			return x.Meta.Outdated, true, "latest " + orDash(x.Meta.Latest)
		})
	case SubjectVersionsBehind:
		m, value, err = compileVersionsBehind(c)
	case SubjectAge:
		m, value, err = compileAge(c)
	case SubjectMissingHash:
		m, value, err = compileMissingHash(c)
	case SubjectIntegrity:
		m, value, err = compileIntegrity(c)
	case SubjectCoordinates:
		m, value, err = compileCoordinates(c)
	case SubjectPurl:
		m, value, err = compilePurl(c)
	case SubjectPackageType:
		m, value, err = compilePackageType(c)
	case SubjectExpression:
		m, value, err = compileExpression(c, schema)
	case SubjectComponentKind:
		m, value, err = compileComponentKind(c)
	case SubjectModelSupplier:
		m, value, err = compileModelFacts(c, OpIn, "supplier", false, func(x *Component) []string {
			if !isModel(x) {
				return nil
			}
			return x.ML.Organizations()
		})
	case SubjectModelName:
		m, value, err = compileModelFacts(c, OpMatches, "model", false, modelNames)
	case SubjectModelLicense:
		m, value, err = compileModelLicense(c)
	case SubjectModelTask:
		m, value, err = compileModelFacts(c, OpIn, "task", false, func(x *Component) []string {
			if !isModel(x) || x.ML == nil || strings.TrimSpace(x.ML.Task) == "" {
				return nil
			}
			return []string{x.ML.Task}
		})
	case SubjectDatasetName:
		m, value, err = compileModelFacts(c, OpMatches, "dataset", true, datasetNames)
	}
	if err != nil {
		return compiled{}, err
	}
	norm, err := json.Marshal(value)
	if err != nil {
		return compiled{}, fmt.Errorf("normalize %s value: %w", c.Subject, err)
	}
	c.Value = norm
	return compiled{Condition: c, match: m}, nil
}

func joinOps(ops []Operator) string {
	s := make([]string, len(ops))
	for i, o := range ops {
		s[i] = string(o)
	}
	return strings.Join(s, ", ")
}

func decode(c Condition, into any, want string) error {
	if err := json.Unmarshal(c.Value, into); err != nil {
		return invalid("%s: value must be %s", c.Subject, want)
	}
	return nil
}

// stringList accepts a string or a list of strings; blanks are dropped and at
// least one entry must remain.
func stringList(c Condition) ([]string, error) {
	var one string
	var many []string
	if json.Unmarshal(c.Value, &one) == nil {
		many = []string{one}
	} else if err := decode(c, &many, "a string or a list of strings"); err != nil {
		return nil, err
	}
	out := []string{}
	for _, s := range many {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, invalid("%s: value must not be empty", c.Subject)
	}
	return out, nil
}

func compileSeverity(c Condition) (matcher, any, error) {
	var s domain.Severity
	if err := decode(c, &s, "a severity"); err != nil {
		return nil, nil, err
	}
	s = domain.Severity(strings.ToLower(string(s)))
	if !s.Valid() {
		return nil, nil, invalid("severity: %q is not a severity", s)
	}
	return func(x *Component, _ time.Time) (bool, string) {
		if x.MaxSeverity == nil {
			return false, ""
		}
		return severityRank(*x.MaxSeverity) >= severityRank(s), "worst vulnerability " + string(*x.MaxSeverity)
	}, s, nil
}

// severityRank orders severities info < low < medium < high < critical.
func severityRank(s domain.Severity) int {
	switch s {
	case domain.SeverityCritical:
		return 5
	case domain.SeverityHigh:
		return 4
	case domain.SeverityMedium:
		return 3
	case domain.SeverityLow:
		return 2
	case domain.SeverityInfo:
		return 1
	}
	return 0
}

func compileVulnID(c Condition) (matcher, any, error) {
	ids, err := stringList(c)
	if err != nil {
		return nil, nil, err
	}
	test := func(id string) bool {
		return slices.ContainsFunc(ids, func(want string) bool { return strings.EqualFold(want, id) })
	}
	if c.Operator == OpMatches {
		re, err := globs(c.Subject, ids)
		if err != nil {
			return nil, nil, err
		}
		test = re.MatchString
	}
	return func(x *Component, _ time.Time) (bool, string) {
		for _, id := range x.VulnIDs {
			if test(id) {
				return true, "vulnerability " + id
			}
		}
		return false, ""
	}, ids, nil
}

// compileBool builds an `is true|false` condition over fact, which reports the
// value, whether it is known, and a description. An unknown fact never matches.
func compileBool(c Condition, fact func(*Component) (v, known bool, desc string)) (matcher, any, error) {
	var want bool
	if err := decode(c, &want, "true or false"); err != nil {
		return nil, nil, err
	}
	return func(x *Component, _ time.Time) (bool, string) {
		v, known, desc := fact(x)
		return known && v == want, desc
	}, want, nil
}

func compileEPSS(c Condition) (matcher, any, error) {
	var min float64
	if err := decode(c, &min, "a number"); err != nil {
		return nil, nil, err
	}
	if min < 0 || min > 1 {
		return nil, nil, invalid("epss: value must be between 0 and 1")
	}
	return func(x *Component, _ time.Time) (bool, string) {
		if x.EPSS == nil {
			return false, ""
		}
		return *x.EPSS >= min, fmt.Sprintf("epss %.4f", *x.EPSS)
	}, min, nil
}

// compileKEVSource holds when a catalog listed asserts one of the component's
// vulnerabilities is known-exploited.
func compileKEVSource(c Condition) (matcher, any, error) {
	sources, err := stringList(c)
	if err != nil {
		return nil, nil, err
	}
	for i, s := range sources {
		if sources[i] = strings.ToLower(s); !domain.ValidKEVCatalog(sources[i]) {
			return nil, nil, invalid("kev_source: %q is not a KEV catalog (%s)", s, strings.Join(domain.KEVCatalogs, ", "))
		}
	}
	return func(x *Component, _ time.Time) (bool, string) {
		for _, s := range x.KEVSources {
			if slices.Contains(sources, s) {
				return true, "kev " + s
			}
		}
		return false, ""
	}, sources, nil
}

func compileCWE(c Condition) (matcher, any, error) {
	var one int
	var cwes []int
	if json.Unmarshal(c.Value, &one) == nil {
		cwes = []int{one}
	} else if err := decode(c, &cwes, "a CWE number or a list of them"); err != nil {
		return nil, nil, err
	}
	if len(cwes) == 0 || slices.ContainsFunc(cwes, func(n int) bool { return n <= 0 }) {
		return nil, nil, invalid("cwe: value must list positive CWE numbers")
	}
	return func(x *Component, _ time.Time) (bool, string) {
		for _, n := range x.CWEs {
			if slices.Contains(cwes, n) {
				return true, fmt.Sprintf("CWE-%d", n)
			}
		}
		return false, ""
	}, cwes, nil
}

// compileLicense: `is` holds when the component can't be used without one of
// the listed licenses (its expression isn't satisfiable avoiding them — so
// "MIT OR GPL-3.0-only" passes a GPL deny); `is_not` when it can't be used
// under the listed licenses alone (an allowlist). No license → unknown.
func compileLicense(c Condition) (matcher, any, error) {
	ids, err := stringList(c)
	if err != nil {
		return nil, nil, err
	}
	re, err := globs(c.Subject, ids)
	if err != nil {
		return nil, nil, err
	}
	return licenseMatcher(c.Operator == OpIs, re.MatchString), ids, nil
}

// licenseMatcher: deny=true holds when the expression can't avoid listed ids;
// deny=false when it can't be satisfied by listed ids only.
func licenseMatcher(deny bool, listed func(id string) bool) matcher {
	return func(x *Component, _ time.Time) (bool, string) {
		if x.License.IsZero() {
			return false, ""
		}
		var ok bool
		if deny {
			ok = !x.License.Satisfies(func(id string) bool { return !listed(id) })
		} else {
			ok = !x.License.Satisfies(listed)
		}
		return ok, licenseFact(x)
	}
}

func compileLicenseGroup(c Condition, groups groupResolver) (matcher, any, error) {
	refs, err := stringList(c)
	if err != nil {
		return nil, nil, err
	}
	members := map[string]bool{}
	for _, ref := range refs {
		ids, err := groups(ref)
		if errors.Is(err, errGroupGone) {
			// Evaluating with a group deleted since the policy was saved: the
			// condition can't be judged, so it never matches.
			never := func(*Component, time.Time) (bool, string) { return false, "" }
			return never, refs, nil
		}
		if err != nil {
			return nil, nil, err
		}
		for _, id := range ids {
			members[strings.ToLower(id)] = true
		}
	}
	in := func(id string) bool { return members[strings.ToLower(id)] }
	return licenseMatcher(c.Operator == OpIn, in), refs, nil
}

func licenseFact(x *Component) string {
	switch {
	case x.LicenseExpression != "":
		return "license " + x.LicenseExpression
	case x.License.IsZero() && x.InventoryComponent.License != "":
		return fmt.Sprintf("license %q (unresolved)", x.InventoryComponent.License)
	default:
		return "no license"
	}
}

func compileVersionsBehind(c Condition) (matcher, any, error) {
	var n int
	if err := decode(c, &n, "a whole number"); err != nil {
		return nil, nil, err
	}
	if n < 1 {
		return nil, nil, invalid("versions_behind: value must be at least 1")
	}
	return func(x *Component, _ time.Time) (bool, string) {
		if x.Meta == nil || x.Meta.VersionsBehind == nil {
			return false, ""
		}
		return *x.Meta.VersionsBehind >= n, fmt.Sprintf("%d versions behind %s", *x.Meta.VersionsBehind, orDash(x.Meta.Latest))
	}, n, nil
}

func compileAge(c Condition) (matcher, any, error) {
	var days int
	if err := decode(c, &days, "a number of days"); err != nil {
		return nil, nil, err
	}
	if days < 1 {
		return nil, nil, invalid("age: value must be at least 1 day")
	}
	return func(x *Component, now time.Time) (bool, string) {
		if x.Meta == nil || x.Meta.Published == nil {
			return false, ""
		}
		age := int(now.Sub(*x.Meta.Published).Hours() / 24)
		return age >= days, fmt.Sprintf("released %s (%d days ago)", x.Meta.Published.UTC().Format(time.DateOnly), age)
	}, days, nil
}

// Hash modes of missing_hash.
const (
	HashAny    = "any"    // the component carries no hash at all
	HashStrong = "strong" // the component carries no SHA-256-or-stronger hash
)

// strongHashes are the algorithms (normalized: upper case, no separators)
// missing_hash "strong" accepts — CycloneDX's and SPDX's spellings of SHA-256
// and up, SHA-3 and BLAKE.
var strongHashes = []string{"SHA256", "SHA384", "SHA512", "SHA3256", "SHA3384", "SHA3512",
	"BLAKE2B256", "BLAKE2B384", "BLAKE2B512", "BLAKE3"}

func compileMissingHash(c Condition) (matcher, any, error) {
	var mode string
	if err := decode(c, &mode, `"any" or "strong"`); err != nil {
		return nil, nil, err
	}
	if mode != HashAny && mode != HashStrong {
		return nil, nil, invalid(`missing_hash: value must be "any" or "strong"`)
	}
	return func(x *Component, _ time.Time) (bool, string) {
		var algs []string
		for alg, v := range x.Hashes {
			if strings.TrimSpace(v) != "" {
				algs = append(algs, alg)
			}
		}
		slices.Sort(algs)
		fact := "no hashes"
		if len(algs) > 0 {
			fact = "hashes " + strings.Join(algs, ", ")
		}
		if mode == HashAny {
			return len(algs) == 0, fact
		}
		for _, alg := range algs {
			norm := strings.NewReplacer("-", "", "_", "", " ", "").Replace(strings.ToUpper(alg))
			if slices.Contains(strongHashes, norm) {
				return false, fact
			}
		}
		return true, fact
	}, mode, nil
}

// compileIntegrity matches a component whose SBOM hashes the registry check
// found to match ("verified") or contradict ("mismatch") its published
// digests. Unknown — no comparable hash — matches neither.
func compileIntegrity(c Condition) (matcher, any, error) {
	var want string
	if err := decode(c, &want, `"mismatch" or "verified"`); err != nil {
		return nil, nil, err
	}
	if want != "mismatch" && want != "verified" {
		return nil, nil, invalid(`integrity: value must be "mismatch" or "verified"`)
	}
	return func(x *Component, _ time.Time) (bool, string) {
		if x.Integrity == "" {
			return false, ""
		}
		return x.Integrity == want, "integrity " + x.Integrity
	}, want, nil
}

func compileCoordinates(c Condition) (matcher, any, error) {
	var co Coordinates
	if err := decode(c, &co, `an object {"group", "name", "version"}`); err != nil {
		return nil, nil, err
	}
	co.Group, co.Name, co.Version = strings.TrimSpace(co.Group), strings.TrimSpace(co.Name), strings.TrimSpace(co.Version)
	if co.Group == "" && co.Name == "" && co.Version == "" {
		return nil, nil, invalid("coordinates: set at least one of group, name, version")
	}
	var tests []func(*Component) bool
	for _, part := range []struct {
		pattern string
		field   func(*Component) string
	}{
		{co.Group, func(x *Component) string { return x.Group }},
		{co.Name, func(x *Component) string { return x.Name }},
	} {
		if part.pattern == "" {
			continue
		}
		re, err := globs(c.Subject, []string{part.pattern})
		if err != nil {
			return nil, nil, err
		}
		tests = append(tests, func(x *Component) bool { return re.MatchString(part.field(x)) })
	}
	if co.Version != "" {
		if isRange(co.Version) {
			rng, err := parseRange(co.Version)
			if err != nil {
				return nil, nil, err
			}
			tests = append(tests, func(x *Component) bool { return x.Version != "" && rng.contains(x.Version) })
		} else {
			re, err := globs(c.Subject, []string{co.Version})
			if err != nil {
				return nil, nil, err
			}
			tests = append(tests, func(x *Component) bool { return re.MatchString(x.Version) })
		}
	}
	want := c.Operator == OpMatches
	return func(x *Component, _ time.Time) (bool, string) {
		all := true
		for _, t := range tests {
			if !t(x) {
				all = false
				break
			}
		}
		return all == want, "coordinates " + coordinates(x)
	}, co, nil
}

// coordinates renders group/name@version.
func coordinates(x *Component) string {
	s := x.Name
	if x.Group != "" {
		s = x.Group + "/" + s
	}
	if x.Version != "" {
		s += "@" + x.Version
	}
	return s
}

func compilePurl(c Condition) (matcher, any, error) {
	patterns, err := stringList(c)
	if err != nil {
		return nil, nil, err
	}
	re, err := globs(c.Subject, patterns)
	if err != nil {
		return nil, nil, err
	}
	want := c.Operator == OpMatches
	return func(x *Component, _ time.Time) (bool, string) {
		if x.Purl == "" {
			return false, "" // nothing to judge
		}
		return re.MatchString(x.Purl) == want, "purl " + x.Purl
	}, patterns, nil
}

func compilePackageType(c Condition) (matcher, any, error) {
	types, err := stringList(c)
	if err != nil {
		return nil, nil, err
	}
	for i := range types {
		types[i] = strings.ToLower(types[i])
	}
	want := c.Operator == OpIn
	return func(x *Component, _ time.Time) (bool, string) {
		t := purlType(x.Purl)
		if t == "" {
			return false, "" // no purl: type unknown
		}
		return slices.Contains(types, t) == want, "package type " + t
	}, types, nil
}

// purlType is the type of "pkg:<type>/…", lower-cased; "" without a purl.
func purlType(purl string) string {
	rest, ok := strings.CutPrefix(purl, "pkg:")
	if !ok {
		return ""
	}
	t, _, ok := strings.Cut(rest, "/")
	if !ok {
		return ""
	}
	return strings.ToLower(t)
}

func compileComponentKind(c Condition) (matcher, any, error) {
	kinds, err := stringList(c)
	if err != nil {
		return nil, nil, err
	}
	for i, k := range kinds {
		kinds[i] = strings.ToLower(k)
		if !slices.Contains(sbom.Kinds, kinds[i]) {
			return nil, nil, invalid("component.kind: %q is not a kind (use %s)", k, strings.Join(sbom.Kinds, ", "))
		}
	}
	want := c.Operator == OpIn
	return func(x *Component, _ time.Time) (bool, string) {
		kind := cmp.Or(x.Kind, sbom.KindSoftware)
		return slices.Contains(kinds, kind) == want, "kind " + kind
	}, kinds, nil
}

// compileModelFacts builds a glob list condition over an AI component's
// facts. The positive operator (in / matches) holds when any fact matches a
// pattern — a deny list. The negative one (not_in / no_match) is an allow
// list that flags what isn't approved: with each, every fact is a separate
// thing that must be approved (a model's datasets); without, the facts are
// names of one thing (a model's name and group/name, its supplier and
// publisher), approved when any of them is. No facts (a software component, a
// model card that doesn't say) is unknown and never matches.
func compileModelFacts(c Condition, positive Operator, label string, each bool, facts func(*Component) []string) (matcher, any, error) {
	patterns, err := stringList(c)
	if err != nil {
		return nil, nil, err
	}
	re, err := globs(c.Subject, patterns)
	if err != nil {
		return nil, nil, err
	}
	deny := c.Operator == positive
	return func(x *Component, _ time.Time) (bool, string) {
		vals := facts(x)
		if len(vals) == 0 {
			return false, ""
		}
		if deny {
			for _, v := range vals {
				if re.MatchString(v) {
					return true, label + " " + v
				}
			}
			return false, label + " " + strings.Join(vals, ", ")
		}
		if !each {
			return !slices.ContainsFunc(vals, re.MatchString), label + " " + strings.Join(vals, ", ")
		}
		for _, v := range vals {
			if !re.MatchString(v) {
				return true, label + " " + v
			}
		}
		return false, label + " " + strings.Join(vals, ", ")
	}, patterns, nil
}

// isModel reports whether model.* subjects judge x: a model or an AI service.
func isModel(x *Component) bool {
	return x.Kind == sbom.KindModel || x.Kind == sbom.KindAIService
}

// modelNames are a model's name and, with a group, group/name (the hub id:
// "meta-llama/Llama-2-7b"), most specific last.
func modelNames(x *Component) []string {
	if !isModel(x) || x.Name == "" {
		return nil
	}
	if x.Group == "" {
		return []string{x.Name}
	}
	return []string{x.Name, x.Group + "/" + x.Name}
}

// datasetNames are a dataset's own name, or the datasets a model card names.
func datasetNames(x *Component) []string {
	switch x.Kind {
	case sbom.KindDataset:
		return []string{x.Name}
	case sbom.KindModel:
		return x.ML.DatasetNames()
	}
	return nil
}

// compileModelLicense is compileLicense for models and AI services only.
func compileModelLicense(c Condition) (matcher, any, error) {
	m, ids, err := compileLicense(c)
	if err != nil {
		return nil, nil, err
	}
	return func(x *Component, now time.Time) (bool, string) {
		if !isModel(x) {
			return false, ""
		}
		return m(x, now)
	}, ids, nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// globs compiles case-insensitive globs ('*' any run, '?' one character —
// across '/' too, so "pkg:npm/*" covers scoped packages) into one regexp
// matching any of them.
func globs(subject Subject, patterns []string) (*regexp.Regexp, error) {
	parts := make([]string, len(patterns))
	for i, p := range patterns {
		q := regexp.QuoteMeta(p)
		q = strings.ReplaceAll(q, `\*`, `.*`)
		q = strings.ReplaceAll(q, `\?`, `.`)
		parts[i] = q
	}
	re, err := regexp.Compile(`(?i)^(?:` + strings.Join(parts, "|") + `)$`)
	if err != nil {
		return nil, invalid("%s: bad pattern: %v", subject, err)
	}
	return re, nil
}

// versionRange is a conjunction of comparisons (">=1.2, <2").
type versionRange []struct {
	op      string
	version string
}

func isRange(s string) bool { return strings.ContainsAny(s[:1], "<>=!") }

var rangeOps = []string{">=", "<=", "!=", "==", ">", "<", "="}

func parseRange(s string) (versionRange, error) {
	var out versionRange
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		op := ""
		for _, o := range rangeOps {
			if strings.HasPrefix(part, o) {
				op = o
				break
			}
		}
		v := strings.TrimSpace(strings.TrimPrefix(part, op))
		if op == "" || v == "" {
			return nil, invalid("coordinates: bad version range %q (use e.g. \">=1.2.0, <2.0.0\")", s)
		}
		out = append(out, struct {
			op      string
			version string
		}{op, v})
	}
	return out, nil
}

func (r versionRange) contains(v string) bool {
	for _, c := range r {
		cmp := sbom.CompareVersions(v, c.version)
		var ok bool
		switch c.op {
		case ">=":
			ok = cmp >= 0
		case "<=":
			ok = cmp <= 0
		case ">":
			ok = cmp > 0
		case "<":
			ok = cmp < 0
		case "!=":
			ok = cmp != 0
		default: // "=", "=="
			ok = cmp == 0
		}
		if !ok {
			return false
		}
	}
	return true
}
