package vulnmatch

import (
	"context"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/expr"
	"github.com/xilasec/xila-api/internal/finding"
)

// Feed rules are admin policy over the incoming advisory feed. They run inside
// the matcher, after every source answered and before the answers become
// snapshot matches and findings, so every source — online, mirrored, private,
// CPE — is subject to them.
//
// Precedence (rules in position order, then oldest first):
//
//   - mute: any matching enabled mute rule drops the advisory for that
//     package. It never becomes a finding; a finding it already produced is
//     missing from the next complete run and auto-closes — but only on a
//     healthy run: a partial one (a source failed) never closes anything.
//   - set_severity: the first matching rule decides the severity.
//   - add_tags: every matching rule's tags are added to the finding.
//
// The rules that acted are recorded in the finding's metadata (feed_rules).

// FeedAction is what a feed rule does to a matching advisory.
type FeedAction string

const (
	FeedMute        FeedAction = "mute"
	FeedSetSeverity FeedAction = "set_severity"
	FeedAddTags     FeedAction = "add_tags"
)

// FeedRule is one condition → action rule. Every condition that is set must
// hold; unknown facts (no stated severity, no CVSS) never match a condition
// that needs them.
type FeedRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	Position    int    `json:"position"`

	// Sources matches when any reporting source is listed (osv, github, …).
	Sources []string `json:"sources"`
	// IDGlob matches the advisory id or any alias (case-insensitive glob:
	// "GHSA-*", "CVE-2019-*").
	IDGlob string `json:"id_glob"`
	// Ecosystems are purl types (npm, maven, pypi, …).
	Ecosystems []string `json:"ecosystems"`
	// PackageGlob matches the package name or namespace/name
	// ("@babel/*", "org.apache.logging.log4j/*"); a CPE-matched component
	// is matched by its CPE.
	PackageGlob string            `json:"package_glob"`
	Severities  []domain.Severity `json:"severities"`
	CVSSMin     *float64          `json:"cvss_min"`
	CVSSMax     *float64          `json:"cvss_max"`
	// Expression is a CEL condition over {advisory, pkg} (FeedSchema;
	// "package" is reserved in CEL).
	Expression string `json:"expression"`

	Action   FeedAction      `json:"action"`
	Severity domain.Severity `json:"severity,omitempty"`
	Tags     []string        `json:"tags"`

	CreatedBy *string   `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	expr *expr.Program
}

// FeedRuleRef names a rule that acted on a finding (its metadata.feed_rules).
type FeedRuleRef struct {
	ID     string     `json:"id"`
	Name   string     `json:"name"`
	Action FeedAction `json:"action"`
}

// ErrFeedRuleNotFound is returned for an unknown rule id.
var ErrFeedRuleNotFound = errors.New("feed rule not found")

// feedDoc is the fact document a rule's expression reads for one advisory as
// matched to one package (purl or CPE key). Unknown facts are null.
func feedDoc(key string, v Vuln) map[string]any {
	var sev, cvss any
	if v.Severity != "" {
		sev = string(v.Severity)
	}
	if v.CVSS != nil {
		cvss = *v.CVSS
	}
	pkg := map[string]any{"purl": nil, "cpe": nil, "ecosystem": nil, "namespace": nil, "name": nil, "version": nil}
	if p, ok := parsePurl(key); ok {
		pkg["purl"], pkg["ecosystem"], pkg["namespace"], pkg["name"], pkg["version"] = key, p.Type, p.Namespace, p.Name, p.Version
	} else {
		pkg["cpe"] = key
	}
	return map[string]any{
		"advisory": map[string]any{
			"id": v.ID, "aliases": strs(v.Aliases), "cves": strs(v.CVEs), "sources": strs(v.Sources),
			"severity": sev, "cvss": cvss, "summary": v.Summary,
		},
		"pkg": pkg,
	}
}

func strs(in []string) []any {
	out := make([]any, len(in))
	for i, s := range in {
		out[i] = s
	}
	return out
}

// FeedSchema is the expression schema, sampled from feedDoc itself so saving
// a rule validates against exactly what evaluation reads.
var FeedSchema = func() expr.Schema {
	cvss := 7.5
	doc := feedDoc("pkg:npm/%40scope/name@1.0.0", Vuln{
		ID: "GHSA-xxxx-xxxx-xxxx", Aliases: []string{"CVE-2024-0001"}, CVEs: []string{"CVE-2024-0001"},
		Sources: []string{SourceOSV}, Severity: domain.SeverityHigh, CVSS: &cvss, Summary: "s",
	})
	doc["pkg"].(map[string]any)["cpe"] = "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*"
	return expr.Schema{Vars: []string{"advisory", "pkg"}, Sample: doc}
}()

// Validate checks and normalizes a rule, compiling its expression.
func (r *FeedRule) Validate() error {
	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return errors.New("name is required")
	}
	r.Sources = normalizeList(r.Sources)
	for _, s := range r.Sources {
		if !slices.Contains(KnownSources, s) {
			return fmt.Errorf("unknown source %q (want one of %s)", s, strings.Join(KnownSources, ", "))
		}
	}
	r.Ecosystems = normalizeList(r.Ecosystems)
	r.IDGlob = strings.TrimSpace(r.IDGlob)
	r.PackageGlob = strings.TrimSpace(r.PackageGlob)
	for _, g := range []string{r.IDGlob, r.PackageGlob} {
		if _, err := path.Match(strings.ToLower(g), ""); err != nil {
			return fmt.Errorf("invalid glob %q", g)
		}
	}
	if r.Severities == nil {
		r.Severities = []domain.Severity{}
	}
	for _, s := range r.Severities {
		if !s.Valid() {
			return fmt.Errorf("invalid severity %q", s)
		}
	}
	for _, c := range []*float64{r.CVSSMin, r.CVSSMax} {
		if c != nil && (*c < 0 || *c > 10) {
			return errors.New("cvss bounds must be between 0 and 10")
		}
	}
	if r.CVSSMin != nil && r.CVSSMax != nil && *r.CVSSMin > *r.CVSSMax {
		return errors.New("cvss_min must not exceed cvss_max")
	}
	r.expr = nil
	r.Expression = strings.TrimSpace(r.Expression)
	if r.Expression != "" {
		p, err := expr.Compile(FeedSchema, r.Expression)
		if err != nil {
			return err
		}
		r.expr = p
	}
	if r.Tags == nil {
		r.Tags = []string{}
	}
	switch r.Action {
	case FeedMute:
		r.Severity, r.Tags = "", []string{}
	case FeedSetSeverity:
		if r.Severity == "" || !r.Severity.Valid() {
			return errors.New("set_severity needs a severity")
		}
		r.Tags = []string{}
	case FeedAddTags:
		tags, err := finding.NormalizeTags(r.Tags)
		if err != nil {
			return err
		}
		if len(tags) == 0 {
			return errors.New("add_tags needs at least one tag")
		}
		r.Tags, r.Severity = tags, ""
	default:
		return errors.New("action must be mute, set_severity or add_tags")
	}
	return nil
}

func normalizeList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// globMatch is a case-insensitive path.Match; patterns were validated on save.
func globMatch(pattern, s string) bool {
	ok, _ := path.Match(strings.ToLower(pattern), strings.ToLower(s))
	return ok
}

// matches reports whether every set condition holds for advisory v on the
// package with match key key.
func (r *FeedRule) matches(ctx context.Context, key string, v Vuln) bool {
	if len(r.Sources) > 0 && !slices.ContainsFunc(v.Sources, func(s string) bool { return slices.Contains(r.Sources, s) }) {
		return false
	}
	if r.IDGlob != "" && !globMatch(r.IDGlob, v.ID) &&
		!slices.ContainsFunc(v.Aliases, func(a string) bool { return globMatch(r.IDGlob, a) }) {
		return false
	}
	p, isPurl := parsePurl(key)
	if len(r.Ecosystems) > 0 && (!isPurl || !slices.Contains(r.Ecosystems, p.Type)) {
		return false
	}
	if r.PackageGlob != "" {
		if isPurl {
			full := p.Name
			if p.Namespace != "" {
				full = p.Namespace + "/" + p.Name
			}
			if !globMatch(r.PackageGlob, p.Name) && !globMatch(r.PackageGlob, full) {
				return false
			}
		} else if !globMatch(r.PackageGlob, key) {
			return false
		}
	}
	if len(r.Severities) > 0 && (v.Severity == "" || !slices.Contains(r.Severities, v.Severity)) {
		return false
	}
	if r.CVSSMin != nil && (v.CVSS == nil || *v.CVSS < *r.CVSSMin) {
		return false
	}
	if r.CVSSMax != nil && (v.CVSS == nil || *v.CVSS > *r.CVSSMax) {
		return false
	}
	if r.expr != nil && !r.expr.Match(ctx, feedDoc(key, v)) {
		return false
	}
	return true
}

// applyFeedRules returns the advisories per match key after the rules: muted
// ones removed, severity and tags set, acting rules recorded. The input map
// (possibly a source's own) is never modified.
func applyFeedRules(ctx context.Context, rules []FeedRule, vulns map[string][]Vuln) map[string][]Vuln {
	if len(rules) == 0 {
		return vulns
	}
	out := make(map[string][]Vuln, len(vulns))
	for key, vs := range vulns {
		kept := make([]Vuln, 0, len(vs))
	next:
		for _, v := range vs {
			var severity domain.Severity
			var refs []FeedRuleRef
			var tags []string
			// Every rule sees the advisory as the feed stated it; the actions
			// apply once all rules were evaluated.
			for i := range rules {
				r := &rules[i]
				if !r.matches(ctx, key, v) {
					continue
				}
				switch r.Action {
				case FeedMute:
					continue next
				case FeedSetSeverity:
					if severity != "" {
						continue // the first matching rule decides
					}
					severity = r.Severity
				case FeedAddTags:
					tags = append(tags, r.Tags...)
				}
				refs = append(refs, FeedRuleRef{ID: r.ID, Name: r.Name, Action: r.Action})
			}
			if severity != "" && severity != v.Severity {
				v.FeedSeverityFrom, v.Severity = v.Severity, severity
			}
			if len(tags) > 0 {
				slices.Sort(tags)
				v.Tags = slices.Compact(tags)
			}
			v.FeedRules = refs
			kept = append(kept, v)
		}
		if len(kept) > 0 {
			out[key] = kept
		}
	}
	return out
}

// feedRuleStore yields the enabled rules in evaluation order.
type feedRuleStore interface {
	Active(ctx context.Context) ([]FeedRule, error)
}

// feedTagger adds the tags feed rules attached (metadata.feed_tags) to the
// findings a scan recorded (finding.Repository).
type feedTagger interface {
	ApplyFeedTags(ctx context.Context, scanID string) error
}

// FeedRuleRepository stores feed rules (feed_rules).
type FeedRuleRepository struct{ db *pgxpool.Pool }

// NewFeedRuleRepository constructs the store.
func NewFeedRuleRepository(db *pgxpool.Pool) *FeedRuleRepository {
	return &FeedRuleRepository{db: db}
}

const feedRuleColumns = `id, name, description, enabled, position, sources, id_glob, ecosystems,
	package_glob, severities, cvss_min, cvss_max, expression, action, COALESCE(severity, ''), tags,
	created_by, created_at, updated_at`

func scanFeedRule(row pgx.Row) (FeedRule, error) {
	var r FeedRule
	var sevs []string
	err := row.Scan(&r.ID, &r.Name, &r.Description, &r.Enabled, &r.Position, &r.Sources, &r.IDGlob,
		&r.Ecosystems, &r.PackageGlob, &sevs, &r.CVSSMin, &r.CVSSMax, &r.Expression, &r.Action, &r.Severity,
		&r.Tags, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	r.Severities = make([]domain.Severity, len(sevs))
	for i, s := range sevs {
		r.Severities[i] = domain.Severity(s)
	}
	return r, err
}

func (r *FeedRuleRepository) query(ctx context.Context, q string, args ...any) ([]FeedRule, error) {
	rows, err := r.db.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("list feed rules: %w", err)
	}
	defer rows.Close()
	out := []FeedRule{}
	for rows.Next() {
		rule, err := scanFeedRule(rows)
		if err != nil {
			return nil, fmt.Errorf("scan feed rule: %w", err)
		}
		out = append(out, rule)
	}
	return out, rows.Err()
}

// List returns every rule in evaluation order.
func (r *FeedRuleRepository) List(ctx context.Context) ([]FeedRule, error) {
	return r.query(ctx, `SELECT `+feedRuleColumns+` FROM feed_rules ORDER BY position, created_at, id`)
}

// Active returns the enabled rules in evaluation order, compiled.
func (r *FeedRuleRepository) Active(ctx context.Context) ([]FeedRule, error) {
	rules, err := r.query(ctx, `SELECT `+feedRuleColumns+` FROM feed_rules WHERE enabled ORDER BY position, created_at, id`)
	if err != nil {
		return nil, err
	}
	for i := range rules {
		// Stored rules were validated on save; a rule that no longer compiles
		// (an expression-language change) must fail the run loudly rather
		// than silently stop muting.
		if err := rules[i].Validate(); err != nil {
			return nil, fmt.Errorf("feed rule %q: %w", rules[i].Name, err)
		}
	}
	return rules, nil
}

// Get returns one rule.
func (r *FeedRuleRepository) Get(ctx context.Context, id string) (FeedRule, error) {
	out, err := scanFeedRule(r.db.QueryRow(ctx, `SELECT `+feedRuleColumns+` FROM feed_rules WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return FeedRule{}, ErrFeedRuleNotFound
	}
	return out, err
}

func sevStrings(in []domain.Severity) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = string(s)
	}
	return out
}

func nullSeverity(s domain.Severity) *string {
	if s == "" {
		return nil
	}
	v := string(s)
	return &v
}

// Create stores a validated rule.
func (r *FeedRuleRepository) Create(ctx context.Context, rule FeedRule, actor *string) (FeedRule, error) {
	return scanFeedRule(r.db.QueryRow(ctx, `
		INSERT INTO feed_rules (name, description, enabled, position, sources, id_glob, ecosystems,
			package_glob, severities, cvss_min, cvss_max, expression, action, severity, tags, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		RETURNING `+feedRuleColumns,
		rule.Name, rule.Description, rule.Enabled, rule.Position, rule.Sources, rule.IDGlob, rule.Ecosystems,
		rule.PackageGlob, sevStrings(rule.Severities), rule.CVSSMin, rule.CVSSMax, rule.Expression, rule.Action,
		nullSeverity(rule.Severity), rule.Tags, actor))
}

// Update replaces a validated rule's fields.
func (r *FeedRuleRepository) Update(ctx context.Context, rule FeedRule) (FeedRule, error) {
	out, err := scanFeedRule(r.db.QueryRow(ctx, `
		UPDATE feed_rules SET name = $2, description = $3, enabled = $4, position = $5, sources = $6,
			id_glob = $7, ecosystems = $8, package_glob = $9, severities = $10, cvss_min = $11, cvss_max = $12,
			expression = $13, action = $14, severity = $15, tags = $16, updated_at = now()
		WHERE id = $1
		RETURNING `+feedRuleColumns,
		rule.ID, rule.Name, rule.Description, rule.Enabled, rule.Position, rule.Sources, rule.IDGlob, rule.Ecosystems,
		rule.PackageGlob, sevStrings(rule.Severities), rule.CVSSMin, rule.CVSSMax, rule.Expression, rule.Action,
		nullSeverity(rule.Severity), rule.Tags))
	if errors.Is(err, pgx.ErrNoRows) {
		return FeedRule{}, ErrFeedRuleNotFound
	}
	return out, err
}

// Delete removes a rule.
func (r *FeedRuleRepository) Delete(ctx context.Context, id string) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM feed_rules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrFeedRuleNotFound
	}
	return nil
}
