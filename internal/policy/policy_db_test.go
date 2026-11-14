package policy_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/xilasec/xila-api/internal/domain"
	"github.com/xilasec/xila-api/internal/finding"
	"github.com/xilasec/xila-api/internal/license"
	"github.com/xilasec/xila-api/internal/notify"
	"github.com/xilasec/xila-api/internal/pgtest"
	"github.com/xilasec/xila-api/internal/pkgmeta"
	"github.com/xilasec/xila-api/internal/policy"
	"github.com/xilasec/xila-api/internal/project"
	"github.com/xilasec/xila-api/internal/sbom"
	"github.com/xilasec/xila-api/internal/scan"
	"github.com/xilasec/xila-api/internal/scanner"
)

// fakeMeta stands in for pkgmeta.Repository (pkgmeta has its own tests).
type fakeMeta map[string]pkgmeta.Info

func (m fakeMeta) Info(_ context.Context, purls []string) (map[string]pkgmeta.Info, error) {
	out := map[string]pkgmeta.Info{}
	for _, p := range purls {
		if i, ok := m[p]; ok {
			out[p] = i
		}
	}
	return out, nil
}

// chanNotifier records events deterministically.
type chanNotifier chan notify.Event

func (c chanNotifier) Notify(_ context.Context, e notify.Event) { c <- e }

type env struct {
	t        *testing.T
	ctx      context.Context
	pool     *pgxpool.Pool
	findings *finding.Repository
	policies *policy.Repository
	svc      *policy.Service
	sboms    *sbom.Service
	ingest   *scan.Service
	events   chanNotifier
	meta     fakeMeta
	projects int
}

func setup(t *testing.T) *env {
	t.Helper()
	pool := pgtest.Pool(t)
	e := &env{t: t, ctx: context.Background(), pool: pool, findings: finding.NewRepository(pool),
		policies: policy.NewRepository(pool), events: make(chanNotifier, 16), meta: fakeMeta{}}
	sbomRepo := sbom.NewRepository(pool)
	scanRepo := scan.NewRepository(pool)
	projects := project.NewRepository(pool)
	e.ingest = scan.NewService(scanRepo, e.findings, projects, scanner.NewRegistry(scanner.NewTrivy()), nil, nil, scanRepo)
	e.svc = policy.NewService(e.policies, sbomRepo, e.meta, license.NewGroups(pool), e.ingest, e.events)
	t.Cleanup(e.svc.WaitIdle)
	e.sboms = sbom.NewService(sbomRepo, projects, e.svc, nil).WithLicenses(license.Resolve)
	return e
}

// project seeds an org/team/project and returns the project id.
func (e *env) project() string {
	e.t.Helper()
	e.projects++
	slug := fmt.Sprintf("p%d", e.projects)
	var id string
	if err := e.pool.QueryRow(e.ctx, `
		WITH o AS (INSERT INTO organizations (slug,name) VALUES ($1,'o') RETURNING id),
		     tm AS (INSERT INTO teams (org_id,slug,name) SELECT id,$1,$1 FROM o RETURNING id)
		INSERT INTO projects (team_id, slug, name) SELECT id,$1,$1 FROM tm RETURNING id`, slug).Scan(&id); err != nil {
		e.t.Fatalf("seed project: %v", err)
	}
	return id
}

// comp is one CycloneDX component.
type comp struct{ name, version, license string }

// upload ingests a CycloneDX SBOM of comps (npm packages) for a project's
// default version, or branch when set — the real upload path, which runs the
// policy evaluator hook.
func (e *env) upload(projectID, branch string, comps ...comp) {
	e.t.Helper()
	var parts []string
	for _, c := range comps {
		lic := ""
		if c.license != "" {
			lic = fmt.Sprintf(`, "licenses": [{"expression": %q}]`, c.license)
		}
		parts = append(parts, fmt.Sprintf(`{"type":"library","name":%q,"version":%q,"purl":"pkg:npm/%s@%s"%s}`,
			c.name, c.version, c.name, c.version, lic))
	}
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"name":"app","version":"1"}},"components":[` +
		strings.Join(parts, ",") + `]}`
	if _, err := e.sboms.Ingest(e.ctx, sbom.IngestRequest{ProjectID: projectID, Artifact: "app", Branch: branch},
		strings.NewReader(doc)); err != nil {
		e.t.Fatalf("upload sbom: %v", err)
	}
}

// violations lists a project's policy findings on every version, in any status.
func (e *env) violations(projectID string) []finding.Finding {
	e.t.Helper()
	list, err := e.findings.List(e.ctx, finding.Filter{ProjectID: projectID, Scanner: policy.Scanner, AllVersions: true, Limit: 1000})
	if err != nil {
		e.t.Fatalf("list findings: %v", err)
	}
	return list
}

func open(fs []finding.Finding) []finding.Finding {
	var out []finding.Finding
	for _, f := range fs {
		if f.Status == domain.FindingOpen || f.Status == domain.FindingConfirmed {
			out = append(out, f)
		}
	}
	return out
}

func (e *env) create(p policy.Policy) policy.Policy {
	e.t.Helper()
	if err := e.svc.Validate(e.ctx, &p); err != nil {
		e.t.Fatalf("validate policy: %v", err)
	}
	out, err := e.policies.Create(e.ctx, p, "")
	if err != nil {
		e.t.Fatalf("create policy: %v", err)
	}
	return out
}

func draft(name string, conds ...policy.Condition) policy.Policy {
	p := policy.Draft()
	p.Name, p.Conditions = name, conds
	return p
}

func cond(s policy.Subject, op policy.Operator, v string) policy.Condition {
	return policy.Condition{Subject: s, Operator: op, Value: json.RawMessage(v)}
}

// The seeded "Strong copyleft licenses" policy replaces LICENSE_DENYLIST: an
// upload raises a license finding for a GPL component (not for a dual-licensed
// one with a permissive way out), and a later SBOM that drops the GPL
// dependency auto-closes it.
func TestUploadRaisesAndResolvesViolations(t *testing.T) {
	e := setup(t)
	p := e.project()

	e.upload(p, "",
		comp{"copyleft", "1.0.0", "GPL-3.0-only"},
		comp{"dual", "2.0.0", "MIT OR GPL-3.0-only"},
		comp{"lgpl", "1.0.0", "LGPL-3.0-only"},
		comp{"mit", "1.0.0", "MIT"})
	vs := e.violations(p)
	if len(vs) != 1 {
		t.Fatalf("violations = %d (%v), want 1 (copyleft only)", len(vs), vs)
	}
	v := vs[0]
	if v.PackageName != "copyleft" || v.Purl != "pkg:npm/copyleft@1.0.0" || v.RuleID != pgtest.SeededPolicyID ||
		v.Category != domain.CategoryLicense || v.Severity != domain.SeverityMedium || v.Status != domain.FindingOpen {
		t.Errorf("violation = %+v", v)
	}
	if v.Title != `Policy "Strong copyleft licenses" violated by copyleft@1.0.0` {
		t.Errorf("title = %q", v.Title)
	}
	if v.Metadata["policy_name"] != "Strong copyleft licenses" {
		t.Errorf("metadata = %v, want the policy name", v.Metadata)
	}
	if facts, _ := v.Metadata["facts"].(map[string]any); facts["license_expression"] != "GPL-3.0-only" {
		t.Errorf("facts = %v, want the license expression", v.Metadata["facts"])
	}

	// Re-uploading the same inventory upserts the same violation.
	e.upload(p, "", comp{"copyleft", "1.0.0", "GPL-3.0-only"}, comp{"mit", "1.0.0", "MIT"})
	if again := e.violations(p); len(again) != 1 || again[0].ID != v.ID {
		t.Fatalf("after re-upload violations = %v, want the same single finding", again)
	}

	// The team swaps the GPL dependency out: the violation auto-closes.
	e.upload(p, "", comp{"mit", "1.0.0", "MIT"})
	got, err := e.findings.Get(e.ctx, v.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != domain.FindingRemediated {
		t.Errorf("status after the fix = %s, want remediated", got.Status)
	}
}

// Disabling a policy closes its violations; a project-scoped policy only hits
// its projects; a default-versions policy skips branches.
func TestPolicyScopeAndLifecycle(t *testing.T) {
	e := setup(t)
	a, b := e.project(), e.project()
	for _, p := range []string{a, b} {
		e.upload(p, "", comp{"left-pad", "1.0.0", "MIT"})
		e.upload(p, "feature", comp{"left-pad", "1.0.0", "MIT"})
	}

	scoped := draft("no left-pad", cond(policy.SubjectCoordinates, policy.OpMatches, `{"name":"left-*"}`))
	scoped.Scope, scoped.ProjectIDs, scoped.Versions = policy.ScopeProjects, []string{a}, policy.VersionsDefault
	pol := e.create(scoped)
	for _, p := range []string{a, b} {
		if _, err := e.svc.EvaluateProject(e.ctx, p); err != nil {
			t.Fatalf("evaluate: %v", err)
		}
	}
	va := open(e.violations(a))
	if len(va) != 1 || va[0].Severity != domain.SeverityHigh || va[0].Category != domain.CategorySCA {
		t.Fatalf("project A violations = %v, want 1 high sca (default version only)", va)
	}
	if vb := e.violations(b); len(vb) != 0 {
		t.Errorf("project B violations = %v, want none (policy scoped to A)", vb)
	}

	// All versions: the branch now violates too.
	pol.Versions = policy.VersionsAll
	if _, err := e.policies.Update(e.ctx, pol); err != nil {
		t.Fatalf("update: %v", err)
	}
	if _, err := e.svc.EvaluateProject(e.ctx, a); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if va := open(e.violations(a)); len(va) != 2 {
		t.Errorf("all-versions violations = %d, want 2 (default + feature)", len(va))
	}

	// Disabled: every violation closes.
	pol.Enabled = false
	if _, err := e.policies.Update(e.ctx, pol); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if _, err := e.svc.EvaluateProject(e.ctx, a); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if va := open(e.violations(a)); len(va) != 0 {
		t.Errorf("open violations after disabling = %v, want none", va)
	}
}

// Background re-evaluation after a policy change (what the API triggers)
// lands the violations without an upload; deleting the policy closes them.
func TestReevaluateAfterPolicyChange(t *testing.T) {
	e := setup(t)
	p := e.project()
	e.upload(p, "", comp{"event-stream", "3.3.6", "MIT"})

	pol := e.create(draft("banned", cond(policy.SubjectPurl, policy.OpMatches, `["pkg:npm/event-stream@3.3.6"]`)))
	e.svc.Reevaluate(nil, true)
	e.svc.WaitIdle()
	if vs := open(e.violations(p)); len(vs) != 1 {
		t.Fatalf("violations after re-evaluation = %d, want 1", len(vs))
	}
	// A new fail violation notifies once per project per evaluation.
	select {
	case ev := <-e.events:
		if ev.Type != notify.EventPolicyViolation || ev.ProjectID != p || ev.Fields["total"] != "1" {
			t.Errorf("event = %+v, want one policy.violation for the project", ev)
		}
	default:
		t.Error("no policy.violation event for a new fail violation")
	}
	// Re-evaluating finds nothing new: no second event.
	if _, err := e.svc.EvaluateProject(e.ctx, p); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	select {
	case ev := <-e.events:
		t.Errorf("unexpected event on an unchanged evaluation: %+v", ev)
	default:
	}

	if err := e.policies.Delete(e.ctx, pol.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	e.svc.Reevaluate([]string{p}, false)
	e.svc.WaitIdle()
	if vs := open(e.violations(p)); len(vs) != 0 {
		t.Errorf("open violations after deleting the policy = %v, want none", vs)
	}
}

// Security conditions read the component's vulnerabilities (scanner findings,
// advisories) incl. KEV/EPSS — but never the policy engine's own findings, or
// a policy would keep itself violated.
func TestSecurityFacts(t *testing.T) {
	e := setup(t)
	p := e.project()
	e.upload(p, "", comp{"log4j", "2.14.1", "Apache-2.0"}, comp{"safe", "1.0.0", "MIT"})

	// Every component trips this fail (= high) policy...
	e.create(draft("inventory", cond(policy.SubjectCoordinates, policy.OpMatches, `{"name":"*"}`)))
	// ...which must not make it look vulnerable to this one.
	sec := e.create(draft("exploited", cond(policy.SubjectSeverity, policy.OpGTE, `"high"`),
		cond(policy.SubjectKEV, policy.OpIs, `true`)))
	sec.Operator = policy.CombineAll
	if _, err := e.policies.Update(e.ctx, sec); err != nil {
		t.Fatalf("update: %v", err)
	}
	for range 2 {
		if _, err := e.svc.EvaluateProject(e.ctx, p); err != nil {
			t.Fatalf("evaluate: %v", err)
		}
	}
	for _, v := range open(e.violations(p)) {
		if v.RuleID == sec.ID {
			t.Fatalf("security policy violated with no vulnerabilities: %s", v.Title)
		}
	}

	// A scanner reports a critical, KEV-listed CVE in log4j.
	if _, err := e.ingest.ApplyFindings(e.ctx, p, "", "osv", domain.CategorySCA, []finding.Finding{{
		Fingerprint: "log4shell", Category: domain.CategorySCA, RuleID: "GHSA-jfh8", Title: "Log4Shell",
		Severity: domain.SeverityCritical, CVE: []string{"CVE-2021-44228"},
		PackageName: "log4j", PackageVersion: "2.14.1", Purl: "pkg:npm/log4j@2.14.1",
	}}); err != nil {
		t.Fatalf("apply osv: %v", err)
	}
	if _, err := e.pool.Exec(e.ctx, `UPDATE findings SET kev = true, epss = 0.97 WHERE fingerprint = 'log4shell'`); err != nil {
		t.Fatalf("enrich: %v", err)
	}
	if _, err := e.svc.EvaluateProject(e.ctx, p); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	var hit []finding.Finding
	for _, v := range open(e.violations(p)) {
		if v.RuleID == sec.ID {
			hit = append(hit, v)
		}
	}
	if len(hit) != 1 || hit[0].PackageName != "log4j" || hit[0].Category != domain.CategorySCA {
		t.Fatalf("security violations = %v, want log4j only", hit)
	}
	facts, _ := hit[0].Metadata["facts"].(map[string]any)
	if facts["kev"] != true || facts["max_severity"] != "critical" {
		t.Errorf("facts = %v, want kev + critical", facts)
	}
}

// Outdated conditions use package metadata; a package the registries know
// nothing about is unknown — neither outdated nor up to date.
func TestOutdatedFacts(t *testing.T) {
	e := setup(t)
	p := e.project()
	e.meta["pkg:npm/old@1.0.0"] = pkgmeta.Info{Latest: "3.0.0", Outdated: true, VersionsBehind: new(5)}
	e.meta["pkg:npm/fresh@2.0.0"] = pkgmeta.Info{Latest: "2.0.0"}
	e.upload(p, "", comp{"old", "1.0.0", "MIT"}, comp{"fresh", "2.0.0", "MIT"}, comp{"unknown", "1.0.0", "MIT"})

	behind := e.create(draft("behind", cond(policy.SubjectVersionsBehind, policy.OpGTE, `3`)))
	current := e.create(draft("current", cond(policy.SubjectOutdated, policy.OpIs, `false`)))
	if _, err := e.svc.EvaluateProject(e.ctx, p); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	got := map[string][]string{}
	for _, v := range open(e.violations(p)) {
		got[v.RuleID] = append(got[v.RuleID], v.PackageName)
	}
	if strings.Join(got[behind.ID], ",") != "old" {
		t.Errorf("versions_behind ≥ 3 hit %v, want [old]", got[behind.ID])
	}
	if strings.Join(got[current.ID], ",") != "fresh" {
		t.Errorf("outdated=false hit %v, want [fresh] (unknown is not up to date)", got[current.ID])
	}
}

// Preview evaluates a draft without writing anything.
func TestPreview(t *testing.T) {
	e := setup(t)
	a, b := e.project(), e.project()
	e.upload(a, "", comp{"lodash", "4.17.20", "MIT"}, comp{"react", "18.0.0", "MIT"})
	e.upload(b, "", comp{"lodash", "4.17.20", "MIT"})
	before := len(e.violations(a)) + len(e.violations(b))

	d := draft("", cond(policy.SubjectCoordinates, policy.OpMatches, `{"name":"lodash","version":"<4.17.21"}`))
	res, err := e.svc.Preview(e.ctx, d, []string{a})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if res.Total != 1 || len(res.Violations) != 1 || res.Violations[0].ProjectID != a || res.Violations[0].Name != "lodash" {
		t.Errorf("preview = %+v, want lodash in project A only", res)
	}
	if res.Components != 2 {
		t.Errorf("evaluated components = %d, want 2 (project A)", res.Components)
	}
	all, err := e.svc.Preview(e.ctx, d, nil)
	if err != nil || all.Total != 2 {
		t.Errorf("preview over everything = %d (%v), want 2", all.Total, err)
	}
	if after := len(e.violations(a)) + len(e.violations(b)); after != before {
		t.Errorf("preview wrote findings: %d → %d", before, after)
	}
	bad := draft("", cond("nope", policy.OpIs, `true`))
	if _, err := e.svc.Preview(e.ctx, bad, nil); err == nil {
		t.Error("preview accepted an unknown subject")
	}
}

// Upgrading from LICENSE_DENYLIST: migration 000040 carries existing
// license-policy findings over to the seeded policy, so a risk acceptance (and
// its history) survives re-evaluation instead of a fresh open finding
// appearing next to a dead one.
func TestLegacyLicenseFindingsKeepTheirTriage(t *testing.T) {
	e := setup(t)
	p := e.project()
	// Store the inventory without evaluating (as before the upgrade).
	plain := sbom.NewService(sbom.NewRepository(e.pool), project.NewRepository(e.pool), nil, nil).WithLicenses(license.Resolve)
	doc := `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[
		{"type":"library","name":"copyleft","version":"1.0.0","purl":"pkg:npm/copyleft@1.0.0","licenses":[{"license":{"id":"GPL-3.0-only"}}]},
		{"type":"library","name":"agpl","version":"2.0.0","purl":"pkg:npm/agpl@2.0.0","licenses":[{"license":{"id":"AGPL-3.0-only"}}]}]}`
	if _, err := plain.Ingest(e.ctx, sbom.IngestRequest{ProjectID: p, Artifact: "app"}, strings.NewReader(doc)); err != nil {
		t.Fatalf("ingest: %v", err)
	}
	// What the old license.Service left behind: one accepted, one open.
	legacy := func(name, purl, rule string) string {
		var id string
		if err := e.pool.QueryRow(e.ctx, `
			INSERT INTO findings (project_id, version_id, fingerprint, scanner, category, rule_id, title, severity,
			                      package_name, package_version, purl, metadata)
			VALUES ($1, project_version($1, NULL, NULL), md5($2), 'license-policy', 'license', $3, 'Disallowed license', 'medium',
			        $2, $4, $5, '{"license":"x"}') RETURNING id`,
			p, name, rule, strings.Split(purl, "@")[1], purl).Scan(&id); err != nil {
			t.Fatalf("seed legacy finding: %v", err)
		}
		return id
	}
	accepted := legacy("copyleft", "pkg:npm/copyleft@1.0.0", "GPL-3.0")
	stillOpen := legacy("agpl", "pkg:npm/agpl@2.0.0", "AGPL-3.0")
	ra, _, err := e.findings.CreateAcceptance(e.ctx, finding.AcceptanceInput{ProjectID: p, Title: "internal tool",
		Justification: "internal tool, never distributed", FindingIDs: []string{accepted}}, "legal")
	if err != nil {
		t.Fatalf("request acceptance: %v", err)
	}
	if _, _, err := e.findings.ApproveAcceptance(e.ctx, p, ra.ID, "ciso", "", true); err != nil {
		t.Fatalf("approve acceptance: %v", err)
	}

	// The upgrade: migration 000040 (idempotent; it already ran on this
	// database, but before these rows existed).
	sqlBytes, err := os.ReadFile("../database/migrations/000040_policies.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := e.pool.Exec(e.ctx, string(sqlBytes)); err != nil {
		t.Fatalf("run migration: %v", err)
	}
	// ...then the evaluation the new version runs.
	if _, err := e.svc.EvaluateProject(e.ctx, p); err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	vs := e.violations(p)
	if len(vs) != 2 {
		t.Fatalf("policy findings = %d (%v), want the 2 migrated ones, no duplicates", len(vs), vs)
	}
	byID := map[string]finding.Finding{}
	for _, v := range vs {
		byID[v.ID] = v
	}
	acc, ok := byID[accepted]
	if reason, _, _ := acc.Exception(); !ok || acc.Status != domain.FindingRiskAccepted || reason != "internal tool, never distributed" {
		t.Errorf("accepted finding after upgrade = %+v, want the same row, still risk_accepted", acc)
	}
	if acc.RuleID != pgtest.SeededPolicyID || acc.Title != `Policy "Strong copyleft licenses" violated by copyleft@1.0.0` {
		t.Errorf("accepted finding not re-attributed to the seeded policy: %+v", acc)
	}
	if hist, err := e.findings.FindingLedger(e.ctx, accepted); err != nil || len(hist) != 1 || hist[0].RemovedAt != nil {
		t.Errorf("acceptance ledger = %v (%v), want the acceptance kept", hist, err)
	}
	if o, ok := byID[stillOpen]; !ok || o.Status != domain.FindingOpen {
		t.Errorf("open legacy finding after upgrade = %+v, want the same row, open", o)
	}
	var left int
	if err := e.pool.QueryRow(e.ctx, `SELECT count(*) FROM findings WHERE scanner = 'license-policy'`).Scan(&left); err != nil || left != 0 {
		t.Errorf("license-policy findings left = %d (%v), want 0", left, err)
	}
}

// "Every project except internal-tool": tagging a project internal-tool
// closes its violations on the next evaluation, untagging reopens them, and
// the SQL twin (InForce) agrees with the Go scope.
func TestPolicyTagScopeFollowsProjectTags(t *testing.T) {
	e := setup(t)
	a, b := e.project(), e.project()
	for _, p := range []string{a, b} {
		e.upload(p, "", comp{"left-pad", "1.0.0", "MIT"})
	}
	p := draft("no left-pad except internal tools", cond(policy.SubjectCoordinates, policy.OpMatches, `{"name":"left-*"}`))
	p.ExcludeTags = []string{" internal-tool ", "internal-tool"}
	pol := e.create(p)
	if len(pol.ExcludeTags) != 1 || pol.ExcludeTags[0] != "internal-tool" {
		t.Fatalf("exclude_tags not normalized: %q", pol.ExcludeTags)
	}
	setTags := func(id string, tags ...string) {
		t.Helper()
		if _, err := e.pool.Exec(e.ctx, `UPDATE projects SET tags = $2 WHERE id = $1`, id, tags); err != nil {
			t.Fatal(err)
		}
		if _, err := e.svc.EvaluateProject(e.ctx, id); err != nil {
			t.Fatalf("evaluate: %v", err)
		}
	}
	inForce := func(id string) bool {
		t.Helper()
		ps, err := e.policies.InForce(e.ctx, []string{id})
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range ps {
			if x.ID == pol.ID {
				return true
			}
		}
		return false
	}

	setTags(a, "web")
	setTags(b, "internal-tool", "web")
	if n := len(open(e.violations(a))); n != 1 || !inForce(a) {
		t.Errorf("project a (web): %d open violations, in force %v; want 1, true", n, inForce(a))
	}
	if n := len(open(e.violations(b))); n != 0 || inForce(b) {
		t.Errorf("project b (internal-tool): %d open violations, in force %v; want 0, false", n, inForce(b))
	}

	setTags(a, "internal-tool")
	if n := len(open(e.violations(a))); n != 0 {
		t.Errorf("tagging a internal-tool left %d violations open", n)
	}
	setTags(b, "web")
	if n := len(open(e.violations(b))); n != 1 {
		t.Errorf("untagging b: %d open violations, want 1", n)
	}

	// A tag can't be both included and excluded.
	bad := draft("contradiction", cond(policy.SubjectCoordinates, policy.OpMatches, `{"name":"x"}`))
	bad.IncludeTags, bad.ExcludeTags = []string{"pci"}, []string{"pci"}
	if err := e.svc.Validate(e.ctx, &bad); err == nil {
		t.Error("a tag both included and excluded was accepted")
	}
}
